"""D4: a semantic detector tier backed by the Claude Messages API.

Findings 3 in the paper argues that pattern matching is structurally blind to
MNPI. D4 is the comparison that argument demands: the same corpus, the same
metrics, a model in the loop.

Results are cached to disk per (model, prompt id), so a re-run costs nothing and
the published numbers are reproducible without re-spending. Latency is recorded
per call because this control sits in the request path -- a detector that costs
900 ms is a different product from one that costs 0.2 ms.

    pip install anthropic
    export ANTHROPIC_API_KEY=...        # or: ant auth login

    python3 llm_detector.py --estimate                      # cost only, no calls
    python3 llm_detector.py --model claude-opus-5 --yes     # spends money
    python3 llm_detector.py --mock                          # offline harness check

`--yes` is required before any real call is made.
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time

MODEL_PRICING = {            # USD per million tokens, (input, output)
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
}

# Haiku 4.5 rejects `effort` and uses the older thinking configuration, so it
# takes neither parameter here.
NO_EFFORT_MODELS = {"claude-haiku-4-5"}

SYSTEM = """\
You screen prompts that employees of a mid-sized financial services firm are \
about to send to an externally operated large language model. The firm does not \
control that model and cannot retract, audit, or attest to the deletion of \
anything it receives.

Flag a prompt if it contains any of the following, in any form:

1. PII -- a client's name in combination with any identifying or financial \
detail, date of birth, government identifier, home address, personal email, or \
personal phone number.
2. ACCOUNT -- account numbers, card numbers, IBANs, or internal settlement \
identifiers.
3. MNPI -- material non-public information: unannounced transactions, deal \
codenames, target companies under consideration, embargoed or unaudited \
results, or the identities of people staffed to an undisclosed deal.
4. STRATEGY -- proprietary models, signals, thresholds, or position sizing.

Do not flag information that is already public: published financial results, \
market prices and volumes, exchange-listed identifiers, press-office contact \
addresses, published office locations, regulatory text, or general questions \
about finance that carry no client or firm specifics. An identifier-shaped \
string is not by itself sensitive -- an invoice number, a support ticket, and a \
CUSIP are all public.

Content may be obfuscated: separators removed, digits spaced out or spelled as \
words, characters replaced with lookalikes, zero-width characters inserted, or \
the payload encoded in base64 or hex and accompanied by decoding instructions. \
Decode and judge the underlying content, not its surface form.

For every item you flag, quote the exact substring as it appears in the prompt, \
character for character, including any obfuscation. Do not decode it in your \
quotation and do not normalize whitespace."""

SCHEMA = {
    "type": "object",
    "properties": {
        "contains_sensitive": {"type": "boolean"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string",
                             "enum": ["PII", "ACCOUNT", "MNPI", "STRATEGY"]},
                    "text": {"type": "string",
                             "description": "Verbatim substring from the prompt."},
                },
                "required": ["type", "text"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["contains_sensitive", "findings"],
    "additionalProperties": False,
}


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------

def _build_request(model, prompt):
    output_config = {"format": {"type": "json_schema", "schema": SCHEMA}}
    kwargs = {
        "model": model,
        "max_tokens": 2000,
        # Cache the system prompt: it is identical across all 600 calls and is
        # the bulk of the input tokens.
        "system": [{"type": "text", "text": SYSTEM,
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user",
                      "content": f"<prompt>\n{prompt}\n</prompt>"}],
    }
    if model not in NO_EFFORT_MODELS:
        kwargs["thinking"] = {"type": "adaptive"}
        output_config["effort"] = "low"
    kwargs["output_config"] = output_config
    return kwargs


def call_api(client, model, prompt):
    """Return (verdict_dict, latency_ms, usage_dict)."""
    import anthropic

    t0 = time.perf_counter()
    try:
        resp = client.messages.create(**_build_request(model, prompt))
    except anthropic.APIStatusError as e:
        return {"error": f"{e.status_code}: {e.message}"}, \
               1000 * (time.perf_counter() - t0), {}
    except anthropic.APIConnectionError as e:
        return {"error": f"connection: {e}"}, \
               1000 * (time.perf_counter() - t0), {}
    latency = 1000 * (time.perf_counter() - t0)

    if resp.stop_reason == "refusal":
        return {"error": "refusal"}, latency, {}

    text = next((b.text for b in resp.content if b.type == "text"), "")
    try:
        verdict = json.loads(text)
    except json.JSONDecodeError:
        return {"error": "unparseable", "raw": text[:200]}, latency, {}

    u = resp.usage
    usage = {
        "input": u.input_tokens,
        "output": u.output_tokens,
        "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
        "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
    }
    return verdict, latency, usage


def call_mock(client, model, prompt):
    """Offline stand-in: exercises the full harness without spending anything.

    Deliberately crude -- it is here to verify caching, concurrency, offset
    mapping, and the results format, not to approximate model quality.
    """
    time.sleep(0.002)
    findings = []
    for pat, kind in [(r"\b9\d{2}-\d{2}-\d{4}\b", "PII"),
                      (r"\b\d{10}\b", "ACCOUNT"),
                      (r"PROJECT [A-Z]+", "MNPI")]:
        for m in re.finditer(pat, prompt):
            findings.append({"type": kind, "text": m.group()})
    return ({"contains_sensitive": bool(findings), "findings": findings},
            2.0, {"input": 500, "output": 40, "cache_read": 450, "cache_write": 0})


# --------------------------------------------------------------------------
# Offset mapping
# --------------------------------------------------------------------------

def to_spans(prompt, verdict):
    """Map verbatim quoted findings back to character offsets.

    A quotation that does not appear verbatim still counts as a prompt-level
    detection but contributes no span. This slightly penalizes D4 on span
    recall relative to the regex tiers, which cannot miss an offset by
    construction; the paper should state that.
    """
    spans, unlocated = [], 0
    for f in verdict.get("findings", []):
        text = f.get("text", "")
        idx = prompt.find(text) if text else -1
        if idx >= 0:
            spans.append({"start": idx, "end": idx + len(text),
                          "type": f.get("type", "?")})
        else:
            unlocated += 1
    return spans, unlocated


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def estimate(records, model):
    """Rough pre-flight cost estimate. System prompt is assumed cached."""
    sys_tokens = len(SYSTEM) // 4
    body = sum(len(r["prompt"]) // 4 + 20 for r in records)
    # First call writes the cache; the rest read it at ~0.1x.
    inp = sys_tokens + body + sys_tokens * 0.1 * (len(records) - 1)
    out = 80 * len(records)
    pi, po = MODEL_PRICING.get(model, (5.0, 25.0))
    return inp / 1e6 * pi + out / 1e6 * po


def run(records, model, backend, workers, cache_path):
    done = {}
    if os.path.exists(cache_path):
        with open(cache_path) as fh:
            for line in fh:
                row = json.loads(line)
                done[row["id"]] = row
        print(f"resuming: {len(done)} cached results in {cache_path}")

    todo = [r for r in records if r["id"] not in done]
    if not todo:
        print("nothing to do -- all results cached")
        return done

    client = None
    if backend is call_api:
        import anthropic
        client = anthropic.Anthropic(max_retries=5)

    lock = threading.Lock()
    fh = open(cache_path, "a")
    counter = {"n": 0}

    def work(rec):
        verdict, latency, usage = backend(client, model, rec["prompt"])
        spans, unlocated = to_spans(rec["prompt"], verdict)
        row = {"id": rec["id"], "model": model, "verdict": verdict,
               "spans": spans, "unlocated": unlocated,
               "latency_ms": latency, "usage": usage}
        with lock:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()
            done[rec["id"]] = row
            counter["n"] += 1
            if counter["n"] % 25 == 0:
                print(f"  {counter['n']}/{len(todo)}", file=sys.stderr)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, todo))
    fh.close()

    errs = [r for r in done.values() if "error" in r["verdict"]]
    if errs:
        print(f"WARNING: {len(errs)} calls failed; "
              f"first: {errs[0]['verdict']['error']}")
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus.jsonl")
    ap.add_argument("--model", default="claude-opus-5")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default=None)
    ap.add_argument("--mock", action="store_true",
                    help="offline harness check; makes no API calls")
    ap.add_argument("--estimate", action="store_true",
                    help="print the cost estimate and exit")
    ap.add_argument("--yes", action="store_true",
                    help="required to make real API calls")
    args = ap.parse_args()

    records = [json.loads(l) for l in open(args.corpus)]
    model = "mock" if args.mock else args.model
    out = args.out or f"cache/d4-{model.replace('/', '_')}.jsonl"
    os.makedirs(os.path.dirname(out), exist_ok=True)

    if not args.mock:
        cost = estimate(records, args.model)
        print(f"{len(records)} prompts on {args.model}: "
              f"estimated ${cost:.2f} (cache-warm; excludes thinking tokens, "
              f"so treat it as a lower bound)")
        if args.estimate:
            return
        if not args.yes:
            print("re-run with --yes to spend it.")
            return

    t0 = time.perf_counter()
    done = run(records, model, call_mock if args.mock else call_api,
               args.workers, out)
    wall = time.perf_counter() - t0

    lat = sorted(r["latency_ms"] for r in done.values() if "error" not in r["verdict"])
    spent = sum(
        r["usage"].get("input", 0) / 1e6 * MODEL_PRICING.get(args.model, (5, 25))[0]
        + r["usage"].get("output", 0) / 1e6 * MODEL_PRICING.get(args.model, (5, 25))[1]
        for r in done.values() if r.get("usage"))
    unloc = sum(r.get("unlocated", 0) for r in done.values())

    print(f"\n{len(done)} results -> {out}")
    if lat:
        print(f"latency ms: p50 {lat[len(lat)//2]:.0f}  "
              f"p95 {lat[int(len(lat)*.95)]:.0f}  max {lat[-1]:.0f}")
    print(f"wall clock: {wall:.1f}s at {args.workers} workers")
    print(f"billed (from usage): ${spent:.2f}")
    print(f"unlocated quotations: {unloc} "
          f"(counted as prompt-level hits, no span)")


if __name__ == "__main__":
    main()
