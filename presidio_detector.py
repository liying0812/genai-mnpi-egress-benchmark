"""D1': Microsoft Presidio as an external PII-detection baseline.

Why this exists: our own D1 is regular expressions we wrote, and a result about
patterns we chose is weak evidence about patterns in general. Presidio is the
reference open-source implementation and is the detector REDACT reports on, so
including it makes our numbers comparable to published work.

Scope of the claim. Presidio is a **PII detection library**, not a deployed
data-loss-prevention product, and it is not marketed as an MNPI detector.
Results here bound what an off-the-shelf personal-information detector achieves
on this benchmark; they say nothing about commercial DLP suites, and no such
claim should be made from them.

Runs in its own virtualenv so the rest of the benchmark stays dependency-free;
results are cached to JSONL and consumed by evaluate.py --presidio.

    python3 -m venv .venv
    .venv/bin/pip install presidio-analyzer spacy
    .venv/bin/python -m spacy download en_core_web_lg
    .venv/bin/python presidio_detector.py
    python3 evaluate.py --presidio cache/presidio.jsonl
"""

import argparse
import json
import os
import time

# Entities enabled. Chosen to mirror the classes our corpus actually contains,
# so that Presidio is not penalised for recognisers we never exercise. Recorded
# here rather than left to the default so the run is reproducible.
ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
    "US_SSN", "US_BANK_NUMBER", "US_ITIN", "US_PASSPORT", "US_DRIVER_LICENSE",
    "LOCATION", "DATE_TIME", "NRP", "ORGANIZATION", "IP_ADDRESS", "URL",
]

LANGUAGE = "en"

# Presidio's own default is 0 (AnalyzerEngine.default_score_threshold), i.e.
# accept every candidate. That is not a defensible operating point to report on
# its own, so we capture raw scores at threshold 0 and sweep offline. Any
# threshold we headline is OUR choice and must be labelled as such.
CAPTURE_THRESHOLD = 0.0


def versions():
    import importlib.metadata as md
    import en_core_web_lg
    return {
        "presidio_analyzer": md.version("presidio-analyzer"),
        "spacy": md.version("spacy"),
        "spacy_model": "en_core_web_lg",
        "spacy_model_version": en_core_web_lg.load().meta["version"],
        "entities": ENTITIES,
        "language": LANGUAGE,
        "capture_threshold": CAPTURE_THRESHOLD,
        "presidio_default_threshold": 0.0,
        "note": "raw scores stored; thresholds applied offline in evaluate.py",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus.jsonl")
    ap.add_argument("--out", default="cache/presidio.jsonl")
    args = ap.parse_args()

    from presidio_analyzer import AnalyzerEngine

    engine = AnalyzerEngine()
    records = [json.loads(l) for l in open(args.corpus)]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    meta = versions()
    print(json.dumps(meta, indent=2))

    with open(args.out, "w") as fh:
        fh.write(json.dumps({"_meta": meta}) + "\n")
        for i, rec in enumerate(records):
            t0 = time.perf_counter()
            results = engine.analyze(text=rec["prompt"], language=LANGUAGE,
                                     entities=ENTITIES,
                                     score_threshold=CAPTURE_THRESHOLD)
            ms = 1000 * (time.perf_counter() - t0)
            fh.write(json.dumps({
                "id": rec["id"],
                "spans": [{"start": r.start, "end": r.end,
                           "type": r.entity_type, "score": round(r.score, 4)}
                          for r in results],
                "latency_ms": ms,
            }) + "\n")
            if (i + 1) % 200 == 0:
                print(f"  {i + 1}/{len(records)}", flush=True)

    print(f"wrote {len(records)} results to {args.out}")


if __name__ == "__main__":
    main()
