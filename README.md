# Sensitive-data egress benchmark for GenAI prompts

Artifact accompanying a submission to PSBD 2026 (13th IEEE Special Session on
Privacy and Security of Big Data, IEEE BigData 2026). Measures what a
prompt-filtering control actually achieves, rather than asserting that it
blocks leaks. Core has zero dependencies: Python 3 stdlib.

```bash
python3 corpus.py --out corpus.jsonl
python3 evaluate.py --corpus corpus.jsonl --out results

# external PII baseline (own venv, keeps the core dependency-free)
python3 -m venv .venv && .venv/bin/pip install presidio-analyzer spacy
.venv/bin/python -m spacy download en_core_web_lg
.venv/bin/python presidio_detector.py
python3 evaluate.py --presidio cache/presidio.jsonl
```

Deterministic (`SEED = 20260918`). *"Prompt leakage" is avoided deliberately: in
the literature it means extraction of the system prompt, the opposite direction
of travel.*

## Corpus

1566 renderings, all synthetic, from **102 base leak prompts** across
**17 templates**. Renderings are *not* independent observations -- cluster
on `base_id` or `template` for any analysis.

| Class | Templates | Note |
|---|---|---|
| `account` | 3 | card, IBAN, settlement identifiers |
| `pii` | 2 | KYC file, tax return |
| `strategy` | 3 | proprietary signal, risk limits, client flow |
| `mnpi` | 6 | carry explicit confidentiality boilerplate |
| `mnpi_unmarked` | 3 | **no boilerplate**; sensitive only because the event has not occurred |

Thirteen evasion transforms plus an untransformed baseline. Four (`base32`,
`urlencode`, `dotted`, `mathbold`) were added **after the detectors were
frozen**, with no detector logic changed -- post-development counterexamples,
not a sample of any evasion distribution.

138 negatives in three strata: 70 `clean`, 50 `near_miss` (public strings
shaped like identifiers), and 18 `paired_public` -- **true 1:1 twins** of the
unmarked MNPI prompts, rendered from the same field values (same company,
amount, people), differing only in whether the event has been announced. Linked
by `pair_id`.

No real personal data: SSNs use the never-issued 900-999 prefix, card numbers
are Luhn-valid but random, names and firms are invented.

## Detector tiers

| Tier | Description |
|---|---|
| `D0_keyword` | 17-term confidentiality word list -- the cheapest plausible answer |
| `D1_pattern` | Handcrafted regular expressions, Luhn-gated cards. **Not** a commercial DLP product |
| `D2_normalized` | D1 + NFKC, zero-width strip, homoglyph fold, digit-word and separator collapse |
| `D3_decoded` | D2 + bounded decode over base64 / hex / reversed tokens |
| `D1'_presidio` | Presidio 2.2.360, spaCy 3.7.5 / `en_core_web_lg` 3.7.1, en, 16 recognisers. Raw scores captured at threshold 0; thresholds applied offline. An **external PII baseline**, not a DLP product |
| `D4_*` | Semantic tier, a Claude model. Run 2026-09-28 against `claude-opus-5`; see below |

## Results

Full tables (A through E, plus the Presidio entity-attribution and threshold-sweep breakdowns) are in `results.md`, generated directly by `evaluate.py` -- not reproduced here by hand, so this file cannot go stale relative to the numbers. Machine-readable: `results.json`.

## D4: the semantic tier

**Run.** All 1566 prompts against `claude-opus-5`, 2026-09-28, two sessions
(the first stopped when the API key ran out of balance at 1029/1566; resumed
and completed from the on-disk cache -- nothing was re-spent). Input+output
token cost alone sums to \$5.16 across the 1084 successful calls; this is a
known lower bound, not the true total -- it excludes prompt-cache write/read
pricing and excludes input tokens on the 482 refused calls entirely, since the
API does not return `usage` on a refusal. Session 1 alone billed \$4.54 by
actual account-balance draw-down against a \$3.63 figure computed the same
way, a $\sim$25\% undercount; treat any total computed from `usage` fields as
directional, not exact. Reproduce or extend:

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...
python3 llm_detector.py --mock                          # offline harness check
python3 llm_detector.py --estimate --model claude-opus-5 # cost only, no calls
python3 llm_detector.py --model claude-opus-5 --yes      # resumes from cache/d4-claude-opus-5.jsonl
python3 evaluate.py --presidio cache/presidio.jsonl --d4 cache/d4-claude-opus-5.jsonl
```

Results cache per (model, prompt id): re-runs are free and published numbers are
reproducible without re-spending. `--yes` is required before any real call.
Latency is recorded per call because this control sits in the request path.

**Headline result.** D4 reaches 1.000 recall on MNPI under no evasion
(including the three unmarked templates, where the pattern tiers cap at
0.333), and separates all 3 of 3 unannounced/announced scenarios in the paired
stratum -- the one result in the whole benchmark that no identifier-based or
keyword-based detector produces even once. See `results.md` Tables A/C1/E for
the numbers this claim rests on.

**The cost of that result is refusal, not error.** 482 of 1566 calls (0.308)
return `stop_reason == "refusal"` -- the provider's safety classifier declines
before the prompt is judged for content at all. This is concentrated almost
entirely on the three transforms that ask the model to decode an encoded
payload: recall collapses to 0.010 on base64, 0.020 on hex, 0.010 on
percent-encoding, while every visual/formatting evasion (spacing, full-width,
homoglyph, spelled-out digits) stays at 0.95+. A refused prompt is scored as
neither a detection nor a miss -- it is a third outcome a deployed control
needs its own policy for, and the paper's Implications section argues this is
itself an unspecified part of "detect sensitive data with a model."

Report D4 as **one untuned operating point**, not a bound: the system prompt was
written once and never tuned. D4 is credited with a detection even when its
quotation cannot be located verbatim (35 such cases), so its annotated-field
coverage is not comparable to the pattern tiers.

> `--mock` output is not a result -- three crude regexes for exercising caching,
> concurrency and offset mapping offline.

## Files

| File | Purpose |
|---|---|
| `corpus.py` | Generators, templates, paired counterparts, 13 transforms, 3 negative strata |
| `detectors.py` | D0-D3; offset-preserving normalization; bounded decode |
| `evaluate.py` | Scoring, template-clustered bootstrap CIs, paired 2x2 over twins; emits md/tex/json |
| `llm_detector.py` | D4 runner: structured output, cached system prompt, disk cache, cost guard, mock |
| `presidio_detector.py` | D1' runner: raw Presidio scores over the corpus, cached for offline threshold sweeps |
| `extract_pdf_text.py` | Text extractor for LaTeX-produced PDFs (drops `fi`/`ffi` ligatures); used for citation verification, not part of the benchmark itself |
| `cache/presidio.jsonl` | Cached Presidio run (raw confidence scores) |
| `cache/d4-claude-opus-5.jsonl` | Cached D4 run against Claude Opus 5 |
| `corpus.jsonl` | The generated corpus itself (seed `20260918`), so results are reproducible without re-running `corpus.py` |
| `results.md` / `results.json` | Full results tables, human- and machine-readable |
