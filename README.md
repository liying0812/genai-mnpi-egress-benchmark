# Sensitive-data egress benchmark for GenAI prompts

Measures what a prompt-filtering control actually achieves, rather than
asserting that it blocks leaks. Core has zero dependencies: Python 3 stdlib.

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

### Table A. Detection on unmodified input

| Detector | Recall, unmodified input | Field-hit (PII+acct) | Complete-field (PII+acct) | ms/prompt |
|---|---|---|---|---|
| D0_keyword | 0.529 | 0.000 | 0.000 | 0.03 |
| D1_pattern | 0.706 | 0.773 | 0.773 | 0.05 |
| D2_normalized | 0.706 | 0.773 | 0.773 | 0.21 |
| D3_decoded | 0.706 | 0.773 | 0.773 | 0.24 |
| D1p_presidio | 1.000 | 0.780 | 0.689 | 10.28 |

*Field-hit counts a gold field as covered if any predicted span overlaps it; complete-field requires every character to be covered, which is what redaction needs. The two can order detectors differently.*

Recall with no evasion, 95% template-clustered bootstrap interval (2000 draws). The seventeen templates were written by us, not sampled from any population, so this quantifies sensitivity to our template choice -- it is not a coverage interval for real financial prompts. Presidio's [1.000, 1.000] means every template we wrote was flagged, not that flagging is certain:
- D0_keyword: 0.529 [0.294, 0.765]
- D1_pattern: 0.706 [0.471, 0.882]
- D2_normalized: 0.706 [0.471, 0.882]
- D3_decoded: 0.706 [0.471, 0.882]
- D1p_presidio: 1.000 [1.000, 1.000]

*No recall pooled over transforms is reported: any such average would be weighted by a transform mix we chose; per-transform results are in Table B. Field coverage is which annotated entity fields a detection overlapped -- for MNPI it is not a redaction measure. Precision and F1 are omitted for the same kind of reason -- they are prevalence-dependent and our prevalence is a design choice. False positives are in Table D.*

### Table C1. Recall by leak category, NO EVASION APPLIED

| Category | Tpl. | D0_keyword | D1_pattern | D2_normalized | D3_decoded | D1p_presidio |
|---|---|---|---|---|---|---|
| account | 3 | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| mnpi (marked) | 6 | 1.000 | 0.667 | 0.667 | 0.667 | 1.000 |
| mnpi (unmarked) | 3 | 0.333 | 0.333 | 0.333 | 0.333 | 1.000 |
| **mnpi (all)** | 9 | 0.778 | 0.556 | 0.556 | 0.556 | 1.000 |
| pii | 2 | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| strategy | 3 | 0.667 | 0.667 | 0.667 | 0.667 | 1.000 |

*No adversary at all. These figures are not confounded with the evasion transforms, so they are free of transform-specific co-design -- though the templates and detectors were still written by the same authors. Cite THIS table, not C2, for category blindness. Note D0 vs mnpi_unmarked: the keyword baseline tracks confidentiality boilerplate, not sensitivity.*

### Table E. Unannounced/announced pairs (n=18, identical fields)

| Detector | flags both | only unannounced | only announced | neither | scenarios correct |
|---|---|---|---|---|---|
| D0_keyword | 0 | 6 | 0 | 12 | 1/3 |
| D1_pattern | 6 | 0 | 0 | 12 | 0/3 |
| D2_normalized | 6 | 0 | 0 | 12 | 0/3 |
| D3_decoded | 6 | 0 | 0 | 12 | 0/3 |
| D1p_presidio | 18 | 0 | 0 | 0 | 0/3 |

*Only `only unannounced` is the desired decision. Pairs share identical entity payloads and differ in a short disclosure-status phrase. The eighteen pairs are six instantiations of each of three scenarios, so the last column -- scenarios on which every instantiation was decided correctly -- is the unit of evidence. No significance test is reported: the independent unit is the scenario, leaving only three scenario-level observations.*

### Table D. False positives, by negative stratum

| Detector | clean | near-miss | paired-public |
|---|---|---|---|
| D0_keyword | 0/70 | 0/50 | 0/18 |
| D1_pattern | 0/70 | 20/50 | 6/18 |
| D2_normalized | 0/70 | 20/50 | 6/18 |
| D3_decoded | 0/70 | 20/50 | 6/18 |
| D1p_presidio | 7/70 | 32/50 | 18/18 |

*paired-public prompts restate the unmarked MNPI prompts as announced events, with identical entity payloads. No identifier separates them; one of the three disclosure phrasings does coincide with a term on D0's list, which Table E reports.*

### Presidio entity-type attribution

| Entity type | MNPI (n=54) | unmarked MNPI (n=18) | public twins (n=18) |
|---|---|---|---|
| PERSON | 54 | 18 | 18 |
| DATE_TIME | 30 | 18 | 18 |
| US_DRIVER_LICENSE | 12 | 6 | 6 |
| LOCATION | 1 | 0 | 0 |

Withholding PERSON, DATE_TIME and US_DRIVER_LICENSE from the cached output leaves recall of 1/54 on MNPI prompts and 0/18 on the unannounced scenarios. This is a post-hoc ablation for mechanism attribution, not a proposed detector configuration.

*Counts are prompts in which the type fired at least once. The unmarked MNPI column and the public-twin column are the same eighteen scenarios in their unannounced and announced forms.*

### Presidio score-threshold sweep

| threshold | recall (no evasion) | FP on 70 clean | pairs correct |
|---|---|---|---|
| 0.00 | 1.000 | 7 | 0/18 |
| 0.35 | 1.000 | 7 | 0/18 |
| 0.50 | 1.000 | 7 | 0/18 |
| 0.85 | 1.000 | 7 | 0/18 |

*0.00 is Presidio's own default. No threshold trades the false positives away without losing recall, and none produces a correct pair decision.*

### What these show

1. **No identifier- or entity-centric detector tracks disclosure status.** Over 18 pairs
   (6 instantiations of each of 3 scenarios): D1-D3 flag both members six times
   and neither twelve times; Presidio flags both in all eighteen. Neither
   separates any scenario. **D0 separates one** -- the board scenario ends
   "not yet filed", a phrase on its list, while its twin ends "filed in an
   8-K". The keyword tier succeeds only when the relevant disclosure-status
   wording is explicitly represented in its list. No significance test: the
   independent unit is the scenario, so the unit of evidence is 3, and D0's
   six successes are one scenario.
2. **A keyword list looks like the answer and is not.** 1.000 recall on MNPI
   prompts carrying boilerplate, 0.333 on unmarked ones -- and the one it still
   catches ends "not yet filed", a phrase on its own list. Field coverage is
   0.000 everywhere: it matches warning labels, so it can block but never
   redact.
3. **Hardening does not generalize.** Normalization and decoding recover most of
   the loss to encodings they were written against, and score 0.000 on three of
   the four introduced afterwards. Presidio fires more often on those but rarely
   locates the payload -- base32: 1.000 prompt recall, **0.145 annotated-field coverage**.
4. **High recall is bought with false positives, not judgement.** Presidio
   reaches 1.000 recall on every class and flags 7/70 clean negatives
   ("Basel" as a LOCATION, "quarterly" as a DATE_TIME). Its MNPI detections are
   attributable to three entity types and no others: PERSON 54/54, DATE_TIME
   30/54, US_DRIVER_LICENSE 12/54. Two involve systematic errors ("these
   minutes" read as a date, `Q3` as a licence number). Withholding those three
   types from the cached output drops MNPI recall to **1/54**. Attribution
   counts are identical between unannounced and announced twins.
5. **Field-hit is not redaction.** Complete-field coverage -- the union of
   predicted spans covering every character, a conservative criterion for
   full-value redaction -- reverses the ordering against field-hit rate: D1-D3 hold
   at 0.773, Presidio drops from 0.780 to 0.689.
6. **The control fails in both directions.** Our tiers: 0/70 clean, 20/50
   near-miss (5 of 13 scenario templates), 6/18 announced twins.

### Limitations -- state all of these

- Synthetic, template-derived; recall is conditional on the leak shapes chosen
  and is not a base rate for any firm.
- False-positive counts characterize challenge sets **we constructed**. No
  pooled rate is reported, by design.
- Held-out transforms were chosen by us after seeing earlier results:
  counterexamples, not an unbiased generalization estimate. Do not average them
  into a rate.
- D2/D3 were developed against nine of the thirteen transforms.
- `homoglyph`, `strip_format`, `spelled`, `mathbold` are **partial** -- read
  their recall against the coverage column, never alone.
- `mathbold` is recovered by D1 with no normalization at all, because Python's
  `\d` matches Unicode `Nd`. Not evidence that normalization generalizes.
- D0's flat recall across evasion conditions is an artifact: transforms touch
  sensitive spans, never surrounding boilerplate. Deleting "confidential"
  defeats it entirely.
- `reversed` is only partly recovered by D3 -- the decode tokenizer splits on
  separators. A detector limitation, not a strong evasion.
- Presidio is a personal-information detection library at one pinned
  configuration, **not** a deployed DLP product and not marketed as an MNPI
  detector. Its own default threshold is 0; any threshold we headline is our
  choice.
- Bootstrap intervals are template-clustered over seventeen templates **we
  wrote**. They quantify sensitivity to that choice, not coverage of any real
  prompt population. Presidio's [1.000, 1.000] means every template we wrote was
  flagged, not that flagging is certain.
- Templates and detectors share authorship.
- These are **synthetic MNPI scenarios**. Materiality is a legal determination
  we do not make, and no compliance practitioner has validated the templates.
- Field coverage is not a redaction measure for MNPI: the disclosive content is
  the unannounced proposition, not any single annotated field. Redaction
  conclusions are restricted to PII and account data.
- Amounts are drawn from per-use ranges (per-share, revenue, raise, VaR limit,
  retail, notional) so they are plausible in context; earlier versions used one
  range everywhere and produced implausible figures.

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
stratum -- the one result in the whole benchmark that no identifier-based
detector produces even once (the keyword tier gets 1 of 3). See `results.md`
Tables A/C1/E for the numbers this claim rests on.

**The cost of that result is refusal, not error.** 482 of 1566 calls (0.308)
return `stop_reason == "refusal"` -- the API reports a refusal rather than a
classification. This is concentrated almost entirely on the three transforms
that ask the model to decode an encoded payload: recall collapses to 0.010 on
base64, 0.020 on hex, 0.010 on percent-encoding, while every visual/formatting
evasion (spacing, full-width, homoglyph, spelled-out digits) stays at 0.95+.
A refusal returns no verdict, so it is scored as a miss in the recall figures
above, the same as a classification that overlooks the sensitive content --
it is a third outcome a deployed control needs its own policy for, and the
paper's Implications section argues this is itself an unspecified part of
"detect sensitive data with a model."

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
| `extract_pdf_text.py` | Text extractor for LaTeX-produced PDFs (drops `fi`/`ffi` ligatures) |
