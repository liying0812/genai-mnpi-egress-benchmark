### Table A. Detection on unmodified input

| Detector | Recall, unmodified input | Field-hit (PII+acct) | Complete-field (PII+acct) | ms/prompt |
|---|---|---|---|---|
| D0_keyword | 0.529 | 0.000 | 0.000 | 0.08 |
| D1_pattern | 0.706 | 0.773 | 0.773 | 0.08 |
| D2_normalized | 0.706 | 0.773 | 0.773 | 0.44 |
| D3_decoded | 0.706 | 0.773 | 0.773 | 0.53 |
| D1p_presidio | 1.000 | 0.780 | 0.689 | 16.17 |
| D4_opus5 | 1.000 | 0.939 | 0.939 | 3322.09 |

*Field-hit counts a gold field as covered if any predicted span overlaps it; complete-field requires every character to be covered, which is what redaction needs. The two can order detectors differently.*

Recall with no evasion, 95% template-clustered bootstrap interval (2000 draws). The seventeen templates were written by us, not sampled from any population, so this quantifies sensitivity to our template choice -- it is not a coverage interval for real financial prompts. Presidio's [1.000, 1.000] means every template we wrote was flagged, not that flagging is certain:
- D0_keyword: 0.529 [0.294, 0.765]
- D1_pattern: 0.706 [0.471, 0.882]
- D2_normalized: 0.706 [0.471, 0.882]
- D3_decoded: 0.706 [0.471, 0.882]
- D1p_presidio: 1.000 [1.000, 1.000]
- D4_opus5: 1.000 [1.000, 1.000]

*No recall pooled over transforms is reported: any such average would be weighted by a transform mix we chose; per-transform results are in Table B. Field coverage is which annotated entity fields a detection overlapped -- for MNPI it is not a redaction measure. Precision and F1 are omitted for the same kind of reason -- they are prevalence-dependent and our prevalence is a design choice. False positives are in Table D.*

### Table B. Recall by evasion variant

| Evasion | Cov. | D0_keyword | fc | D1_pattern | fc | D2_normalized | fc | D3_decoded | fc | D1p_presidio | fc | D4_opus5 | fc |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| none | -- | 0.529 | 0.000 | 0.706 | 0.403 | 0.706 | 0.403 | 0.706 | 0.403 | 1.000 | 0.527 | 1.000 | 0.911 |
| base32 (H) | 1.000 | 0.529 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | 0.145 | 0.520 | 0.527 |
| base64 | 1.000 | 0.529 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.647 | 0.387 | 0.725 | 0.188 | 0.010 | 0.008 |
| dotted (H) | 1.000 | 0.529 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.892 | 0.341 | 0.480 | 0.433 |
| fullwidth | 1.000 | 0.529 | 0.000 | 0.235 | 0.081 | 0.706 | 0.403 | 0.706 | 0.403 | 0.951 | 0.476 | 0.990 | 0.892 |
| hex | 1.000 | 0.529 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.647 | 0.387 | 0.549 | 0.081 | 0.020 | 0.016 |
| homoglyph | 0.589 | 0.529 | 0.000 | 0.588 | 0.325 | 0.706 | 0.403 | 0.706 | 0.403 | 1.000 | 0.599 | 1.000 | 0.917 |
| mathbold (H) | 0.452 | 0.529 | 0.000 | 0.706 | 0.387 | 0.706 | 0.403 | 0.706 | 0.403 | 1.000 | 0.484 | 1.000 | 0.911 |
| reversed | 1.000 | 0.529 | 0.000 | 0.235 | 0.065 | 0.245 | 0.067 | 0.294 | 0.099 | 0.765 | 0.132 | 0.333 | 0.298 |
| spaced | 1.000 | 0.529 | 0.000 | 0.069 | 0.019 | 0.353 | 0.116 | 0.353 | 0.116 | 0.755 | 0.169 | 0.951 | 0.774 |
| spelled | 0.452 | 0.529 | 0.000 | 0.235 | 0.065 | 0.559 | 0.274 | 0.559 | 0.274 | 1.000 | 0.484 | 1.000 | 0.903 |
| strip_format | 0.613 | 0.529 | 0.000 | 0.588 | 0.339 | 0.588 | 0.339 | 0.588 | 0.339 | 0.794 | 0.255 | 1.000 | 0.930 |
| urlencode (H) | 1.000 | 0.529 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.716 | 0.140 | 0.010 | 0.008 |
| zwsp | 1.000 | 0.529 | 0.000 | 0.000 | 0.000 | 0.706 | 0.403 | 0.706 | 0.403 | 0.745 | 0.183 | 1.000 | 0.919 |

*(H) = held out: added after the detectors were written, with no detector logic changed. `fc` = annotated-field coverage: which entity fields a detection overlapped, as opposed to merely firing on the prompt. For MNPI this is not a redaction measure.*

*Cov. is the fraction of gold spans the transform actually alters. Four transforms are partial -- `homoglyph`, `strip_format`, `spelled`, `mathbold` -- so an untouched span in the same prompt can still trigger a detection and their recall overstates robustness.*

### Table C1. Recall by leak category, NO EVASION APPLIED

| Category | Tpl. | D0_keyword | D1_pattern | D2_normalized | D3_decoded | D1p_presidio | D4_opus5 |
|---|---|---|---|---|---|---|---|
| account | 3 | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| mnpi (marked) | 6 | 1.000 | 0.667 | 0.667 | 0.667 | 1.000 | 1.000 |
| mnpi (unmarked) | 3 | 0.333 | 0.333 | 0.333 | 0.333 | 1.000 | 1.000 |
| **mnpi (all)** | 9 | 0.778 | 0.556 | 0.556 | 0.556 | 1.000 | 1.000 |
| pii | 2 | 0.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| strategy | 3 | 0.667 | 0.667 | 0.667 | 0.667 | 1.000 | 1.000 |

*No adversary at all. These figures are not confounded with the evasion transforms, so they are free of transform-specific co-design -- though the templates and detectors were still written by the same authors. Cite THIS table, not C2, for category blindness. Note D0 vs mnpi_unmarked: the keyword baseline tracks confidentiality boilerplate, not sensitivity.*

### Table C2. Recall by leak category, pooled over all variants

| Category | Tpl. | D0_keyword | D1_pattern | D2_normalized | D3_decoded | D1p_presidio | D4_opus5 |
|---|---|---|---|---|---|---|---|
| account | 3 | 0.000 | 0.480 | 0.643 | 0.786 | 0.841 | 0.742 |
| mnpi (marked) | 6 | 1.000 | 0.167 | 0.302 | 0.373 | 0.788 | 0.597 |
| mnpi (unmarked) | 3 | 0.333 | 0.095 | 0.147 | 0.194 | 1.000 | 0.639 |
| pii | 2 | 0.000 | 0.321 | 0.577 | 0.750 | 0.905 | 0.726 |
| strategy | 3 | 0.667 | 0.238 | 0.357 | 0.452 | 0.794 | 0.710 |

*Tpl. is the number of distinct task templates behind the category. These figures characterize the task shapes modelled, not the category in general.*

### Table E. Unannounced/announced pairs (n=18, identical fields)

| Detector | flags both | only unannounced | only announced | neither | scenarios correct |
|---|---|---|---|---|---|
| D0_keyword | 0 | 6 | 0 | 12 | 1/3 |
| D1_pattern | 6 | 0 | 0 | 12 | 0/3 |
| D2_normalized | 6 | 0 | 0 | 12 | 0/3 |
| D3_decoded | 6 | 0 | 0 | 12 | 0/3 |
| D1p_presidio | 18 | 0 | 0 | 0 | 0/3 |
| D4_opus5 | 0 | 18 | 0 | 0 | 3/3 |

*Only `only unannounced` is the desired decision. Pairs share identical entity payloads and differ in a short disclosure-status phrase. The eighteen pairs are six instantiations of each of three scenarios, so the last column -- scenarios on which every instantiation was decided correctly -- is the unit of evidence. No significance test is reported: instantiations within a scenario are not independent.*

### Table D. False positives, by negative stratum

| Detector | clean | near-miss | paired-public |
|---|---|---|---|
| D0_keyword | 0/70 | 0/50 | 0/18 |
| D1_pattern | 0/70 | 20/50 | 6/18 |
| D2_normalized | 0/70 | 20/50 | 6/18 |
| D3_decoded | 0/70 | 20/50 | 6/18 |
| D1p_presidio | 7/70 | 32/50 | 18/18 |
| D4_opus5 | 0/70 | 4/50 | 0/18 |

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
