"""Evaluate detector tiers over the synthetic prompt corpus.

Prompt-level task: does the middleware flag this prompt before it reaches the
external model? Span-level recall is reported as a secondary measure of how
much of the sensitive payload a redaction step would actually mask.

Usage:
    python3 evaluate.py --corpus corpus.jsonl --out results
"""

import argparse
import collections
import json
import math
import random
import time

from corpus import HELD_OUT
from detectors import DETECTORS


def overlaps(a, b):
    return a["start"] < b["end"] and b["start"] < a["end"]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def as_pair(fn):
    """Adapt a span-returning detector to the (flagged, spans) protocol."""
    def g(text):
        hits = fn(text)
        return bool(hits), hits
    return g


def load_d4(path, records):
    """Build a D4 detector from a cached llm_detector.py run.

    Returns (name, fn, mean_latency_ms). The model may report a prompt as
    sensitive while quoting text we cannot locate verbatim; such a prompt is
    still flagged, with no span. Flagging and localization are kept separate
    for exactly this reason.
    """
    rows = {}
    model = "d4"
    for line in open(path):
        row = json.loads(line)
        rows[row["id"]] = row
        model = row.get("model", model)

    missing = [r["id"] for r in records if r["id"] not in rows]
    failed = [i for i, r in rows.items() if "error" in r["verdict"]]
    if missing:
        print(f"WARNING: {len(missing)} prompts absent from {path}; "
              f"scored as not flagged. Re-run llm_detector.py to complete.")
    if failed:
        print(f"WARNING: {len(failed)} cached calls errored; scored as not flagged.")

    by_text = {}
    for r in records:
        row = rows.get(r["id"])
        if not row or "error" in row["verdict"]:
            by_text[r["prompt"]] = (False, [])
        else:
            by_text[r["prompt"]] = (
                bool(row["verdict"].get("contains_sensitive")), row["spans"])

    lat = [r["latency_ms"] for r in rows.values() if "error" not in r["verdict"]]
    mean_ms = sum(lat) / len(lat) if lat else float("nan")
    short = model.replace("claude-", "").replace("-", "")
    return f"D4_{short}", (lambda t: by_text.get(t, (False, []))), mean_ms


def load_cached(path, records, name, threshold=None):
    """Load a cached external detector (Presidio or D4) as (name, fn, mean_ms).

    Handles both file shapes: Presidio rows carry `spans`; D4 rows carry a
    `verdict` and may flag a prompt without a locatable span.
    """
    rows, meta = {}, None
    for line in open(path):
        row = json.loads(line)
        if "_meta" in row:
            meta = row["_meta"]
            continue
        rows[row["id"]] = row
        name = row.get("model", name)

    missing = [r["id"] for r in records if r["id"] not in rows]
    failed = [i for i, r in rows.items()
              if isinstance(r.get("verdict"), dict) and "error" in r["verdict"]]
    if missing:
        print(f"WARNING: {len(missing)} prompts absent from {path}; "
              f"scored as not flagged.")
    if failed:
        print(f"WARNING: {len(failed)} cached calls errored; scored as not flagged.")

    by_text = {}
    for r in records:
        row = rows.get(r["id"])
        if not row or (isinstance(row.get("verdict"), dict)
                       and "error" in row["verdict"]):
            by_text[r["prompt"]] = (False, [])
        elif "verdict" in row:
            by_text[r["prompt"]] = (bool(row["verdict"].get("contains_sensitive")),
                                    row["spans"])
        else:
            sp = row["spans"]
            if threshold is not None:
                sp = [x for x in sp if x.get("score", 1.0) >= threshold]
            by_text[r["prompt"]] = (bool(sp), sp)

    lat = [r["latency_ms"] for r in rows.values() if "latency_ms" in r]
    mean_ms = sum(lat) / len(lat) if lat else float("nan")
    short = str(name).replace("claude-", "").replace("-", "")
    return short, (lambda t: by_text.get(t, (False, []))), mean_ms, meta


def evaluate(records, name, fn, ms_override=None):
    counts = collections.Counter()
    per_variant = collections.defaultdict(collections.Counter)
    per_category = collections.defaultdict(collections.Counter)
    per_stratum = collections.defaultdict(collections.Counter)
    per_cat_none = collections.defaultdict(collections.Counter)
    per_variant_span = collections.defaultdict(collections.Counter)
    elapsed = 0.0

    for rec in records:
        t0 = time.perf_counter()
        flagged, hits = fn(rec["prompt"])
        elapsed += time.perf_counter() - t0

        v, c = per_variant[rec["variant"]], per_category[rec["category"]]

        if rec["label"] == 1:
            key = "tp" if flagged else "fn"
        else:
            key = "fp" if flagged else "tn"
        counts[key] += 1
        v[key] += 1
        c[key] += 1
        if rec["label"] == 0:
            per_stratum[rec.get("stratum", "clean")][key] += 1
        if rec["label"] == 1 and rec["variant"] == "none":
            per_cat_none[rec["category"]][key] += 1
            # Field coverage is only a redaction measure where the sensitive
            # content is the field itself. For MNPI and strategy the disclosive
            # element is the unannounced proposition, which no single field
            # carries, so those classes are excluded from the headline figure
            # and reported per class in the artifact instead.
            key = "_span" if rec["category"] in ("pii", "account") else "_spanx"
            for gold in rec["spans"]:
                # Two coverage definitions. `hit` is any overlap, which is what
                # most span metrics report; `full` requires the union of
                # predicted spans to cover every character of the gold field,
                # which is what redaction actually needs. They can order
                # detectors differently, so we report both.
                covered = {i for h in hits
                           for i in range(max(h["start"], gold["start"]),
                                          min(h["end"], gold["end"]))}
                per_cat_none[key]["tp" if covered else "fn"] += 1
                per_cat_none[key + "full"][
                    "tp" if len(covered) == gold["end"] - gold["start"]
                    else "fn"] += 1

        # span-level recall: a gold span counts as covered if any hit overlaps it
        for gold in rec["spans"]:
            covered = any(overlaps(gold, h) for h in hits)
            counts["span_tp" if covered else "span_fn"] += 1
            v["span_tp" if covered else "span_fn"] += 1
            per_variant_span[rec["variant"]]["tp" if covered else "fn"] += 1

    return {
        "detector": name,
        "counts": dict(counts),
        "per_variant": {k: dict(v) for k, v in per_variant.items()},
        "per_category": {k: dict(v) for k, v in per_category.items()},
        "per_stratum": {k: dict(v) for k, v in per_stratum.items()},
        "per_cat_none": {k: dict(v) for k, v in per_cat_none.items()},
        "per_variant_span": {k: dict(v) for k, v in per_variant_span.items()},
        "ms_per_prompt": (ms_override if ms_override is not None
                          else 1000 * elapsed / len(records)),
    }


MNPI_CLASSES = ("mnpi", "mnpi_unmarked")


def merged_mnpi(per_cat):
    c = collections.Counter()
    for k in MNPI_CLASSES:
        c.update(per_cat.get(k, {}))
    return dict(c)


def coverage(records):
    """Fraction of gold spans each transform actually alters.

    Several transforms are partial: `homoglyph` only rewrites letters it has a
    lookalike for, `strip_format` only removes separators that exist. Under
    block-on-any-hit, a prompt whose other spans were left untouched is still
    flagged, so recall on a partial transform overstates robustness. Reporting
    coverage next to recall keeps that visible.
    """
    base = {r["base_id"]: r for r in records if r["variant"] == "none"}
    changed, total = collections.Counter(), collections.Counter()
    for r in records:
        if r["label"] != 1:
            continue
        b = base.get(r["base_id"])
        if not b:
            continue
        if r["variant"] == "none":
            continue          # identity transform: coverage is undefined
        for s, t in zip(r["spans"], b["spans"]):
            total[r["variant"]] += 1
            changed[r["variant"]] += (s["shown"] != t["shown"])
    return {v: changed[v] / total[v] if total[v] else float("nan") for v in total}



def paired_analysis(records, fn):
    """2x2 over true unannounced/announced pairs, reported per scenario.

    Each pair shares its company, amount and people; only disclosure status
    differs. A detector with any notion of what is public should flag the
    unannounced member and not its twin.
    """
    unm = {r["pair_id"]: r for r in records
           if r.get("category") == "mnpi_unmarked" and r["variant"] == "none"}
    pub = {r["pair_id"]: r for r in records
           if r.get("stratum") == "paired_public"}
    both = only_u = only_p = neither = 0
    per_tpl = collections.defaultdict(lambda: [0, 0])
    for pid in sorted(set(unm) & set(pub)):
        u = fn(unm[pid]["prompt"])[0]
        q = fn(pub[pid]["prompt"])[0]
        both += u and q
        only_u += u and not q
        only_p += q and not u
        neither += not u and not q
        t = unm[pid]["template"]
        per_tpl[t][0] += (u and not q)
        per_tpl[t][1] += 1
    # No significance test is reported. The eighteen pairs are six
    # instantiations of each of three scenarios, so they are not independent
    # observations and a McNemar test over them would overstate the evidence by
    # a factor of six. The informative statistic is `scenarios_correct`: the
    # number of scenarios decided correctly in every instantiation.
    scen_ok = sum(1 for v in per_tpl.values() if v[0] == v[1])
    return {"pairs": len(set(unm) & set(pub)), "both": both,
            "only_unannounced": only_u, "only_announced": only_p,
            "neither": neither, "concordant": both + neither,
            "scenarios": len(per_tpl), "scenarios_correct": scen_ok,
            "by_template": {k: v[0] for k, v in sorted(per_tpl.items())}}


def boot_ci(records, fn, select, n_boot=2000, seed=7):
    """Bootstrap a rate, resampling TEMPLATES rather than renderings.

    `select` filters to the rows in scope BEFORE clustering. Filtering inside
    the resample instead would let out-of-scope templates enter the pool and
    contribute nothing, so the effective number of clusters would vary from
    draw to draw and the interval would be wrong.
    """
    scope = [r for r in records if select(r)]
    by_t = collections.defaultdict(list)
    for r in scope:
        by_t[r["template"]].append(r)
    tmpls = sorted(by_t)

    def rate(sample):
        num = den = 0
        for t in sample:
            for r in by_t[t]:
                den += 1
                num += fn(r["prompt"])[0]
        return num / den if den else float("nan")

    point = rate(tmpls)
    rng = random.Random(seed)
    draws = sorted(x for x in
                   (rate([rng.choice(tmpls) for _ in tmpls]) for _ in range(n_boot))
                   if x == x)
    if not draws:
        return point, float("nan"), float("nan")
    return point, draws[int(.025 * len(draws))], draws[int(.975 * len(draws))]


def cond_recall(r, variants):
    """Recall pooled over a named set of variants."""
    tp = sum(r["per_variant"].get(v, {}).get("tp", 0) for v in variants)
    fn = sum(r["per_variant"].get(v, {}).get("fn", 0) for v in variants)
    return tp / (tp + fn) if tp + fn else float("nan")


def recall_of(c):
    tp, fn = c.get("tp", 0), c.get("fn", 0)
    return tp / (tp + fn) if tp + fn else float("nan")


def fpr_of(c):
    fp, tn = c.get("fp", 0), c.get("tn", 0)
    return fp / (fp + tn) if fp + tn else float("nan")


CATEGORY_LABEL = {"mnpi": "mnpi (marked)", "mnpi_unmarked": "mnpi (unmarked)"}


def catlabel(c):
    return CATEGORY_LABEL.get(c, c)


def fmt(x):
    return "--" if x != x else f"{x:.3f}"


def markdown_tables(results, variants, categories, cov):
    L = []
    L.append("### Table A. Detection on unmodified input\n")
    L.append("| Detector | Recall, unmodified input | Field-hit (PII+acct) | "
             "Complete-field (PII+acct) | ms/prompt |")
    L.append("|---|---|---|---|---|")
    for r in results:
        sp = r["per_cat_none"].get("_span", {})
        fu = r["per_cat_none"].get("_spanfull", {})
        st, sf = sp.get("tp", 0), sp.get("fn", 0)
        ft, ff = fu.get("tp", 0), fu.get("fn", 0)
        L.append(f"| {r['detector']} | {fmt(cond_recall(r, ['none']))} | "
                 f"{fmt(st / (st + sf) if st + sf else float('nan'))} | "
                 f"{fmt(ft / (ft + ff) if ft + ff else float('nan'))} | "
                 f"{r['ms_per_prompt']:.2f} |")
    L.append("\n*Field-hit counts a gold field as covered if any predicted span "
             "overlaps it; complete-field requires every character to be "
             "covered, which is what redaction needs. The two can order "
             "detectors differently.*")
    L.append("")
    L.append("Recall with no evasion, 95% template-clustered bootstrap interval "
             "(2000 draws). The seventeen templates were written by us, not "
             "sampled from any population, so this quantifies sensitivity to "
             "our template choice -- it is not a coverage interval for real "
             "financial prompts. Presidio's [1.000, 1.000] means every template "
             "we wrote was flagged, not that flagging is certain:")
    for r in results:
        pt, lo, hi = r["none_recall_ci"]
        L.append(f"- {r['detector']}: {pt:.3f} [{lo:.3f}, {hi:.3f}]")
    L.append("\n*No recall pooled over transforms is reported: any such average "
             "would be weighted by a transform mix we chose; per-transform "
             "results are in Table B. Field coverage is which annotated entity "
             "fields a detection overlapped -- for MNPI it is not a redaction "
             "measure. Precision and F1 are omitted for the same kind of reason "
             "-- they are prevalence-dependent and our prevalence is a design "
             "choice. False positives "
             "are in Table D.*")

    L.append("\n### Table B. Recall by evasion variant\n")
    L.append("| Evasion | Cov. | " + " | ".join(
        f"{r['detector']} | fc" for r in results) + " |")
    L.append("|---" * (2 * len(results) + 2) + "|")
    for v in variants:
        row = []
        for r in results:
            sp = r["per_variant_span"].get(v, {})
            tp, fn = sp.get("tp", 0), sp.get("fn", 0)
            row.append(fmt(recall_of(r["per_variant"].get(v, {}))))
            row.append(fmt(tp / (tp + fn) if tp + fn else float("nan")))
        mark = " (H)" if v in HELD_OUT else ""
        L.append(f"| {v}{mark} | {fmt(cov.get(v, float('nan')))} | " + " | ".join(row) + " |")
    L.append("\n*(H) = held out: added after the detectors were written, with no detector logic changed. `fc` = annotated-field coverage: which entity fields a detection overlapped, as opposed to merely firing on the prompt. For MNPI this is not a redaction measure.*")
    L.append("\n*Cov. is the fraction of gold spans the transform actually "
             "alters. Four transforms are partial -- `homoglyph`, "
             "`strip_format`, `spelled`, `mathbold` -- so an untouched span in "
             "the same prompt can still trigger a detection and their recall "
             "overstates robustness.*")

    L.append("\n### Table C1. Recall by leak category, NO EVASION APPLIED\n")
    L.append("| Category | Tpl. | " + " | ".join(r["detector"] for r in results) + " |")
    L.append("|---" * (len(results) + 2) + "|")
    for c in categories:
        if c == "benign":
            continue
        row = [fmt(recall_of(r["per_cat_none"].get(c, {}))) for r in results]
        L.append(f"| {catlabel(c)} | {TEMPLATE_COUNTS.get(c, 0)} | " + " | ".join(row) + " |")
        if c == "mnpi_unmarked":
            row = [fmt(recall_of(merged_mnpi(r["per_cat_none"]))) for r in results]
            L.append(f"| **mnpi (all)** | {sum(TEMPLATE_COUNTS.get(k, 0) for k in MNPI_CLASSES)} | "
                     + " | ".join(row) + " |")
    L.append("\n*No adversary at all. These figures are not confounded with the "
             "evasion transforms, so they are free of transform-specific "
             "co-design -- though the templates and detectors were still written "
             "by the same authors. Cite THIS table, not C2, for category "
             "blindness. Note D0 vs mnpi_unmarked: the keyword baseline tracks "
             "confidentiality boilerplate, not sensitivity.*")

    L.append("\n### Table C2. Recall by leak category, pooled over all variants\n")
    L.append("| Category | Tpl. | " + " | ".join(r["detector"] for r in results) + " |")
    L.append("|---" * (len(results) + 2) + "|")
    for c in categories:
        if c == "benign":
            continue
        row = [fmt(recall_of(r["per_category"].get(c, {}))) for r in results]
        L.append(f"| {catlabel(c)} | {TEMPLATE_COUNTS.get(c, 0)} | " + " | ".join(row) + " |")
    L.append("\n*Tpl. is the number of distinct task templates behind the "
             "category. These figures characterize the task shapes modelled, "
             "not the category in general.*")

    L.append("\n### Table E. Unannounced/announced pairs (n=18, identical fields)\n")
    L.append("| Detector | flags both | only unannounced | only announced | "
             "neither | scenarios correct |")
    L.append("|---|---|---|---|---|---|")
    for r in results:
        pa = r.get("paired")
        if not pa:
            continue
        L.append(f"| {r['detector']} | {pa['both']} | {pa['only_unannounced']} | "
                 f"{pa['only_announced']} | {pa['neither']} | "
                 f"{pa['scenarios_correct']}/{pa['scenarios']} |")
    L.append("\n*Only `only unannounced` is the desired decision. Pairs share "
             "identical entity payloads and differ in a short disclosure-status "
             "phrase. The eighteen pairs are six instantiations of each of three "
             "scenarios, so the last column -- scenarios on which every "
             "instantiation was decided correctly -- is the unit of evidence. "
             "No significance test is reported: instantiations within a scenario "
             "are not independent.*")

    L.append("\n### Table D. False positives, by negative stratum\n")
    L.append("| Detector | clean | near-miss | paired-public |")
    L.append("|---|---|---|---|")
    for r in results:
        cells = []
        for st in ("clean", "near_miss", "paired_public"):
            d = r["per_stratum"].get(st, {})
            n = d.get("fp", 0) + d.get("tn", 0)
            cells.append(f"{d.get('fp', 0)}/{n}")
        L.append(f"| {r['detector']} | " + " | ".join(cells) + " |")
    L.append("\n*paired-public prompts restate the unmarked MNPI prompts as "
             "announced events, with identical entity payloads. No identifier "
             "separates them; one of the three disclosure phrasings does "
             "coincide with a term on D0's list, which Table E reports.*")
    return "\n".join(L)


def _tex(s):
    return s.replace("_", r"\_")


def _wrap(caption, label, cols, header, rows, wide=False):
    # `wide=True` emits a `table*`, which spans both IEEEtran columns.
    # Tables with more than ~5 columns overflow a single 3.5in column and
    # visually collide with the adjacent column's text -- use `wide` for any
    # table with 6+ columns (label included).
    # Single-column tables get the IEEE sample's [htbp] for placement
    # flexibility (matches the official IEEE conference template); a
    # `table*` spans both columns and can only float to the top/bottom of a
    # page, so it keeps the narrower [t].
    env = "table*" if wide else "table"
    placement = "t" if wide else "htbp"
    L = [rf"\begin{{{env}}}[{placement}]", r"\centering", r"\footnotesize",
         rf"\caption{{{caption}}}",
         rf"\label{{{label}}}", rf"\begin{{tabular}}{{{cols}}}", r"\hline",
         " & ".join(header) + r" \\ \hline"]
    L += [" & ".join(r) + r" \\" for r in rows]
    L += [r"\hline", r"\end{tabular}", rf"\end{{{env}}}"]
    return "\n".join(L)


TEMPLATE_COUNTS = {}


def count_templates(records):
    seen = collections.defaultdict(set)
    for r in records:
        if r["label"] == 1:
            seen[r["category"]].add(r["template"])
    return {k: len(v) for k, v in seen.items()}


def latex_tables(results, variants, cov):
    out = []

    rows = []
    for r in results:
        sp = r["per_cat_none"].get("_span", {})
        st, sf = sp.get("tp", 0), sp.get("fn", 0)
        fu = r["per_cat_none"].get("_spanfull", {})
        ft, ff = fu.get("tp", 0), fu.get("fn", 0)
        rows.append([_tex(r["detector"]), fmt(cond_recall(r, ["none"])),
                     fmt(st / (st + sf) if st + sf else float("nan")),
                     fmt(ft / (ft + ff) if ft + ff else float("nan")),
                     f"{r['ms_per_prompt']:.2f}"])
    out.append(_wrap(
        "Prompt-level detection on unmodified input. Field coverage is reported "
        "for PII and account data only, where the sensitive content is the "
        "annotated field and coverage therefore measures redaction; for MNPI "
        "and strategy the disclosive element is the unannounced proposition, "
        "which no single field carries, so per-class field results are left to "
        "the artifact. Field-hit counts any overlap with a gold field; complete "
        "requires every character of it, which is what redaction needs. No recall pooled over transforms is "
        "reported -- any such average would be weighted by a transform mix we "
        "chose -- so per-transform results are in Table~\\ref{tab:evasion}. "
        "Precision and F1 are omitted because they are prevalence-dependent and "
        "our prevalence is a design choice. False positives: "
        "Table~\\ref{tab:fpr}.",
        "tab:overall", "lrrrr",
        ["Detector", "Recall", "Field-hit", "Complete", "ms/prompt"], rows))

    PAPER_ROWS = ["none", "zwsp", "spaced", "base64", "hex",
                  "base32", "urlencode", "dotted", "mathbold"]
    rows = []
    for v in [x for x in variants if x in PAPER_ROWS]:
        cells = [_tex(v) + (" (H)" if v in HELD_OUT else ""),
                 fmt(cov.get(v, float("nan")))]
        for r in results:
            cells.append(fmt(recall_of(r["per_variant"].get(v, {}))))
        rows.append(cells)
    out.append(_wrap(
        "Prompt-level recall by evasion transform, selected rows; the full "
        "thirteen-transform table with annotated-field coverage is in the "
        "artifact. (H) marks the four transforms added after the detectors were "
        "frozen. D1 reaches exactly zero recall under base32, base64, hex, "
        "percent-encoding and zero-width injection.",
        "tab:evasion", "lr" + "r" * len(results),
        ["Evasion", "Cov."] + [_tex(r["detector"]) for r in results], rows,
        wide=True))

    cats = [c for c in sorted(TEMPLATE_COUNTS) if c != "benign"]

    rows = []
    for c in cats:
        rows.append([_tex(catlabel(c)), str(TEMPLATE_COUNTS[c])]
                    + [fmt(recall_of(r["per_cat_none"].get(c, {}))) for r in results])
        if c == "mnpi_unmarked":
            rows.append(["\\textbf{mnpi (all)}",
                         str(sum(TEMPLATE_COUNTS.get(k, 0) for k in MNPI_CLASSES))]
                        + [fmt(recall_of(merged_mnpi(r["per_cat_none"])))
                           for r in results])
    out.append(_wrap(
        "Recall by leak category, no evasion applied. The marked and unmarked "
        "MNPI rows are subsets of one class, split by whether the prompt "
        "carries confidentiality boilerplate; the third is their union. Tpl.\\ "
        "is the number of task templates behind each row. This is the only "
        "category result not confounded with the evasion transforms, though "
        "templates and detectors share authorship. Account identifiers and PII "
        "have syntax a pattern can express; for MNPI and proprietary strategy "
        "the sensitivity is not definable by identifier syntax.",
        "tab:category", "lr" + "r" * len(results),
        ["Category", "Tpl."] + [_tex(r["detector"]) for r in results], rows,
        wide=True))

    # Table C2 (pooled over transforms) and the overall-recall column of
    # Table A are deliberately NOT emitted to LaTeX: both are weighted by an
    # arbitrary mix of transforms that we chose, so they are artifact material
    # rather than results. They remain in results.md.

    rows = []
    for r in results:
        cells = [_tex(r["detector"])]
        for st in ("clean", "near_miss", "paired_public"):
            d = r["per_stratum"].get(st, {})
            cells.append(f"{d.get('fp', 0)}/{d.get('fp', 0) + d.get('tn', 0)}")
        rows.append(cells)
    out.append(_wrap(
        "False positives by negative stratum, as counts. No pooled rate is "
        "given: it would depend on a stratum mix we chose. Paired-public "
        "prompts restate the unmarked MNPI prompts as announced events.",
        "tab:fpr", "lrrr",
        ["Detector", "clean", "near-miss", "paired-public"], rows))

    rows = [[_tex(r["detector"]), str(r["paired"]["both"]),
             str(r["paired"]["only_unannounced"]),
             str(r["paired"]["only_announced"]), str(r["paired"]["neither"]),
             f"{r['paired']['scenarios_correct']}/{r['paired']['scenarios']}"]
            for r in results if r.get("paired")]
    out.append(_wrap(
        "Eighteen pairs sharing entity payloads and differing in a short "
        "disclosure-status phrase. Only `only unann.' is the desired decision. "
        "The pairs are six instantiations of each of three scenarios, so "
        "`scen.' -- scenarios decided correctly throughout -- is the unit of "
        "evidence; no test is reported because instantiations within a scenario "
        "are not independent.",
        "tab:pairs", "lrrrrr",
        ["Detector", "both", "only unann.", "only ann.", "neither", "scen."],
        rows))

    return "\n\n".join(out)


def presidio_attribution(records, path):
    """Which Presidio entity types fire on MNPI, and on the public twins.

    Two anecdotes ("Basel" as a location) are weaker evidence than showing that
    the SAME entity types fire on the unannounced prompt and on its announced
    twin. That is the mechanism claim, and it is free to compute.
    """
    rows = {}
    for line in open(path):
        d = json.loads(line)
        if "_meta" not in d:
            rows[d["id"]] = d["spans"]
    DROP = {"PERSON", "DATE_TIME", "US_DRIVER_LICENSE"}
    out = {}
    for label, sel in (
            ("mnpi_all", lambda r: r["label"] == 1 and r["variant"] == "none"
             and r["category"] in ("mnpi", "mnpi_unmarked")),
            ("mnpi_unmarked", lambda r: r["category"] == "mnpi_unmarked"
             and r["variant"] == "none"),
            ("public_twins", lambda r: r.get("stratum") == "paired_public")):
        sub = [r for r in records if sel(r)]
        c = collections.Counter()
        for r in sub:
            for t in {x["type"] for x in rows.get(r["id"], [])}:
                c[t] += 1
        # Post-hoc ablation on the cached output: how much of the MNPI recall
        # survives if the three entity types above are withheld? This is a
        # mechanism analysis, not a proposed detector.
        kept = sum(1 for r in sub
                   if [x for x in rows.get(r["id"], []) if x["type"] not in DROP])
        out[label] = {"n": len(sub), "types": dict(c.most_common()),
                      "ablated_recall": f"{kept}/{len(sub)}"}
    return out


def write_macros(results, records, cov, path, d4_path=None):
    """Emit every figure the paper cites as a LaTeX macro.

    The paper must not contain hand-typed numbers. Each is defined here from
    the live results and used in main.tex as \\FigXxx, so regenerating the
    benchmark updates the prose automatically and a stale figure becomes an
    undefined-control-sequence error rather than a silent wrong claim.
    """
    # Explicit, readable names. LaTeX command names cannot contain digits, so
    # every component is mapped by hand rather than by character substitution --
    # a generated name nobody can predict is a name that gets mistyped.
    DET = {"D0_keyword": "Kw", "D1_pattern": "Rx", "D2_normalized": "Nrm",
           "D3_decoded": "Dec", "D1p_presidio": "Prs", "D4_opus5": "Sem"}
    VAR = {"base32": "Bthirtytwo", "base64": "Bsixtyfour", "hex": "Hex",
           "urlencode": "Url", "dotted": "Dot", "zwsp": "Zwsp",
           "spaced": "Spaced", "mathbold": "Mathbold", "homoglyph": "Homoglyph",
           "strip_format": "Strip", "spelled": "Spelled", "reversed": "Reversed",
           "fullwidth": "Fullwidth"}
    CAT = {"account": "Account", "pii": "Pii", "strategy": "Strategy",
           "mnpi": "MnpiMarked", "mnpi_unmarked": "MnpiUnmarked"}
    STR = {"clean": "Clean", "near_miss": "Near", "paired_public": "Paired"}
    PAIR = {"both": "Both", "neither": "Neither",
            "only_unannounced": "OnlyUnann", "only_announced": "OnlyAnn"}

    def esc(x):
        return DET.get(x) or VAR.get(x) or CAT.get(x) or STR.get(x) or PAIR.get(x)

    M = {}
    leak = [r for r in records if r["label"] == 1]
    M["CorpusTotal"] = f"{len(records):,}".replace(",", "{,}")
    M["CorpusLeak"] = f"{len(leak):,}".replace(",", "{,}")
    M["CorpusNeg"] = str(sum(1 for r in records if r["label"] == 0))
    M["CorpusBase"] = str(len({r["base_id"] for r in leak}))
    M["CorpusTemplates"] = str(len({r["template"] for r in leak}))
    M["CorpusPairs"] = str(sum(1 for r in records
                               if r.get("stratum") == "paired_public"))
    M["CorpusTransforms"] = str(len({r["variant"] for r in leak}) - 1)
    M["CorpusHeldOut"] = str(len(HELD_OUT))

    for r in results:
        d = esc(r["detector"])
        sp = r["per_cat_none"].get("_span", {})
        st, sf = sp.get("tp", 0), sp.get("fn", 0)
        M[f"{d}NoneRecall"] = fmt(cond_recall(r, ["none"]))
        M[f"{d}NoneFieldCov"] = fmt(st / (st + sf) if st + sf else float("nan"))
        fu = r["per_cat_none"].get("_spanfull", {})
        ft, ff = fu.get("tp", 0), fu.get("fn", 0)
        M[f"{d}NoneFieldFull"] = fmt(ft / (ft + ff) if ft + ff else float("nan"))
        M[f"{d}Ms"] = f"{r['ms_per_prompt']:.2f}"
        M[f"{d}MnpiAll"] = fmt(recall_of(merged_mnpi(r["per_cat_none"])))
        for c in CAT:
            M[f"{d}{esc(c)}"] = fmt(recall_of(r["per_cat_none"].get(c, {})))
        for v in VAR:
            M[f"{d}V{esc(v)}"] = fmt(recall_of(r["per_variant"].get(v, {})))
            fcv = r["per_variant_span"].get(v, {})
            x, y = fcv.get("tp", 0), fcv.get("fn", 0)
            M[f"{d}Fc{esc(v)}"] = fmt(x / (x + y) if x + y else float("nan"))
        for st_name in STR:
            x = r["per_stratum"].get(st_name, {})
            M[f"{d}FP{esc(st_name)}"] = str(x.get("fp", 0))
            M[f"{d}N{esc(st_name)}"] = str(x.get("fp", 0) + x.get("tn", 0))
        pa = r.get("paired", {})
        for k in PAIR:
            M[f"{d}Pair{esc(k)}"] = str(pa.get(k, 0))
        M[f"{d}PairScenOk"] = str(pa.get("scenarios_correct", 0))
        M[f"{d}PairScen"] = str(pa.get("scenarios", 0))
    att = write_macros.attribution
    if att:
        M["MnpiN"] = str(att["mnpi_all"]["n"])
        M["MnpiDate"] = str(att["mnpi_all"]["types"].get("DATE_TIME", 0))
        M["MnpiDl"] = str(att["mnpi_all"]["types"].get("US_DRIVER_LICENSE", 0))
        M["MnpiAblated"] = att["mnpi_all"]["ablated_recall"].replace("/", " of ")
    for v, c in cov.items():
        if esc(v):
            M[f"Cov{esc(v)}"] = f"{c:.2f}"

    if d4_path:
        # Refusal is a distinct outcome from a wrong answer: the safety
        # classifier declines before the model reads the prompt for content,
        # so it is tracked separately from recall rather than folded into it.
        answered, refused, unlocated = 0, 0, 0
        for line in open(d4_path):
            row = json.loads(line)
            if "_meta" in row:
                continue
            v = row.get("verdict", {})
            if isinstance(v, dict) and v.get("error") == "refusal":
                refused += 1
            else:
                answered += 1
                unlocated += row.get("unlocated", 0)
        total = answered + refused
        M["SemAnswered"] = str(answered)
        M["SemRefusals"] = str(refused)
        M["SemTotal"] = str(total)
        M["SemRefusalRate"] = fmt(refused / total) if total else "nan"
        M["SemUnlocated"] = str(unlocated)

    with open(path, "w") as fh:
        fh.write("% GENERATED by evaluate.py -- do not edit.\n")
        fh.write("% Every number the paper cites is defined here from live\n")
        fh.write("% results. Never hand-type a figure into main.tex.\n")
        for k in sorted(M):
            fh.write(f"\\newcommand{{\\Fig{k}}}{{{M[k]}}}\n")
    print(f"wrote {len(M)} figure macros to {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus.jsonl")
    ap.add_argument("--out", default="results")
    ap.add_argument("--presidio", default=None,
                    help="path to a cached presidio_detector.py run")
    ap.add_argument("--d4", default=None,
                    help="path to a cached llm_detector.py run, e.g. "
                         "cache/d4-claude-opus-5.jsonl")
    args = ap.parse_args()

    records = [json.loads(l) for l in open(args.corpus)]
    variants = sorted({r["variant"] for r in records},
                      key=lambda v: (v != "none", v))
    categories = sorted({r["category"] for r in records})

    tiers = [(n, as_pair(f), None) for n, f in DETECTORS.items()]
    sweep = []
    for path, label in ((args.presidio, "D1p_presidio"), (args.d4, "D4")):
        if path:
            short, fn, ms, meta = load_cached(path, records, label)
            tiers.append((label if label != "D4" else f"D4_{short}", fn, ms))
            if meta:
                print(f"{label} configuration: {json.dumps(meta)}")
            if label.startswith("D1p"):
                for th in (0.0, 0.35, 0.5, 0.85):
                    _, tfn, _, _ = load_cached(path, records, label, threshold=th)
                    rec_none = sum(tfn(r["prompt"])[0] for r in records
                                   if r["label"] == 1 and r["variant"] == "none")
                    den = sum(1 for r in records
                              if r["label"] == 1 and r["variant"] == "none")
                    fp_clean = sum(tfn(r["prompt"])[0] for r in records
                                   if r.get("stratum") == "clean")
                    pair_ok = paired_analysis(records, tfn)["only_unannounced"]
                    sweep.append((th, rec_none / den, fp_clean, pair_ok))

    is_pos_none = lambda rec: rec["label"] == 1 and rec["variant"] == "none"
    results = []
    for name, fn, ms in tiers:
        r = evaluate(records, name, fn, ms_override=ms)
        r["paired"] = paired_analysis(records, fn)
        r["none_recall_ci"] = boot_ci(records, fn, is_pos_none)
        results.append(r)

    cov = coverage(records)
    TEMPLATE_COUNTS.update(count_templates(records))
    md = markdown_tables(results, variants, categories, cov)
    if args.presidio:
        att = presidio_attribution(records, args.presidio)
        md += "\n\n### Presidio entity-type attribution\n\n"
        md += "| Entity type | MNPI (n=%d) | unmarked MNPI (n=%d) | public twins (n=%d) |\n" % (
            att["mnpi_all"]["n"], att["mnpi_unmarked"]["n"], att["public_twins"]["n"])
        md += "|---|---|---|---|\n"
        keys = sorted(set().union(*[a["types"] for a in att.values()]),
                      key=lambda k: -att["mnpi_all"]["types"].get(k, 0))
        for k in keys:
            md += "| %s | %d | %d | %d |\n" % (
                k, att["mnpi_all"]["types"].get(k, 0),
                att["mnpi_unmarked"]["types"].get(k, 0),
                att["public_twins"]["types"].get(k, 0))
        md += ("\n\nWithholding PERSON, DATE_TIME and US_DRIVER_LICENSE from the "
               "cached output leaves recall of %s on MNPI prompts and %s on the "
               "unannounced scenarios. This is a post-hoc ablation for mechanism "
               "attribution, not a proposed detector configuration.\n"
               % (att["mnpi_all"]["ablated_recall"],
                  att["mnpi_unmarked"]["ablated_recall"]))
        md += ("\n*Counts are prompts in which the type fired at least once. "
               "The unmarked MNPI column and the public-twin column are the "
               "same eighteen scenarios in their unannounced and announced "
               "forms.*")

    if sweep:
        md += ("\n\n### Presidio score-threshold sweep\n\n"
               "| threshold | recall (no evasion) | FP on 70 clean | pairs correct |\n"
               "|---|---|---|---|\n"
               + "\n".join(f"| {t:.2f} | {r:.3f} | {f} | {p}/18 |"
                            for t, r, f, p in sweep)
               + "\n\n*0.00 is Presidio's own default. No threshold trades the "
                 "false positives away without losing recall, and none produces "
                 "a correct pair decision.*")
    open(f"{args.out}.md", "w").write(md + "\n")
    open(f"{args.out}.tex", "w").write(latex_tables(results, variants, cov) + "\n")
    json.dump(results, open(f"{args.out}.json", "w"), indent=2)
    write_macros.attribution = (presidio_attribution(records, args.presidio)
                                if args.presidio else None)
    write_macros(results, records, cov, f"{args.out}-figures.tex", d4_path=args.d4)

    print(md)
    print(f"\nwrote {args.out}.md / {args.out}.tex / {args.out}.json")


if __name__ == "__main__":
    main()
