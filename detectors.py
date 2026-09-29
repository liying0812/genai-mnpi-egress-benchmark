"""Detector tiers for the prompt-leakage middleware experiment.

D1  pattern      regex only -- the naive DLP baseline
D2  normalized   Unicode-fold + zero-width strip + separator strip, then regex
D3  decoded      D2 plus a bounded decode pass (base64 / hex / reversed tokens)

Each detector takes the prompt text and returns a list of spans
{start, end, type} with offsets into the ORIGINAL text.
"""

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = "​‌‍⁠﻿"

# Cyrillic/Greek lookalikes. NFKD does not fold these -- they are distinct
# letters, not decorated Latin -- so they need an explicit map.
HOMOGLYPH_FOLD = str.maketrans({
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "һ": "h", "ј": "j", "ӏ": "l", "п": "n",
    "А": "A", "Е": "E", "О": "O", "С": "C", "Р": "P", "Х": "X", "У": "Y",
    "І": "I", "Ѕ": "S", "Н": "H", "К": "K", "М": "M", "Т": "T", "В": "B",
    "α": "a", "ο": "o", "ε": "e", "ρ": "p", "χ": "x", "ν": "v", "Ι": "I",
})

# --------------------------------------------------------------------------
# Patterns. Ordered; first match on a region wins.
# --------------------------------------------------------------------------

PATTERNS = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z]{4}\d{10,20}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("SSN", re.compile(r"\b9\d{8}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("PHONE", re.compile(r"\(\d{3}\)\s?\d{3}-\d{4}\b|\b\d{3}-\d{3}-\d{4}\b")),
    ("DOB", re.compile(r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d)/(?:19|20)\d{2}\b")),
    ("ACCOUNT", re.compile(r"\b\d{10}\b")),
    ("ADDRESS", re.compile(r"\b\d{1,5}\s+[A-Z][\w']*(?:\s+[A-Z][\w']*)*\s+"
                           r"(?:Rd|Ct|Ln|Ave|Way|Dr|St|Blvd)\b[^\n]{0,40}")),
    ("MONEY", re.compile(r"\$\d{1,3}(?:,\d{3})+(?:\.\d{2})?\b")),
    ("DEAL", re.compile(r"\bPROJECT\s+[A-Z]{4,}\b")),
]

# Types whose bare-number form is too ambiguous to claim without a separator.
LUHN_GATED = {"CARD"}


def luhn_ok(digits: str) -> bool:
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _scan(text, offset_map=None):
    """Run every pattern over `text`; map offsets back through `offset_map`."""
    hits = []
    for stype, pat in PATTERNS:
        for m in pat.finditer(text):
            if stype in LUHN_GATED:
                digits = re.sub(r"\D", "", m.group())
                if not luhn_ok(digits):
                    continue
            s, e = m.start(), m.end()
            if offset_map is not None:
                if s >= len(offset_map):
                    continue
                s = offset_map[s]
                e = offset_map[min(e, len(offset_map) - 1)]
            hits.append({"start": s, "end": e, "type": stype})
    return _dedupe(hits)


def _dedupe(hits):
    """Drop spans fully contained in an earlier, longer span of the same region."""
    hits.sort(key=lambda h: (h["start"], -(h["end"] - h["start"])))
    kept = []
    for h in hits:
        if any(k["start"] <= h["start"] and h["end"] <= k["end"] for k in kept):
            continue
        kept.append(h)
    return kept


# --------------------------------------------------------------------------
# D1 -- raw pattern matching
# --------------------------------------------------------------------------

def detect_pattern(text):
    return _scan(text)


# --------------------------------------------------------------------------
# D2 -- normalize, then pattern match
# --------------------------------------------------------------------------

DIGIT_WORDS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
               "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}


def normalize(text):
    """Fold the prompt and return (normalized, offset_map into original)."""
    # Pass 1: spelled-out digit runs collapse to digits.
    def unspell(m):
        return "".join(DIGIT_WORDS[w] for w in m.group().split())

    spelled = re.compile(r"\b(?:" + "|".join(DIGIT_WORDS) + r")(?:\s+(?:"
                         + "|".join(DIGIT_WORDS) + r")){2,}\b")
    stage, smap = [], []
    last = 0
    for m in spelled.finditer(text):
        for i in range(last, m.start()):
            stage.append(text[i]); smap.append(i)
        for ch in unspell(m):
            stage.append(ch); smap.append(m.start())
        last = m.end()
    for i in range(last, len(text)):
        stage.append(text[i]); smap.append(i)

    # Pass 2: NFKC (fullwidth -> ascii), drop zero-width, fold homoglyphs.
    out, omap = [], []
    for ch, oi in zip(stage, smap):
        if ch in ZERO_WIDTH:
            continue
        folded = unicodedata.normalize("NFKC", ch).translate(HOMOGLYPH_FOLD)
        folded = unicodedata.normalize(
            "NFKD", folded).encode("ascii", "ignore").decode() or folded
        for f in folded:
            out.append(f)
            omap.append(oi)
    omap.append(len(text))
    return "".join(out), omap


def _despace_digits(text, omap):
    """Collapse '9 1 2 3 4' and '912 34 5678' runs so separators stop hiding IDs."""
    out, nmap = [], []
    i = 0
    run = re.compile(r"\d(?:[ \-]?\d){6,}")
    last = 0
    for m in run.finditer(text):
        for k in range(last, m.start()):
            out.append(text[k]); nmap.append(omap[k])
        for k in range(m.start(), m.end()):
            if text[k].isdigit():
                out.append(text[k]); nmap.append(omap[k])
        last = m.end()
    for k in range(last, len(text)):
        out.append(text[k]); nmap.append(omap[k])
    nmap.append(omap[-1])
    return "".join(out), nmap


def detect_normalized(text):
    norm, omap = normalize(text)
    hits = _scan(norm, omap)
    tight, tmap = _despace_digits(norm, omap)
    hits += _scan(tight, tmap)
    return _dedupe(hits)


# --------------------------------------------------------------------------
# D3 -- normalize + bounded decode pass
# --------------------------------------------------------------------------

TOKEN = re.compile(r"[A-Za-z0-9+/=]{8,}")


def _candidate_decodings(tok):
    yield tok[::-1]
    try:
        if len(tok) % 2 == 0:
            yield binascii.unhexlify(tok).decode("ascii")
    except Exception:
        pass
    try:
        pad = tok + "=" * (-len(tok) % 4)
        yield base64.b64decode(pad, validate=True).decode("ascii")
    except Exception:
        pass


def detect_decoded(text):
    hits = detect_normalized(text)
    for m in TOKEN.finditer(text):
        tok = m.group()
        for cand in _candidate_decodings(tok):
            if not cand.isprintable():
                continue
            found = _scan(cand)
            if found:
                hits.append({"start": m.start(), "end": m.end(),
                             "type": found[0]["type"]})
                break
    return _dedupe(hits)


# --------------------------------------------------------------------------
# D0 -- confidentiality-keyword baseline
# --------------------------------------------------------------------------
# The cheapest thing a firm could deploy against MNPI: a word list. It is
# included because without it, "identifier regexes miss MNPI" is close to true
# by construction -- a reviewer would rightly ask whether a keyword list solves
# the problem. On MNPI prompts that carry explicit confidentiality boilerplate
# it very nearly does; the unmarked templates and the paired public negatives
# exist to show what it is actually tracking.

CONFIDENTIALITY_TERMS = [
    "confidential", "not for distribution", "not yet public", "do not circulate",
    "unapproved", "embargoed", "unaudited", "restricted list",
    "inside information", "insider-dealing", "material non-public",
    "internal only", "proprietary", "not yet filed", "not been made public",
    "do not distribute", "draft -- do not", "privileged",
]

_KW = re.compile("|".join(re.escape(t) for t in CONFIDENTIALITY_TERMS), re.I)


def detect_keyword(text):
    return [{"start": m.start(), "end": m.end(), "type": "CONFIDENTIALITY"}
            for m in _KW.finditer(text)]


DETECTORS = {
    "D0_keyword": detect_keyword,
    "D1_pattern": detect_pattern,
    "D2_normalized": detect_normalized,
    "D3_decoded": detect_decoded,
}
