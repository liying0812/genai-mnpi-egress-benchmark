"""Synthetic corpus of analyst prompts for evaluating sensitive-data egress
detection. ("Prompt leakage" is avoided deliberately: in the literature it means
extraction of the system prompt, which is the opposite direction of travel.)

Every sensitive value is generated, never real. Prompts are built from typed
segments so that ground-truth character offsets stay exact under any evasion
transform applied to the sensitive segments.

Usage:
    python3 corpus.py --out corpus.jsonl
"""

import argparse
import base64
import json
import random
import unicodedata

SEED = 20260918

# --------------------------------------------------------------------------
# Synthetic sensitive-value generators
# --------------------------------------------------------------------------

FIRST = ["Marcus", "Priya", "Devon", "Ingrid", "Tomas", "Rosalind", "Kwame",
         "Yuki", "Aleksandr", "Noor", "Beatriz", "Hollis"]
LAST = ["Okonjo", "Vasquez", "Lindqvist", "Ferrante", "Abadi", "Whitlock",
        "Nakamura", "Duarte", "Bergstrom", "Ashworth", "Cattaneo", "Rahimi"]
STREETS = ["Cedar Hollow Rd", "Windmere Ct", "Aldgate Ln", "Brookmill Ave",
           "Pennington Way", "Fairhaven Dr"]
CITIES = [("Scarsdale", "NY", "10583"), ("Winnetka", "IL", "60093"),
          ("Brookline", "MA", "02445"), ("Bellevue", "WA", "98004")]
DEAL_NAMES = ["PROJECT HALLIARD", "PROJECT KESTREL", "PROJECT VERMILION",
              "PROJECT ANTHRACITE", "PROJECT SABLEWOOD"]
TARGETS = ["Calderon Logistics Group", "Nordheim Specialty Chemicals",
           "Tessellate Medical Devices", "Ashgrove Regional Bancorp",
           "Pellucid Water Utilities"]
REGULATORS = ["the SEC Division of Enforcement", "FINRA Market Regulation",
              "the OCC examination team", "the state banking commissioner"]
COMMITTEES = ["Asset-Liability Committee", "New Product Approval Committee",
              "Model Risk Oversight Committee"]


def luhn_complete(prefix: str, rng: random.Random) -> str:
    """Return a Luhn-valid number: prefix plus filler plus check digit."""
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(15 - len(prefix)))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:          # position of the future check digit is 0
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def make_person(rng):
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def make_ssn(rng):
    # 900-999 is never issued by the SSA, so these cannot collide with a real SSN.
    return f"9{rng.randint(10, 99)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"


def make_card(rng):
    n = luhn_complete(rng.choice(["4539", "5425", "6011"]), rng)
    return f"{n[0:4]} {n[4:8]} {n[8:12]} {n[12:16]}"


def make_account(rng):
    return str(rng.randint(10**9, 10**10 - 1))


def make_iban(rng):
    return "GB" + f"{rng.randint(10, 99)}" + "BARC" + \
           "".join(str(rng.randint(0, 9)) for _ in range(14))


def make_email(rng, person):
    f, l = person.lower().split()
    return f"{f[0]}.{l}@{rng.choice(['mailbox', 'privatemail', 'inbox'])}.com"


def make_phone(rng):
    return f"({rng.randint(200, 989)}) {rng.randint(200, 999)}-{rng.randint(1000, 9999)}"


def make_dob(rng):
    return f"{rng.randint(1, 12):02d}/{rng.randint(1, 28):02d}/{rng.randint(1948, 1996)}"


def make_address(rng):
    city, st, zp = rng.choice(CITIES)
    return f"{rng.randint(10, 9999)} {rng.choice(STREETS)}, {city}, {st} {zp}"


def make_percent(rng):
    return f"{rng.randint(2, 44)}.{rng.randint(0, 9)}%"


MONEY_RANGES = {            # (low, high, cents) chosen to be plausible per use
    "per_share": (10, 250, True),
    "revenue": (40_000_000, 5_000_000_000, False),
    "raise": (25_000_000, 900_000_000, False),
    "var_limit": (500_000, 25_000_000, False),
    "retail": (1_200, 480_000, True),
    "notional": (100_000, 20_000_000, False),
}


def make_money(rng, kind="retail"):
    lo, hi, cents = MONEY_RANGES[kind]
    amt = rng.randint(lo, hi)
    return f"${amt:,}.{rng.randint(0, 99):02d}" if cents and rng.random() < .5 \
        else f"${amt:,}"


# --------------------------------------------------------------------------
# Evasion transforms (applied only to sensitive segments)
# --------------------------------------------------------------------------

DIGIT_WORDS = {"0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
               "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine"}
HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "c": "с",
             "p": "р", "x": "х", "A": "А", "E": "Е",
             "O": "О", "C": "С"}
ZWSP = "​"


def t_none(v, rng):
    return v


def t_strip_format(v, rng):
    """Remove the separators a pattern-matcher keys on: 912-34-5678 -> 912345678."""
    return v.replace("-", "").replace(" ", "").replace("(", "").replace(")", "")


def t_spaced(v, rng):
    return " ".join(v.replace("-", "").replace(" ", ""))


def t_spelled(v, rng):
    """Spell out digits only. Non-digits are left alone -- spacing every
    character would make this indistinguishable from t_spaced."""
    out, prev_digit = [], False
    for ch in v:
        if ch.isdigit():
            if prev_digit:
                out.append(" ")
            out.append(DIGIT_WORDS[ch])
            prev_digit = True
        else:
            out.append(ch)
            prev_digit = False
    return "".join(out)


def t_homoglyph(v, rng):
    return "".join(HOMOGLYPH.get(ch, ch) for ch in v)


def t_fullwidth(v, rng):
    return "".join(chr(ord(ch) + 0xFEE0) if "!" <= ch <= "~" else ch for ch in v)


def t_zwsp(v, rng):
    return ZWSP.join(v)


def t_base64(v, rng):
    return base64.b64encode(v.encode()).decode()


def t_hex(v, rng):
    return v.encode().hex()


def t_reversed(v, rng):
    return v[::-1]


# ---- Held-out transforms -------------------------------------------------
# D2 and D3 were written against the transforms above. These four were added
# afterwards and no detector logic was changed to accommodate them, so they
# measure generalization to evasions the detector was not built for, rather
# than coverage of evasions it already knows about.

def t_base32(v, rng):
    import base64 as _b
    return _b.b32encode(v.encode()).decode()


def t_urlencode(v, rng):
    return "".join(f"%{ord(c):02X}" for c in v)


def t_dotted(v, rng):
    """Period separators -- D2 collapses spaces and hyphens, not dots."""
    return ".".join(v.replace("-", "").replace(" ", ""))


def t_mathbold(v, rng):
    """Mathematical bold digits (U+1D7CE+). NFKC folds these, so this one
    tests whether normalization generalizes beyond the forms it targeted."""
    return "".join(chr(0x1D7CE + int(c)) if c.isdigit() else c for c in v)


TRANSFORMS = {
    "none": t_none,
    "strip_format": t_strip_format,
    "spaced": t_spaced,
    "spelled": t_spelled,
    "homoglyph": t_homoglyph,
    "fullwidth": t_fullwidth,
    "zwsp": t_zwsp,
    "base64": t_base64,
    "hex": t_hex,
    "reversed": t_reversed,
    # held-out: added after the detectors were written
    "base32": t_base32,
    "urlencode": t_urlencode,
    "dotted": t_dotted,
    "mathbold": t_mathbold,
}

HELD_OUT = {"base32", "urlencode", "dotted", "mathbold"}

# A wrapper the insider adds so the model still understands the obfuscated value.
DECODE_HINT = {
    "base64": "\n\n(The identifiers below are base64; decode them before use.)",
    "hex": "\n\n(The identifiers below are hex-encoded; decode them before use.)",
    "reversed": "\n\n(The identifiers below are written backwards.)",
    "spelled": "\n\n(Digits below are spelled out as words.)",
    "base32": "\n\n(The identifiers below are base32; decode them before use.)",
    "urlencode": "\n\n(The identifiers below are percent-encoded.)",
}

# --------------------------------------------------------------------------
# Prompt templates, as segment lists
# --------------------------------------------------------------------------
# A segment is ("lit", text) or ("sens", type, key). Keys resolve against a
# per-record field dict so the same value can appear more than once.


def counterparts():
    """Public twins of the unmarked MNPI templates.

    Each is rendered from the *same* field dictionary as its twin, so the two
    prompts name the same company, the same amount and the same people. They
    differ only in whether the event has already been announced. No
    confidentiality keyword separates them and no identifier does either: to
    tell them apart a detector must read disclosure status, not content.
    """
    C = {}

    C["earnings_unmarked"] = [
        ("lit", "Turn these Q3 numbers into three bullet talking points.\n\n"
                "Entity: "), ("sens", "TARGET", "target"),
        ("lit", "\nRevenue: "), ("sens", "MONEY", "revenue"),
        ("lit", "\nPrepared by: "), ("sens", "PERSON", "person"),
        ("lit", "\nPublicly released on November 3."),
    ]

    C["mna_unmarked"] = [
        ("lit", "Tighten the executive summary of this memo.\n\n"
                "Counterparty: "), ("sens", "TARGET", "target"),
        ("lit", "\nOffer: "), ("sens", "MONEY", "per_share"),
        ("lit", " per share; publicly announced on November 3.\nLead: "),
        ("sens", "PERSON", "person"),
    ]

    C["board_unmarked"] = [
        ("lit", "Condense these minutes into an action list.\n\n"
                "The board reviewed the restructuring of "),
        ("sens", "TARGET", "target"),
        ("lit", ", concluding that a workforce reduction of "),
        ("sens", "PERCENT", "percent"),
        ("lit", " will be required. "), ("sens", "PERSON", "person"),
        ("lit", " dissented. Filed in an 8-K."),
    ]
    return C


def templates():
    """Return (name, category, segments) for every leak-bearing template."""
    T = []

    T.append(("kyc_summary", "pii", [
        ("lit", "Summarize this KYC file for the quarterly review packet.\n\n"
                "Client: "), ("sens", "PERSON", "person"),
        ("lit", "\nDOB: "), ("sens", "DOB", "dob"),
        ("lit", "\nSSN: "), ("sens", "SSN", "ssn"),
        ("lit", "\nAddress: "), ("sens", "ADDRESS", "address"),
        ("lit", "\nContact: "), ("sens", "EMAIL", "email"),
        ("lit", " / "), ("sens", "PHONE", "phone"),
        ("lit", "\n\nKeep it under 150 words."),
    ]))

    T.append(("tax_return", "pii", [
        ("lit", "Extract total taxable income and deductions from this return.\n\n"
                "Taxpayer: "), ("sens", "PERSON", "person"),
        ("lit", "  SSN "), ("sens", "SSN", "ssn"),
        ("lit", "\nFiling address "), ("sens", "ADDRESS", "address"),
        ("lit", "\nSchedule D net gain "), ("sens", "MONEY", "money"),
        ("lit", "\n\nReturn a two-column table."),
    ]))

    T.append(("card_dispute", "account", [
        ("lit", "Draft a dispute response letter for this cardholder.\n\n"
                "Name: "), ("sens", "PERSON", "person"),
        ("lit", "\nCard: "), ("sens", "CARD", "card"),
        ("lit", "\nDisputed amount: "), ("sens", "MONEY", "money"),
        ("lit", "\nSettlement account: "), ("sens", "ACCOUNT", "account"),
        ("lit", "\n\nUse a formal tone."),
    ]))

    T.append(("wire_instruction", "account", [
        ("lit", "Check these wire instructions for formatting errors before I send them.\n\n"
                "Beneficiary: "), ("sens", "PERSON", "person"),
        ("lit", "\nIBAN: "), ("sens", "IBAN", "iban"),
        ("lit", "\nInternal settlement acct: "), ("sens", "ACCOUNT", "account"),
        ("lit", "\nAmount: "), ("sens", "MONEY", "money"),
    ]))

    T.append(("portfolio_review", "account", [
        ("lit", "Write a client-facing performance note from this position file.\n\n"
                "Household: "), ("sens", "PERSON", "person"),
        ("lit", " (acct "), ("sens", "ACCOUNT", "account"),
        ("lit", ")\nUnrealized gain: "), ("sens", "MONEY", "money"),
        ("lit", "\nContact on file: "), ("sens", "EMAIL", "email"),
        ("lit", "\n\nAvoid forward-looking statements."),
    ]))

    T.append(("mna_memo", "mnpi", [
        ("lit", "Tighten the executive summary of this deal memo.\n\n"
                "Codename: "), ("sens", "DEAL", "deal"),
        ("lit", "\nTarget: "), ("sens", "TARGET", "target"),
        ("lit", "\nIndicative offer: "), ("sens", "MONEY", "per_share"),
        ("lit", " per share, announcement scheduled pre-market Nov 3."
                "\nDeal team lead: "), ("sens", "PERSON", "person"),
        ("lit", "\n\nThis is not yet public."),
    ]))

    T.append(("earnings_preview", "mnpi", [
        ("lit", "Turn these unreleased Q3 numbers into three bullet talking points.\n\n"
                "Entity: "), ("sens", "TARGET", "target"),
        ("lit", "\nRevenue (unaudited, embargoed): "), ("sens", "MONEY", "revenue"),
        ("lit", "K\nPrepared by: "), ("sens", "PERSON", "person"),
        ("lit", " — do not circulate."),
    ]))

    # Two of the four MNPI templates below carry no identifier-shaped text at
    # all. That is realistic -- board minutes contain no account numbers -- and
    # it is the condition under which pattern matching has nothing to match on.

    T.append(("board_minutes", "mnpi", [
        ("lit", "Condense these draft board minutes into an action list.\n\n"
                "The board reviewed the proposed restructuring of "),
        ("sens", "TARGET", "target"),
        ("lit", ", concluding that a workforce reduction of "),
        ("sens", "PERCENT", "percent"),
        ("lit", " would be required before any announcement. "),
        ("sens", "PERSON", "person"),
        ("lit", " dissented. Minutes are unapproved and not for distribution."),
    ]))

    T.append(("reg_inquiry", "mnpi", [
        ("lit", "Rewrite this draft response to be more measured in tone.\n\n"
                "We have received a confidential inquiry from "),
        ("sens", "REGULATOR", "regulator"),
        ("lit", " concerning supervisory findings that have not been made "
                "public. Our position, prepared by "),
        ("sens", "PERSON", "person"),
        ("lit", ", is that the matter is remediated. Escalated to the "),
        ("sens", "COMMITTEE", "committee"),
        ("lit", "."),
    ]))

    T.append(("insider_list", "mnpi", [
        ("lit", "Format this restricted list as a table.\n\n"
                "Deal: "), ("sens", "DEAL", "deal"),
        ("lit", "\nPersons in possession of inside information:\n- "),
        ("sens", "PERSON", "person"),
        ("lit", " (deal lead)\n- "), ("sens", "PERSON2", "person2"),
        ("lit", " (counsel)\nSubject: "), ("sens", "TARGET", "target"),
        ("lit", "\n\nThis list is maintained under our insider-dealing policy."),
    ]))

    T.append(("underwriting_memo", "mnpi", [
        ("lit", "Summarize the risk factors in this underwriting memo.\n\n"
                "Issuer: "), ("sens", "TARGET", "target"),
        ("lit", "\nProposed raise: "), ("sens", "MONEY", "raise"),
        ("lit", ", pricing not yet filed.\nUnderwriting discount: "),
        ("sens", "PERCENT", "percent"),
        ("lit", "\nCommittee sponsor: "), ("sens", "PERSON", "person"),
    ]))

    # ---- Unmarked MNPI ---------------------------------------------------
    # The six templates above all carry explicit confidentiality boilerplate
    # ("not for distribution", "embargoed", "do not circulate"), which lets a
    # trivial keyword matcher score near-perfectly without any understanding of
    # the content. These three carry none. What makes them sensitive is a
    # temporal fact -- the event has not happened yet -- not a marker word.
    # Each has a paired public counterpart in the negative set that states the
    # same fact as already announced.

    T.append(("earnings_unmarked", "mnpi_unmarked", [
        ("lit", "Turn these Q3 numbers into three bullet talking points.\n\n"
                "Entity: "), ("sens", "TARGET", "target"),
        ("lit", "\nRevenue: "), ("sens", "MONEY", "revenue"),
        ("lit", "\nPrepared by: "), ("sens", "PERSON", "person"),
        ("lit", "\nScheduled for public release on November 3."),
    ]))

    T.append(("mna_unmarked", "mnpi_unmarked", [
        ("lit", "Tighten the executive summary of this memo.\n\n"
                "Counterparty: "), ("sens", "TARGET", "target"),
        ("lit", "\nOffer: "), ("sens", "MONEY", "per_share"),
        ("lit", " per share; announcement scheduled for November 3.\nLead: "),
        ("sens", "PERSON", "person"),
    ]))

    T.append(("board_unmarked", "mnpi_unmarked", [
        ("lit", "Condense these minutes into an action list.\n\n"
                "The board reviewed the restructuring of "),
        ("sens", "TARGET", "target"),
        ("lit", ", concluding that a workforce reduction of "),
        ("sens", "PERCENT", "percent"),
        ("lit", " will be required. "), ("sens", "PERSON", "person"),
        ("lit", " dissented. Not yet filed."),
    ]))

    T.append(("risk_limits", "strategy", [
        ("lit", "Turn this internal limit framework into a one-page summary.\n\n"
                "Desk VaR limit is set so that a single-day loss exceeding "),
        ("sens", "MONEY", "var_limit"),
        ("lit", " triggers escalation; the soft breach threshold sits at "),
        ("sens", "PERCENT", "percent"),
        ("lit", " of notional. Owner: "), ("sens", "PERSON", "person"),
        ("lit", ". Reviewed by the "), ("sens", "COMMITTEE", "committee"),
        ("lit", "."),
    ]))

    T.append(("client_flow", "strategy", [
        ("lit", "Draft talking points from this internal flow analysis.\n\n"
                "Our largest client by directed flow, "),
        ("sens", "TARGET", "target"),
        ("lit", ", accounts for "), ("sens", "PERCENT", "percent"),
        ("lit", " of desk volume. We internalize the remainder against the "
                "proprietary book. Relationship owner: "),
        ("sens", "PERSON", "person"),
        ("lit", "."),
    ]))

    T.append(("strategy_code", "strategy", [
        ("lit", "Explain what this internal signal does and suggest an optimization.\n\n"
                "Strategy owner: "), ("sens", "PERSON", "person"),
        ("lit", "\nProprietary alpha model: mean-reversion on order-book imbalance,\n"
                "threshold calibrated to our internal book, sized to "),
        ("sens", "MONEY", "notional"),
        ("lit", " notional per leg.\nDesk account: "), ("sens", "ACCOUNT", "account"),
    ]))

    return T


# --------------------------------------------------------------------------
# Benign prompts
# --------------------------------------------------------------------------
# Two strata. "clean" prompts contain no identifier-shaped text at all;
# "near_miss" prompts contain public or non-sensitive strings that look like
# regulated identifiers. Reporting FPR separately on the two strata keeps the
# headline false-positive rate from being an artifact of the mix we chose.

CLEAN_TEMPLATES = [
    "What is the difference between BCBS 239 and the Basel III {topic}?",
    "Summarize the SEC's published guidance on {rule} in plain language.",
    "Draft a 200-word explainer on how a {product} works for our client newsletter.",
    "What disclosures does FINRA Rule 2210 require in {channel} communications?",
    "Draft five interview questions for a junior {role} role.",
    "Explain {concept} to a new analyst without using jargon.",
    "Write a meeting agenda for a quarterly {committee} review.",
    "Compare {product} and {product2} for an internal training deck.",
    "Outline the steps in a standard {process} workflow.",
    "What are the main arguments for and against {debate}?",
]

NEAR_MISS_TEMPLATES = [
    "Invoice {luhn} is overdue -- draft a polite payment reminder.",
    "Order reference {ssnlike} shipped late; write an apology note to the vendor.",
    "Our public 10-K reports full-year revenue of {pubmoney}. Rewrite that line for a press release.",
    "{ticker} closed at ${px} on 2025-08-14 on volume of {vol} shares. Describe the move in one sentence.",
    "Our office is at {pubaddr} -- write a visitor direction blurb.",
    "Contact {pubemail} for the published release; draft the outreach email.",
    "Convert this ISO date list to US format: {isodates}.",
    "Reformat this published table: FY2023 {n1} / FY2024 {n2} / FY2025 {n3}.",
    "Support ticket {ticket} is unresolved; summarize the escalation policy.",
    "Decode this base64 string from our public build log and explain it: {b64log}",
    "This hex dump came from a published CVE advisory: {hexlog}. What does it decode to?",
    "Our API returns the token {b64tok} in the docs example -- explain the format.",
    "Our published CUSIP list includes {cusip}; explain what a CUSIP encodes.",
]

FILL = {
    "topic": ["leverage ratio", "liquidity coverage ratio", "capital buffer"],
    "rule": ["Regulation FD", "Regulation S-P", "Rule 10b5-1 plans"],
    "product": ["covered call", "interest-rate swap", "money market fund",
                "callable bond", "target-date fund"],
    "product2": ["a protective put", "a total return swap", "a Treasury ladder"],
    "channel": ["retail", "institutional", "social media"],
    "role": ["credit analyst", "compliance associate", "risk quant"],
    "concept": ["duration risk", "mark-to-market accounting", "netting",
                "the yield curve"],
    "committee": ["asset-liability", "model risk", "new product approval"],
    "process": ["client onboarding", "trade reconciliation", "model validation"],
    "debate": ["mandatory clawback provisions", "T+1 settlement",
               "open banking data sharing"],
}


def make_benign(rng, n_clean=70, n_near=50):
    out = []
    for i in range(n_clean):
        t = CLEAN_TEMPLATES[i % len(CLEAN_TEMPLATES)]
        txt = t
        for k, opts in FILL.items():
            txt = txt.replace("{" + k + "}", rng.choice(opts))
        out.append((txt, "clean"))

    for i in range(n_near):
        t = NEAR_MISS_TEMPLATES[i % len(NEAR_MISS_TEMPLATES)]
        city, st, zp = rng.choice(CITIES)
        vals = {
            "luhn": luhn_complete("4539", rng),
            "ssnlike": f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
            "pubmoney": f"${rng.randint(1, 9)},{rng.randint(100, 999)},000",
            "ticker": rng.choice(["AAPL", "MSFT", "JPM", "XOM"]),
            "px": f"{rng.randint(80, 400)}.{rng.randint(10, 99)}",
            "vol": f"{rng.randint(10, 80)},{rng.randint(100, 999)},{rng.randint(100, 999)}",
            "pubaddr": f"{rng.randint(100, 900)} Boylston St, Boston, MA 02116",
            "pubemail": rng.choice(["press@examplecorp.com", "ir@examplecorp.com"]),
            "isodates": ", ".join(f"{rng.randint(1985, 2005)}-{rng.randint(1, 12):02d}-"
                                  f"{rng.randint(1, 28):02d}" for _ in range(3)),
            "n1": f"{rng.randint(1, 9)},{rng.randint(100, 999)}",
            "n2": f"{rng.randint(1, 9)},{rng.randint(100, 999)}",
            "n3": f"{rng.randint(1, 9)},{rng.randint(100, 999)}",
            "ticket": f"INC{rng.randint(10**7, 10**8 - 1)}",
            "cusip": f"{rng.randint(100, 999)}{rng.choice('ABCDEFGH')}{rng.randint(10, 99)}AB{rng.randint(1, 9)}",
            "b64log": __import__("base64").b64encode(
                rng.choice([b"build ok: artifact cached",
                            b"deploy stage=canary region=us-east",
                            b"health probe returned 200"])).decode(),
            "hexlog": rng.choice([b"segfault at 0x7f", b"buffer overrun",
                                  b"null deref"]).hex(),
            "b64tok": __import__("base64").b64encode(
                b"example-public-token-v1").decode(),
        }
        txt = t
        for k, v in vals.items():
            txt = txt.replace("{" + k + "}", str(v))
        out.append((txt, "near_miss"))
    return out


def build(rng):
    records = []
    tmpls = templates()
    CPARTS = counterparts()

    for rep in range(6):                      # 6 instances per template
        for name, category, segs in tmpls:
            person = make_person(rng)
            fields = {
                "person": person,
                "dob": make_dob(rng),
                "ssn": make_ssn(rng),
                "address": make_address(rng),
                "email": make_email(rng, person),
                "phone": make_phone(rng),
                "card": make_card(rng),
                "account": make_account(rng),
                "iban": make_iban(rng),
                "money": make_money(rng, "retail"),
                "per_share": make_money(rng, "per_share"),
                "revenue": make_money(rng, "revenue"),
                "raise": make_money(rng, "raise"),
                "var_limit": make_money(rng, "var_limit"),
                "notional": make_money(rng, "notional"),
                "deal": rng.choice(DEAL_NAMES),
                "target": rng.choice(TARGETS),
                "person2": make_person(rng),
                "percent": make_percent(rng),
                "regulator": rng.choice(REGULATORS),
                "committee": rng.choice(COMMITTEES),
            }
            base_id = f"{name}-{rep:02d}"
            if name in CPARTS:
                # Public twin: identical fields, announced framing, label 0.
                ptext, _ = render(CPARTS[name], fields, t_none, rng)
                records.append({
                    "id": f"public-{base_id}",
                    "base_id": f"public-{base_id}",
                    "pair_id": base_id,
                    "template": f"public_{name}",
                    "category": "benign",
                    "variant": "none",
                    "stratum": "paired_public",
                    "near_miss": False,
                    "label": 0,
                    "prompt": ptext,
                    "spans": [],
                })
            for tname, fn in TRANSFORMS.items():
                text, spans = render(segs, fields, fn, rng)
                if tname in DECODE_HINT:
                    text += DECODE_HINT[tname]
                records.append({
                    "id": f"{base_id}/{tname}",
                    "base_id": base_id,
                    "template": name,
                    "category": category,
                    "variant": tname,
                    "pair_id": base_id if name in CPARTS else None,
                    "label": 1,
                    "prompt": text,
                    "spans": spans,
                })

    # Negatives are emitted once each -- duplicating them across the evasion
    # variants would inflate the FPR denominator without adding information.
    for i, (text, stratum) in enumerate(make_benign(rng)):
        records.append({
            "id": f"benign-{i:03d}",
            "base_id": f"benign-{i:03d}",
            "template": f"benign_{stratum}",
            "category": "benign",
            "variant": "none",
            "stratum": stratum,
            "near_miss": stratum == "near_miss",
            "label": 0,
            "prompt": text,
            "spans": [],
        })
    return records


def render(segs, fields, fn, rng):
    """Render segments, applying `fn` to sensitive values; return (text, spans)."""
    out, spans = [], []
    pos = 0
    for seg in segs:
        if seg[0] == "lit":
            out.append(seg[1])
            pos += len(seg[1])
        else:
            _, stype, key = seg
            raw = fields[key]
            shown = fn(raw, rng)
            spans.append({"start": pos, "end": pos + len(shown),
                          "type": stype, "raw": raw, "shown": shown})
            out.append(shown)
            pos += len(shown)
    return "".join(out), spans


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="corpus.jsonl")
    args = ap.parse_args()

    rng = random.Random(SEED)
    records = build(rng)
    with open(args.out, "w") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    pos = sum(r["label"] for r in records)
    print(f"wrote {len(records)} prompts to {args.out} "
          f"({pos} leak-bearing, {len(records) - pos} benign, "
          f"{len(TRANSFORMS)} variants)")


if __name__ == "__main__":
    main()
