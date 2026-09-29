import re, zlib, sys
d = open(sys.argv[1], "rb").read()

def unescape(b):
    out, i = [], 0
    while i < len(b):
        c = b[i:i+1]
        if c == b"\\":
            nxt = b[i+1:i+2]
            if nxt in (b"(", b")", b"\\"):
                out.append(nxt); i += 2
            elif nxt.isdigit():
                m = re.match(rb"[0-7]{1,3}", b[i+1:i+4])
                out.append(bytes([int(m.group(), 8)])); i += 1 + len(m.group())
            elif nxt == b"n": out.append(b"\n"); i += 2
            else: i += 2
        else:
            out.append(c); i += 1
    return b"".join(out)

STR = re.compile(rb"\((?:\\.|[^\\()])*\)", re.S)
pages = []
for m in re.finditer(rb"stream\r?\n", d):
    raw = d[m.end():d.find(b"endstream", m.end())]
    try: c = zlib.decompress(raw)
    except Exception: continue
    if b"Tj" not in c and b"TJ" not in c:
        continue
    buf = []
    for tm in re.finditer(rb"\[((?:\((?:\\.|[^\\()])*\)|[^\[\]])*)\]\s*TJ|"
                          rb"(\((?:\\.|[^\\()])*\))\s*Tj|"
                          rb"(T\*|TD|Td)", c):
        if tm.group(3):
            buf.append("\n" if tm.group(3) in (b"T*", b"TD") else " ")
            continue
        arr = tm.group(1) if tm.group(1) is not None else tm.group(2)
        if tm.group(1) is not None:
            parts = re.split(rb"(\((?:\\.|[^\\()])*\))", arr)
            for p in parts:
                if p.startswith(b"("):
                    buf.append(unescape(p[1:-1]).decode("latin-1"))
                else:
                    for k in re.findall(rb"-?\d+", p):
                        if int(k) <= -120:
                            buf.append(" ")
        else:
            buf.append(unescape(arr[1:-1]).decode("latin-1"))
    pages.append("".join(buf))

txt = "\n".join(pages)
txt = txt.replace("ﬁ","fi").replace("ﬂ","fl").replace("ﬀ","ff")
txt = re.sub(r"[ \t]+", " ", txt)
txt = re.sub(r"\n{3,}", "\n\n", txt)
print(txt)
