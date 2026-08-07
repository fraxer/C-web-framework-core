#!/usr/bin/env python3
# Generates qpack_statictable.h verbatim from RFC 9204 Appendix A.
#
#   Source data: RFC 9204
#     - Appendix A  QPACK Static Table (99 entries, 0-based)
#
#   Usage: python3 gen_qpack_static.py path/to/rfc9204.txt
#
# A separate script from protocols/http2/hpack/gen_tables.py on purpose: that
# one parses RFC 7541 (HPACK's Huffman table + 61-entry static table). The QPACK
# static table is a different source (RFC 9204) -- 99 entries, 0-based, and the
# only generated artifact needed here. The generated header is committed; this
# script documents provenance and allows regeneration/re-verification.
import re
import sys


def cstr(s):
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    return '"' + s + '"'


def parse(rfc_path):
    txt = open(rfc_path, encoding="utf-8", errors="replace").read().splitlines()

    # The TOC lists "Appendix A.  Static Table" too; the real one is the last
    # occurrence (the body), followed by Appendix B.
    a_starts = [i for i, l in enumerate(txt) if l.strip() == "Appendix A.  Static Table"]
    assert a_starts, "Appendix A heading not found"
    a_start = a_starts[-1]
    b_start = next(i for i, l in enumerate(txt[a_start:], a_start)
                   if l.strip() == "Appendix B.  Encoding and Decoding Examples")

    # A data row: `| <index> | <name> | <value> |`. Separator (---) and header
    # (===) lines begin with `+`, the column-heading row spells "Index", so the
    # digit-anchored pattern below matches only data rows.
    row = re.compile(r"^\s*\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$")
    rows = []
    for l in txt[a_start:b_start]:
        m = row.match(l)
        if m:
            rows.append((int(m.group(1)), m.group(2).strip(), m.group(3).strip()))
    rows.sort()
    assert len(rows) == 99, "expected 99 static-table rows, got %d" % len(rows)
    assert [r[0] for r in rows] == list(range(99)), "static-table indices not 0..98"
    return rows


def emit(rows):
    out = []
    out.append("/* Auto-generated from RFC 9204 Appendix A by gen_qpack_static.py.")
    out.append(" * QPACK static table: 99 entries (0-based; index 0 is :authority).")
    out.append(" *")
    out.append(" * Unlike HPACK's table (RFC 7541 App. A), QPACK's is 0-based, which is why")
    out.append(" * a static index N refers directly to entry N below (no unused slot 0).")
    out.append(" * Do not edit by hand. */")
    out.append("#ifndef __QPACK_STATIC_TABLE__")
    out.append("#define __QPACK_STATIC_TABLE__")
    out.append("")
    out.append("#include <stddef.h>")
    out.append("")
    out.append("#define QPACK_STATIC_TABLE_SIZE 99  /* entries [0..98], 0-based */")
    out.append("")
    out.append("typedef struct {")
    out.append("    const char* name;")
    out.append("    const char* value;")
    out.append("} qpack_static_entry_t;")
    out.append("")
    out.append("/* 0-based: the (i+1)-th initializer is index i. */")
    out.append("static const qpack_static_entry_t")
    out.append("qpack_static_table[QPACK_STATIC_TABLE_SIZE] = {")
    for _, name, value in rows:
        out.append('    { %s, %s },' % (cstr(name), cstr(value)))
    out.append("};")
    out.append("")
    out.append("#endif")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_qpack_static.py path/to/rfc9204.txt")
    rows = parse(sys.argv[1])
    with open("qpack_statictable.h", "w") as f:
        f.write(emit(rows))
    print("generated qpack_statictable.h (%d entries)" % len(rows))


if __name__ == "__main__":
    main()
