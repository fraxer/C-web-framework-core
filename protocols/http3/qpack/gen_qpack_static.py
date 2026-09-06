#!/usr/bin/env python3
# Generates qpack_statictable.h verbatim from RFC 9204 Appendix A.
#
#   Source data: RFC 9204 (XML edition)
#     - Appendix A  QPACK Static Table (99 entries, 0-based)
#
#   Usage: python3 gen_qpack_static.py path/to/rfc9204.xml
#          curl -O https://www.rfc-editor.org/rfc/rfc9204.xml
#
# The XML edition and not the .txt one on purpose. The plain-text table wraps
# long cells across physical lines, and the wrap is not reversible by machine:
# `application/x-www-` + `form-urlencoded` joins with nothing between them while
# `max-age=31536000;` + `includesubdomains` joins with a space. A line-at-a-time
# reader silently keeps the first fragment and drops the rest -- ten of the 99
# entries came out truncated that way, and a truncated static entry is not a
# cosmetic defect: index 47 decoded `content-type` as `application/x-www-`,
# which changes how the request body is parsed. The XML carries each cell whole.
#
# A separate script from protocols/http2/hpack/gen_tables.py on purpose: that
# one parses RFC 7541 (HPACK's Huffman table + 61-entry static table). The QPACK
# static table is a different source (RFC 9204) -- 99 entries, 0-based, and the
# only generated artifact needed here. The generated header is committed; this
# script documents provenance and allows regeneration/re-verification.
import re
import sys
import xml.etree.ElementTree as ET


def cstr(s):
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    return '"' + s + '"'


def cell_text(td):
    """The cell's text with markup flattened and whitespace normalised."""
    return re.sub(r"\s+", " ", "".join(td.itertext())).strip()


def parse(rfc_path):
    root = ET.parse(rfc_path).getroot()

    # Appendix A is <section anchor="static-table">, and the only <table> in it
    # is the static table itself.
    section = None
    for s in root.iter("section"):
        if s.get("anchor") == "static-table":
            section = s
            break
    assert section is not None, "Appendix A (anchor=static-table) not found"

    tables = list(section.iter("table"))
    assert len(tables) == 1, "expected exactly one table in Appendix A"

    rows = []
    for tr in tables[0].iter("tr"):
        tds = tr.findall("td")
        if len(tds) != 3:
            continue  # the <th> heading row
        index, name, value = (cell_text(td) for td in tds)
        assert index.isdigit(), "non-numeric index %r" % index
        rows.append((int(index), name, value))

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
    out.append("/* The lengths are carried alongside the strings: the encoder scans all 99")
    out.append(" * entries for every header it writes, and strlen() on each one turned that")
    out.append(" * scan into the single largest item of the response profile. */")
    out.append("typedef struct {")
    out.append("    const char* name;")
    out.append("    size_t      name_len;")
    out.append("    const char* value;")
    out.append("    size_t      value_len;")
    out.append("} qpack_static_entry_t;")
    out.append("")
    out.append("/* 0-based: the (i+1)-th initializer is index i. */")
    out.append("static const qpack_static_entry_t")
    out.append("qpack_static_table[QPACK_STATIC_TABLE_SIZE] = {")
    for _, name, value in rows:
        out.append('    { %s, %d, %s, %d },' % (cstr(name), len(name), cstr(value), len(value)))
    out.append("};")
    out.append("")
    out.append("#endif")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_qpack_static.py path/to/rfc9204.xml")
    rows = parse(sys.argv[1])
    with open("qpack_statictable.h", "w") as f:
        f.write(emit(rows))
    print("generated qpack_statictable.h (%d entries)" % len(rows))


if __name__ == "__main__":
    main()
