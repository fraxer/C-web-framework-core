#!/usr/bin/env python3
# Generates hpack_huffman.h and hpack_statictable.h verbatim from RFC 7541.
#
#   Source data: RFC 7541
#     - Appendix A  Static Table Definition
#     - Appendix B  Huffman Code
#   Usage: python3 gen_tables.py path/to/rfc7541.txt
#
# The generated headers are committed; this script documents their provenance
# and lets the tables be regenerated / re-verified against the RFC.  Running it
# requires only the plain-text RFC (https://www.rfc-editor.org/rfc/rfc7541.txt).
import re
import sys


def emit_huffman(syms):
    # syms: list of (sym, code, length) for 0..256
    out = []
    out.append("/* Auto-generated from RFC 7541 Appendix B by gen_tables.py.")
    out.append(" * HPACK Huffman code table: 257 symbols (0..255 + EOS=256).")
    out.append(" * Do not edit by hand. */")
    out.append("#ifndef __HPACK_HUFFMAN_TABLE__")
    out.append("#define __HPACK_HUFFMAN_TABLE__")
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    out.append("#define HPACK_HUFF_EOS 256")
    out.append("")
    out.append("/* Huffman code value (MSB-aligned numeric value) per symbol. */")
    out.append("static const uint32_t hpack_huff_code[257] = {")
    for i in range(0, 257, 8):
        chunk = syms[i:i + 8]
        out.append("    " + ", ".join("0x%08x" % c for _, c, _ in chunk) + ",")
    out.append("};")
    out.append("")
    out.append("/* Code length in bits per symbol. */")
    out.append("static const uint8_t hpack_huff_len[257] = {")
    for i in range(0, 257, 16):
        chunk = syms[i:i + 16]
        out.append("    " + ", ".join("%2d" % l for _, _, l in chunk) + ",")
    out.append("};")
    out.append("")
    out.append("#endif")
    return "\n".join(out) + "\n"


def emit_static(rows):
    # rows: list of (index, name, value), 1..61
    out = []
    out.append("/* Auto-generated from RFC 7541 Appendix A by gen_tables.py.")
    out.append(" * HPACK static table: 61 entries (1-based; index 0 unused).")
    out.append(" * Do not edit by hand. */")
    out.append("#ifndef __HPACK_STATIC_TABLE__")
    out.append("#define __HPACK_STATIC_TABLE__")
    out.append("")
    out.append("#include <stddef.h>")
    out.append("#include <stdint.h>")
    out.append("")
    out.append("#define HPACK_STATIC_TABLE_SIZE 62 /* [0..61], 0 unused */")
    out.append("")
    out.append("typedef struct {")
    out.append("    const char* name;")
    out.append("    const char* value;")
    out.append("} hpack_static_entry_t;")
    out.append("")
    out.append("/* 1-based; index 0 is a dummy. */")
    out.append("static const hpack_static_entry_t hpack_static_table[HPACK_STATIC_TABLE_SIZE] = {")
    out.append("    { \"\", \"\" },")
    for _, name, value in rows:
        out.append('    { %s, %s },' % (cstr(name), cstr(value)))
    out.append("};")
    out.append("")
    out.append("#endif")
    return "\n".join(out) + "\n"


def cstr(s):
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    return '"' + s + '"'


def parse(rfc_path):
    txt = open(rfc_path, encoding="utf-8", errors="replace").read().splitlines()

    def line_starts(prefix):
        return [i for i, l in enumerate(txt) if l.startswith(prefix)]

    a_start = line_starts("Appendix A.  Static Table Definition")[0]
    b_start = line_starts("Appendix B.  Huffman Code")[0]
    c_start = line_starts("Appendix C.  Examples")[0]

    # --- Huffman (Appendix B) ---
    hrow = re.compile(r"^\s+.*?\(\s*(\d+)\s*\)\s*\|[\d|]+\s*([0-9a-f]+)\s*\[\s*(\d+)\s*\]")
    codes = {}
    for l in txt[b_start:c_start]:
        m = hrow.match(l)
        if m:
            codes[int(m.group(1))] = (int(m.group(2), 16), int(m.group(3)))
    assert len(codes) == 257, "expected 257 huffman symbols, got %d" % len(codes)
    for i in range(257):
        assert i in codes, "missing huffman symbol %d" % i
    syms = [(i, codes[i][0], codes[i][1]) for i in range(257)]

    # --- Static table (Appendix A) ---
    srow = re.compile(r"^\s*\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$")
    rows = []
    for l in txt[a_start:b_start]:
        m = srow.match(l)
        if m:
            rows.append((int(m.group(1)), m.group(2).strip(), m.group(3).strip()))
    rows.sort()
    assert len(rows) == 61, "expected 61 static-table rows, got %d" % len(rows)
    assert [r[0] for r in rows] == list(range(1, 62)), "static-table indices not 1..61"

    return syms, rows


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_tables.py path/to/rfc7541.txt")
    syms, rows = parse(sys.argv[1])
    with open("hpack_huffman.h", "w") as f:
        f.write(emit_huffman(syms))
    with open("hpack_statictable.h", "w") as f:
        f.write(emit_static(rows))
    print("generated hpack_huffman.h (%d syms) and hpack_statictable.h (%d rows)"
          % (len(syms), len(rows)))


if __name__ == "__main__":
    main()
