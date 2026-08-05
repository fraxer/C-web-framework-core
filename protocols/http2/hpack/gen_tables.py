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
from fractions import Fraction

# Decoding-table entry flags (mirrored in hpack_huffman.h).
HUFF_SYM = 0x01     # the entry completed a symbol, emit entry.sym
HUFF_ACCEPT = 0x02  # the resulting state is a valid end of string
HUFF_FAIL = 0x04    # the nibble walked into EOS — invalid inside a string

EOS = 256


def build_decode_table(syms):
    """Nibble-driven DFA over the Huffman code tree.

    A state is a position in the code tree reached after a whole number of
    4-bit nibbles; the transition for one nibble walks four bits, emitting a
    symbol (and returning to the root) whenever it lands on a leaf.  At most one
    symbol can complete per nibble because the shortest code is 5 bits long,
    which is what keeps an entry down to a single `sym` field.

    Returns (table, states) where table[state][nibble] = (next, flags, sym).
    """
    leaves = {}    # (depth, value) -> symbol
    prefixes = set()
    for sym, code, length in syms:
        for d in range(1, length):
            prefixes.add((d, code >> (length - d)))
        leaves[(length, code)] = sym

    # A complete prefix code has every bit path ending on a leaf; the walk below
    # relies on that (it never has to handle a missing child).
    assert sum(Fraction(1, 2 ** l) for _, _, l in syms) == 1, "code is not complete"

    root = (0, 0)

    def step(node, bit):
        depth, value = node
        child = (depth + 1, (value << 1) | bit)
        if child in leaves:
            return True, leaves[child]
        assert child in prefixes, "no child for %s bit %d" % (node, bit)
        return False, child

    def accepting(node):
        # RFC 7541 5.2: padding is the most significant bits of EOS (all ones)
        # and strictly shorter than one octet.
        depth, value = node
        return depth <= 7 and value == (1 << depth) - 1

    states = [root]
    index = {root: 0}
    table = []
    i = 0
    while i < len(states):
        row = []
        for nibble in range(16):
            node = states[i]
            sym = None
            fail = False
            for shift in (3, 2, 1, 0):
                is_leaf, val = step(node, (nibble >> shift) & 1)
                if not is_leaf:
                    node = val
                    continue
                if val == EOS:
                    fail = True
                    break
                assert sym is None, "two symbols completed in one nibble"
                sym = val
                node = root
            if fail:
                # A discarded symbol here would make FAIL lose output the
                # bit-at-a-time decoder emits first. It cannot happen — EOS is
                # 30 bits, so no nibble can both complete a symbol and reach it
                # — and the assert keeps that true if the code table ever moves.
                assert sym is None, "nibble completed a symbol and then hit EOS"
                row.append((0, HUFF_FAIL, 0))
                continue
            if node not in index:
                index[node] = len(states)
                states.append(node)
            flags = (HUFF_SYM if sym is not None else 0)
            flags |= (HUFF_ACCEPT if accepting(node) else 0)
            row.append((index[node], flags, sym if sym is not None else 0))
        table.append(row)
        i += 1

    assert len(states) <= 256, "%d states will not fit in uint8_t" % len(states)

    return table, states


def emit_huffman(syms):
    # syms: list of (sym, code, length) for 0..256
    table, states = build_decode_table(syms)
    out = []
    out.append("/* Auto-generated from RFC 7541 Appendix B by gen_tables.py.")
    out.append(" * HPACK Huffman code table: 257 symbols (0..255 + EOS=256),")
    out.append(" * plus the nibble-driven decoding DFA derived from it.")
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
    out.append("/* ---- Decoding DFA ----")
    out.append(" * One state per position in the code tree reachable at a nibble boundary;")
    out.append(" * two lookups decode an octet. The bit-at-a-time alternative costs a scan")
    out.append(" * of all 256 symbols per bit, which is ~0.5 us per input byte and turns a")
    out.append(" * single large header block into hundreds of milliseconds of CPU.")
    out.append(" *")
    out.append(" * flags: SYM   — the entry completed `sym`, emit it;")
    out.append(" *        ACCEPT — the resulting state is a legal end of string (padding is")
    out.append(" *                 all ones and shorter than an octet, RFC 7541 5.2);")
    out.append(" *        FAIL  — the walk reached EOS, which may not appear in a string. */")
    out.append("#define HPACK_HUFF_SYM    0x01")
    out.append("#define HPACK_HUFF_ACCEPT 0x02")
    out.append("#define HPACK_HUFF_FAIL   0x04")
    out.append("")
    out.append("#define HPACK_HUFF_STATES %d" % len(states))
    out.append("")
    out.append("typedef struct {")
    out.append("    uint8_t state; /* next state */")
    out.append("    uint8_t flags;")
    out.append("    uint8_t sym;   /* valid when flags & HPACK_HUFF_SYM */")
    out.append("} hpack_huff_decode_t;")
    out.append("")
    out.append("static const hpack_huff_decode_t")
    out.append("hpack_huff_decode[HPACK_HUFF_STATES][16] = {")
    for st, row in enumerate(table):
        out.append("    /* %3d */ {" % st)
        for i in range(0, 16, 4):
            cells = ", ".join("{%3d, 0x%02x, %3d}" % cell for cell in row[i:i + 4])
            out.append("        " + cells + ",")
        out.append("    },")
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
