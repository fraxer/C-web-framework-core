cmake_minimum_required(VERSION 3.12.4)

# HPACK (RFC 7541): header compression for HTTP/2. The Huffman codec and prefix
# integer live in misc/huffman (shared with QPACK, RFC 9204 §5); the Huffman
# table is generated into misc/huffman_table.h by gen_tables.py, and the HPACK
# static table (61 entries, HPACK-specific) is generated here.
cwfr_add_lib(hpack LINK_LIBS misc)
