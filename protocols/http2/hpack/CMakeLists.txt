cmake_minimum_required(VERSION 3.12.4)

# HPACK (RFC 7541): self-contained header compression for HTTP/2. Depends only
# on the C standard library, so it stays testable in isolation. The Huffman and
# static tables are generated from RFC 7541 by gen_tables.py.
cwfr_add_lib(hpack)
