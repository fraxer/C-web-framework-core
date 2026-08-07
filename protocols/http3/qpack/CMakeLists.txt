cmake_minimum_required(VERSION 3.12.4)

# QPACK (RFC 9204) header compression for HTTP/3. The static table is generated
# from RFC 9204 Appendix A by gen_qpack_static.py; the Huffman codec and prefix
# integer come from misc/huffman (shared with HPACK, RFC 9204 §5).
cwfr_add_lib(qpack LINK_LIBS misc)
