cmake_minimum_required(VERSION 3.12.4)

# HTTP/3 session-layer modules (docs/http3/05-http3.md §3, §5). This directory
# holds the per-connection state -- uni-stream routing now, then h3session,
# h3stream and the h3 write filter as the phase progresses. It is kept separate
# from frame/ because, unlike the frame codec, these modules carry (or will
# carry) connection state.
#
# h3unistream depends on h3frame only for the shared error codes in h3error.h,
# and on quic_common for the varint the stream-type prefix is encoded with.
cwfr_add_lib(h3unistream LINK_LIBS h3frame quic_common)
