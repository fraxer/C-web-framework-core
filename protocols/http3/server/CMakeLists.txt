cmake_minimum_required(VERSION 3.12.4)

# HTTP/3 session-layer modules (docs/http3/05-http3.md §3, §5). One library for
# the directory: cwfr_add_lib globs every .c here, so the per-stream receive
# state machine (h3stream) and the uni-stream router (h3unistream) share a target
# and its include directory. h3session and the h3 write filter will land here too
# as phase 5 progresses.
#
# h3unistream needs h3frame (error codes) + quic_common (varint); h3stream needs
# h3frame, qpack, the shared http layer (httprequest/httpfields/h2field) and
# config (env()->main.client_max_body_size); h3session needs h3frame, qpack and
# quic_common, and deliberately not quic_transport -- it holds no connection.
# h3conn is the one module here that touches the transport: it reads QUIC
# streams and turns h3 verdicts into RESET_STREAM / STOP_SENDING, hence
# quic_transport. The others stay free of it on purpose.
cwfr_add_lib(h3server LINK_LIBS h3frame quic_common quic_transport qpack http config metrics)
