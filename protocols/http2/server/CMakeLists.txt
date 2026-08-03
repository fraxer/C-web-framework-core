cmake_minimum_required(VERSION 3.12.4)

# HTTP/2 server session (Phase 3): per-connection h2 read/write guards plus the
# terminal write filter, binding the frame layer + HPACK to the HTTP/1.1
# request/response dispatch. Reuses http_server_dispatch/__run_*_filters, which
# resolve inside the framework .so.
# websocketsparser is here for the RFC 8441 tunnel (h2ws.c, docs/http2/09): a
# tunnelled stream runs the WebSocket frame parser over DATA payloads.
cwfr_add_lib(h2server LINK_LIBS connection http route server multiplexing openssl hpack h2frame websocket_server_parsers websocket)
