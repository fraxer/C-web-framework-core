cmake_minimum_required(VERSION 3.12.4)

# HTTP/2 frame layer (RFC 9113 §4/§6): resumable 9-byte-frame parser + encoder,
# connection preface handling. No connection state, no dependencies — stays
# unit-testable in isolation (consumed by the HTTP/2 connection layer later).
cwfr_add_lib(h2frame)
