cmake_minimum_required(VERSION 3.12.4)

# QUIC packet protection and the TLS bridge (RFC 9001) -- docs/http3/03-quic-tls.md.
#
# The one part of the QUIC stack that leans on OpenSSL: the TLS 1.3 handshake
# and the primitives come from the library, everything that turns a secret into
# a protected packet is here.
cwfr_add_lib(quic_crypto LINK_LIBS quic_common openssl misc)
