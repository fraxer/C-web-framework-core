cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(protocols FORCE_C LINK_LIBS connection smtp smtp_client websocket websocket_server http http_server http_client openssl)

cpdy_add_subdirs()
