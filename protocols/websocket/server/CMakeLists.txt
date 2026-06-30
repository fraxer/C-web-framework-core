cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(websocket_server LINK_LIBS connection middleware websocket_server_parsers misc)

cpdy_add_subdirs()
