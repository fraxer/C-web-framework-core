cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(websocket LINK_LIBS connection middleware mimetype misc websocket_server websocket_server_parsers ZLIB::ZLIB)

cpdy_add_subdirs()
