cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(connection LINK_LIBS socket openssl misc multiplexing broadcast)
