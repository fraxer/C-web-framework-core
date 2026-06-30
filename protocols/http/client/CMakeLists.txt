cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(http_client LINK_LIBS multiplexing redirect openssl misc http_client_parsers)

cpdy_add_subdirs()
