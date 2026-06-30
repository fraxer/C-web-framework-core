cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(smtp_client LINK_LIBS connection config misc smtp_client_parsers -lidn2 -lresolv)

cpdy_add_subdirs()
