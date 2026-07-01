cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(smtp_client LINK_LIBS connection config misc smtp_client_parsers -lidn2 -lresolv)

cwfr_add_subdirs()
