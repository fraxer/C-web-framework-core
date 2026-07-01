cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(smtp LINK_LIBS connection config misc taskmanager -lidn2 -lresolv)

cwfr_add_subdirs()
