cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(smtp LINK_LIBS connection config misc taskmanager -lidn2 -lresolv)

cpdy_add_subdirs()
