cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(multiplexing LINK_LIBS server socket connection protocols openssl misc)
