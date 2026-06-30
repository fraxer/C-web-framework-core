cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(server LINK_LIBS redirect route database domain openssl misc)
