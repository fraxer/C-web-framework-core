cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(moduleloader LINK_LIBS storage view protocols config misc redirect route domain server openssl mimetype thread database broadcast ${CMAKE_DL_LIBS})
