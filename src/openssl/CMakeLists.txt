cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(openssl LINK_LIBS connection misc ${OPENSSL_LIBRARIES})
