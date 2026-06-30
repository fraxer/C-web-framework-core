cmake_minimum_required(VERSION 3.12.4)

cpdy_add_lib(storage INCLUDE_DIRS . ${LIBXML2_INCLUDE_DIR} LINK_LIBS http_client config misc ${LIBXML2_LIBRARIES})
