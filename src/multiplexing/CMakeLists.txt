cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(multiplexing LINK_LIBS server socket connection protocols openssl misc)

# The worker loop creates and drains QUIC endpoints alongside TCP listeners.
# Only for the include path -- every archive here is pulled whole into
# libcwfr_framework.so, so link order does not arise.
if(INCLUDE_HTTP3 STREQUAL yes)
	target_link_libraries(multiplexing udp)
endif()
