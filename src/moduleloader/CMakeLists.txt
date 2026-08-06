cmake_minimum_required(VERSION 3.12.4)

cwfr_add_lib(moduleloader LINK_LIBS storage view protocols config misc redirect route domain server openssl mimetype thread database broadcast metrics ${CMAKE_DL_LIBS})

# quic_policy_init() is called from here, next to h2_policy_init(), so the QUIC
# policy and the shared connection table exist before any worker starts.
if(INCLUDE_HTTP3 STREQUAL yes)
	target_link_libraries(moduleloader udp)
endif()
