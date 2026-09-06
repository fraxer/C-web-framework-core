cmake_minimum_required(VERSION 3.12.4)

# `middlewares` (the application's archive) used to be listed here -- a core
# target naming an application target by hand, which pinned the whole framework
# to one application. The core needs nothing from it: middleware.c includes only
# middleware.h, and application middlewares reach the registry at runtime.
cwfr_add_lib(middleware LINK_LIBS protocols)
