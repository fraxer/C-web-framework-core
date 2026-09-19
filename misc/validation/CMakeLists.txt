cmake_minimum_required(VERSION 3.12.4)

# String cleaning, form-field validation and output escaping. A separate
# archive inside misc/ rather than files next to json.c and utf8.c: the pairs
# here are one subject, and cwfr_add_lib globs a directory.
cwfr_add_lib(validation
	INCLUDE_DIRS . ${UNISTRING_INCLUDE_DIRS}
	LINK_LIBS misc ${UNISTRING_LIBRARIES})
