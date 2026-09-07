/* Two SONAMEs where one is a tail of the other, so that a linker which merges
 * suffixes in .dynstr stores only the longer string -- the case elfsoname.c has
 * to refuse rather than overwrite. Built twice under different SONAMEs. */
const char* shadow_dep_name(void) { return SHADOW_DEP_NAME; }
