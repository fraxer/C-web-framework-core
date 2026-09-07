/* Needs both libraries of the suffix pair, and uses a symbol from each so that
 * --as-needed keeps both DT_NEEDED entries. */
const char* shadow_dep_name(void);
const char* shadow_dep_other_name(void);

const char* shadow_merged_names(void) {
    return shadow_dep_name()[0] == 0 ? shadow_dep_other_name() : shadow_dep_name();
}
