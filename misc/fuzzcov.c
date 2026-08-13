/* A no-op edge callback, so an instrumented framework links into binaries that
 * are not fuzzers (docs/http3/08-testing.md §5).
 *
 * -fsanitize-coverage=trace-pc makes every edge in the framework call
 * __sanitizer_cov_trace_pc(), and the framework is a shared library used by the
 * server and every handler module -- none of which define it. Weak, so the
 * fuzzing driver's own definition preempts this one: ELF looks the symbol up in
 * the executable first, and a strong definition there wins for calls made from
 * inside the library.
 *
 * Compiled only in a BUILD_FUZZERS build; an ordinary build has neither the
 * instrumentation nor this file. */

#ifdef CWFR_FUZZ_COVERAGE

void __sanitizer_cov_trace_pc(void);

/* no_sanitize_coverage for the same reason as the driver's definition: an
 * instrumented hook calls itself. */
__attribute__((weak, no_sanitize_coverage)) void __sanitizer_cov_trace_pc(void) {
}

#endif
