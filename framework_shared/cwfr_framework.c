/*
 * cwfr_framework.c — anchor translation unit for the cwfr_framework shared library.
 *
 * The framework code itself lives in the static archives (core/framework/*,
 * core/src/*, core/protocols/*, core/misc, common/*) and is pulled into this
 * shared library wholesale via `-Wl,--whole-archive` (see CMakeLists.txt). This
 * file only exists so the SHARED library has a source to anchor the link step.
 */

int cwfr_framework_version(void) {
	return 1;
}
