#include "numlocale.h"

/* Created when the library loads, before main() and before any thread, so
 * readers need no synchronization. */
static locale_t __numeric_locale = (locale_t)0;

__attribute__((constructor))
static void __numeric_locale_init(void) {
    __numeric_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
}

__attribute__((destructor))
static void __numeric_locale_free(void) {
    if (__numeric_locale != (locale_t)0)
        freelocale(__numeric_locale);

    __numeric_locale = (locale_t)0;
}

/**
 * The locale numbers in SQL, JSON and templates are read and written in: a
 * decimal point, whatever locale the application selected with setlocale().
 * Use it around printf/strtold for the current thread only:
 *
 *     const locale_t previous = uselocale(numeric_locale());
 *     ...
 *     uselocale(previous);
 *
 * @return The locale, or (locale_t)0 if it could not be created: uselocale()
 *         then leaves the current locale in place.
 */
locale_t numeric_locale(void) {
    return __numeric_locale;
}
