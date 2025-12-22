#ifndef __IDN_UTILS__
#define __IDN_UTILS__

/**
 * Convert internationalized domain name to ASCII/Punycode format
 * Returns: newly allocated string with Punycode domain, or NULL on error
 * Caller must free() the returned string
 */
char* idn_to_ascii(const char* domain);

/**
 * Check if domain contains non-ASCII characters
 * Returns: 1 if domain needs conversion, 0 if already ASCII
 */
int idn_needs_conversion(const char* domain);

#endif
