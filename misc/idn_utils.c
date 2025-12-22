#include <idn2.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "idn_utils.h"

int idn_needs_conversion(const char* domain) {
    if (domain == NULL) return 0;

    for (const char* p = domain; *p; p++) {
        if ((unsigned char)*p > 127) return 1;
    }
    return 0;
}

char* idn_to_ascii(const char* domain) {
    if (domain == NULL) return NULL;

    // Fast path: if domain is already ASCII, just duplicate it
    if (!idn_needs_conversion(domain)) {
        char* result = malloc(strlen(domain) + 1);
        if (result == NULL) return NULL;
        strcpy(result, domain);
        return result;
    }

    // Convert to Punycode using libidn2
    char* output = NULL;
    int rc = idn2_to_ascii_8z(domain, &output, IDN2_NONTRANSITIONAL);

    if (rc != IDN2_OK) {
        log_error("IDN conversion failed for '%s': %s\n", domain, idn2_strerror(rc));
        if (output != NULL) idn2_free(output);
        return NULL;
    }

    // Convert libidn2 allocation to regular malloc (for consistency)
    char* result = malloc(strlen(output) + 1);
    if (result != NULL) {
        strcpy(result, output);
    }
    idn2_free(output);

    return result;
}
