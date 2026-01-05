#ifndef __TRANSLATION__
#define __TRANSLATION__

/**
 * Translate message by key.
 * @return Translated string (do not free)
 */
const char* tr(httpctx_t* ctx, const char* key);

/**
 * Translate message with placeholders.
 * Example: trf(ctx, "greeting", "name", username, "count", "5", NULL)
 * JSON: { "greeting": "Hello, {name}! You have {count} messages." }
 * @return Translated string (caller must free)
 */
char* trf(httpctx_t* ctx, const char* key, ...);

#endif