#ifndef __TRANSLATION__
#define __TRANSLATION__

/**
 * Translate message by msgid from specific domain.
 * @param ctx HTTP context (for language detection)
 * @param domain Translation domain (e.g., "identity")
 * @param msgid Message identifier
 * @return Translated string (do not free)
 */
const char* tr(httpctx_t* ctx, const char* domain, const char* msgid);

/**
 * Translate message with placeholders.
 * Example: trf(ctx, "identity", "greeting", "name", username, NULL)
 * @return Translated string (caller must free)
 */
char* trf(httpctx_t* ctx, const char* domain, const char* msgid, ...);

/**
 * Translate plural message.
 * Example: trn(ctx, "identity", "error", "errors", error_count)
 * @return Translated string (do not free)
 */
const char* trn(httpctx_t* ctx, const char* domain, const char* singular, const char* plural, unsigned long n);

/**
 * Translate plural message with placeholders.
 * Example: trnf(ctx, "identity", "{n} error", "{n} errors", count, "n", count_str, NULL)
 * @return Translated string (caller must free)
 */
char* trnf(httpctx_t* ctx, const char* domain, const char* singular, const char* plural, unsigned long n, ...);

#endif
