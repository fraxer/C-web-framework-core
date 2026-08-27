#ifndef __DOTENV__
#define __DOTENV__

/**
 * Parser for .env files: one `key=value` pair per line.
 *
 * Accepted syntax: blank lines and lines starting with `#` are skipped, an
 * optional `export ` prefix is allowed, whitespace around the key and the value
 * is trimmed. A value in matching quotes is a string by definition (a `#` inside
 * it is not a comment); an unquoted value drops everything after ` #` as a
 * trailing comment.
 */

/**
 * Called for every parsed pair, in file order.
 *
 * key and value point into the buffer passed to dotenv_parse() and are only
 * valid while it runs. `quoted` is set when the value was taken into quotes,
 * so a caller doing type inference can keep it a string.
 *
 * @return 1 to continue, 0 to stop the parse
 */
typedef int (*dotenv_pair_fn)(const char* key, const char* value, int quoted, void* userdata);

/**
 * Reads a whole file into a malloc'd buffer.
 *
 * @param path  File path
 * @return Buffer, terminated with '\0' (free with free()), NULL on error --
 *         the error is already in the log when NULL is returned
 */
char* dotenv_load(const char* path);

/**
 * Parses `key=value` lines in place (the buffer is modified).
 *
 * A malformed line -- no '=' or an empty key -- is reported to the log with
 * its line number and skipped; parsing continues.
 *
 * @param data      Buffer from dotenv_load()
 * @param name      File name used in log messages (may be NULL)
 * @param fn        Per-pair callback, may be NULL to validate only
 * @param userdata  Passed through to the callback
 * @return Number of pairs delivered, -1 if the callback stopped the parse
 */
int dotenv_parse(char* data, const char* name, dotenv_pair_fn fn, void* userdata);

#endif
