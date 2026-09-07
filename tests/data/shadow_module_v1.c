/* One half of the pair the shadow-copy suite rebuilds in place. The two differ
 * only in what this returns, which is how the test tells which of them the
 * loader actually mapped. */
int shadow_test_version(void) { return 1; }
