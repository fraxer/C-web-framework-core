#ifndef __QUICMEMORY__
#define __QUICMEMORY__

#include <stddef.h>

typedef void (*quicmemory_observer_fn)(size_t current, size_t limit,
                                       unsigned long long refused);

void quicmemory_configure(size_t limit, quicmemory_observer_fn observer);
int  quicmemory_reserve(size_t bytes);
void quicmemory_release(size_t bytes);
size_t quicmemory_current(void);
size_t quicmemory_limit(void);
unsigned long long quicmemory_refused(void);

#endif
