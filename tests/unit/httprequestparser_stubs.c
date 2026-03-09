// Stub implementations for missing functions in HTTP parser tests
#include <stdlib.h>
#include <string.h>
#include "domain.h"
#include "connection.h"

// Stub for domains_free
void domains_free(domain_t* domain) {
    while (domain) {
        domain_t* next = domain->next;
        if (domain->template) free(domain->template);
        if (domain->prepared_template) free(domain->prepared_template);
        free(domain);
        domain = next;
    }
}

// Stub for connection_queue_item_create
void* connection_queue_item_create(void) {
    return NULL;
}

// Stub for connection_after_read
int connection_after_read(connection_t* conn) {
    (void)conn;
    return 0;
}

// Stub for connection_queue_append_broadcast
int connection_queue_append_broadcast(connection_t* conn) {
    (void)conn;
    return 0;
}
