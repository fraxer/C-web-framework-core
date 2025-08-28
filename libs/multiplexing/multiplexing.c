#include "multiplexing.h"
#include "multiplexingepoll.h"

mpxapi_t* mpx_create() {
    return mpx_epoll_init();
}

void mpx_free(mpxapi_t* api) {
    if (api == NULL) return;

    api->free(api);
}
