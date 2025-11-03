#ifndef __WEBSOCKETSREQUEST__
#define __WEBSOCKETSREQUEST__

#include "route.h"
#include "connection_s.h"
#include "websocketscommon.h"
#include "json.h"
#include "request.h"
#include "file.h"

struct websocketsrequest;
struct websocketsparser;

typedef struct websockets_protocol {
    websockets_payload_t payload;
    int(*payload_parse)(struct websocketsparser* parser, char* data, size_t size);
    int(*get_resource)(connection_t* connection, struct websocketsrequest* request);
    void(*reset)(void*);
    void(*free)(void*);
} websockets_protocol_t;

typedef struct websocketsrequest {
    request_t base;
    websockets_datatype_e type;
    websockets_protocol_t* protocol;

    int can_reset;
    int fragmented;

    connection_t* connection;
} websocketsrequest_t;

websocketsrequest_t* websocketsrequest_create(connection_t* connection, websockets_protocol_t* protocol);
void websocketsrequest_reset(websocketsrequest_t*);
void websocketsrequest_reset_continue(websocketsrequest_t*);
void websocketsrequest_free(void* arg);

char* websocketsrequest_payload(websockets_protocol_t*);
file_content_t websocketsrequest_payload_file(websockets_protocol_t*);
json_doc_t* websocketsrequest_payload_json(websockets_protocol_t*);

void websockets_protocol_init_payload(websockets_protocol_t*);
int websockets_create_tmpfile(websockets_protocol_t*, const char*);

#endif
