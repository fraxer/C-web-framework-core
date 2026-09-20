#ifndef __HTTPSTORAGE__
#define __HTTPSTORAGE__

#include "httprequest.h"
#include "httpresponse.h"

/* Ответ из S3-хранилища: HEAD за метаданными, затем тело нужного объёма.
 * Вызывается из рабочего потока отложенной очереди — синхронный запрос к S3
 * в event loop недопустим. */
void http_storage_respond(httprequest_t* request, httpresponse_t* response,
                          const char* storage_name, const char* path);

#endif
