#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libgen.h>

#include "log.h"
#include "appconfig.h"
#include "base64.h"
#include "helpers.h"
#include "mimetype.h"
#include "storages3.h"
#include "httpclient.h"
#include "str.h"

static const char* EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

static void __free(void* storage);
static file_t __file_get(void* storage, const char* path);
static int __file_put(void* storage, const file_t* file, const char* path);
static int __file_content_put(void* storage, const file_content_t* file_content, const char* path);
static int __file_data_put(void* storage, const char* data, const size_t data_size, const char* path);
static int __file_remove(void* storage, const char* path);
static int __file_exist(void* storage, const char* path);
static storage_entry_e __entry_type(void* storage, const char* path);
static int __prefix_has_objects(storages3_t* storage, const char* prefix);
static array_t* __file_list(void* storage, const char* path);
static char* __create_uri(storages3_t* storage, const char* path_format, ...);
static char* __create_url(storages3_t* storage, const char* uri);
static char* __create_authtoken(storages3_t* storage, httpclient_t* client, const char* method, const char* date, const char* payload_hash);
static int __host_str(storages3_t* storage, char* string);
static void __create_amz_date(char* date_str, size_t date_size);
static void __create_short_date(char* short_date, size_t short_date_size);
static int __file_sha256(const int fd, unsigned char* hash);
static int __data_sha256(const char* data, const size_t data_size, unsigned char* hash);
static array_t* __parse_file_list_payload(const char* payload);
/* Живёт в storage.c и объявлена только там: storage.h раздаёт обёртки по
 * имени, а сюда нужен сам storage_t, чтобы проверить тип до запроса. */
storage_t* __storage_find(const char* storage_name);
static httpresponse_t* __request_object(storages3_t* s, const char* method_name, route_methods_e method,
                                        const char* path, const char* range, const char* if_none_match,
                                        const char* if_modified_since, httpclient_t** client_out);
static char* __header_copy(httpresponse_t* res, const char* key);
static char* __payload_take(httpresponse_t* res, size_t* size);

storages3_t* storage_create_s3(const char* storage_name, const char* access_id, const char* access_secret, const char* protocol, const char* host, const char* port, const char* bucket, const char* region) {
    storages3_t* storage = calloc(1, sizeof * storage);
    if (storage == NULL)
        return NULL;

    // Initialize all str_t fields
    str_init(&storage->access_id, 0);
    str_init(&storage->access_secret, 0);
    str_init(&storage->protocol, 0);
    str_init(&storage->host, 0);
    str_init(&storage->port, 0);
    str_init(&storage->bucket, 0);
    str_init(&storage->region, 0);

    storage->base.type = STORAGE_TYPE_S3;
    storage->base.next = NULL;
    strcpy(storage->base.name, storage_name);

    if (!str_assign(&storage->access_id, access_id, strlen(access_id)) ||
        !str_assign(&storage->access_secret, access_secret, strlen(access_secret)) ||
        !str_assign(&storage->protocol, protocol, strlen(protocol)) ||
        !str_assign(&storage->host, host, strlen(host)) ||
        !str_assign(&storage->port, port, strlen(port)) ||
        !str_assign(&storage->bucket, bucket, strlen(bucket)) ||
        !str_assign(&storage->region, region, strlen(region))) {
        __free(storage);
        return NULL;
    }

    storage->base.free = __free;
    storage->base.file_get = __file_get;
    storage->base.file_put = __file_put;
    storage->base.file_content_put = __file_content_put;
    storage->base.file_data_put = __file_data_put;
    storage->base.file_remove = __file_remove;
    storage->base.file_exist = __file_exist;
    storage->base.entry_type = __entry_type;
    storage->base.file_list = __file_list;

    return storage;
}

void __free(void* storage) {
    storages3_t* s = storage;
    if (s == NULL) return;

    str_clear(&s->access_id);
    str_clear(&s->access_secret);
    str_clear(&s->protocol);
    str_clear(&s->host);
    str_clear(&s->port);
    str_clear(&s->bucket);
    str_clear(&s->region);
    free(s);
}

file_t __file_get(void* storage, const char* path) {
    storages3_t* s = storage;
    file_t result = file_alloc();

    const char* method = "GET";
    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    httpclient_t* client = NULL;

    uri = __create_uri(s, "%s", path);
    if (uri == NULL) goto failed;

    url = __create_url(s, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_GET, url, timeout);
    if (client == NULL)
        goto failed;

    httprequest_t* req = client->request;

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method, amz_date, EMPTY_PAYLOAD_HASH);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", EMPTY_PAYLOAD_HASH);
    req->add_header(req, "x-amz-date", amz_date);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code != 200)
        goto failed;

    file_content_t file_content = res->get_payload_file(res);
    if (!file_content.ok)
        goto failed;

    const char* filename = basename((char*)path);
    if (strcmp(filename, "/") == 0) goto failed;
    if (strcmp(filename, ".") == 0) goto failed;
    if (strcmp(filename, "..") == 0) goto failed;

    file_content.set_filename(&file_content, filename);

    result = file_content.make_tmpfile(&file_content, env()->main.tmp);

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);

    return result;
}

int __file_put(void* storage, const file_t* file, const char* path) {
    if (storage == NULL) return 0;
    if (file == NULL) return 0;
    if (path == NULL) return 0;

    file_content_t file_content = file_content_create(file->fd, file->name, 0, file->size);

    return __file_content_put(storage, &file_content, path);
}

int __file_content_put(void* storage, const file_content_t* file_content, const char* path) {
    storages3_t* s = storage;
    int result = 0;

    const char* method = "PUT";
    const char* ext = file_extension(file_content->filename);
    const char* mimetype = mimetype_find_type(appconfig()->mimetype, ext);
    if (mimetype == NULL)
        mimetype = "text/plain";

    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    httpclient_t* client =  NULL;

    uri = __create_uri(s, "%s", path);
    if (uri == NULL) goto failed;

    url = __create_url(s, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_PUT, url, timeout);
    if (client == NULL)
        goto failed;

    httprequest_t* req = client->request;

    unsigned char file_content_hash[SHA256_DIGEST_LENGTH];
    char payload_hash[SHA256_DIGEST_LENGTH * 2 + 1];

    if (!__file_sha256(file_content->fd, file_content_hash))
        goto failed;

    bytes_to_hex(file_content_hash, SHA256_DIGEST_LENGTH, payload_hash);

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method, amz_date, payload_hash);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", payload_hash);
    req->add_header(req, "x-amz-date", amz_date);

    char content_disposition[512];
    snprintf(content_disposition, sizeof(content_disposition), "attachment; filename=%s", file_content->filename);
    req->add_header(req, "Content-Disposition", content_disposition);
    req->add_header(req, "Content-Type", mimetype);

    char filesize[32];
    snprintf(filesize, sizeof(filesize), "%ld", file_content->size);
    req->add_header(req, "Content-Length", filesize);

    req->set_payload_file_content(req, file_content);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code >= 300)
        goto failed;

    result = 1;

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);

    return result;
}

int __file_data_put(void* storage, const char* data, const size_t data_size, const char* path) {
    storages3_t* s = storage;
    int result = 0;

    const char* method = "PUT";
    const char* ext = file_extension(path);
    const char* filename = basename((char*)path);
    const char* mimetype = mimetype_find_type(appconfig()->mimetype, ext);
    if (mimetype == NULL)
        mimetype = "text/plain";

    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    httpclient_t* client =  NULL;

    uri = __create_uri(s, "%s", path);
    if (uri == NULL) goto failed;

    url = __create_url(s, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_PUT, url, timeout);
    if (client == NULL)
        goto failed;

    httprequest_t* req = client->request;

    unsigned char content_hash[SHA256_DIGEST_LENGTH];
    char payload_hash[SHA256_DIGEST_LENGTH * 2 + 1];

    if (!__data_sha256(data, data_size, content_hash))
        goto failed;

    bytes_to_hex(content_hash, SHA256_DIGEST_LENGTH, payload_hash);

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method, amz_date, payload_hash);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", payload_hash);
    req->add_header(req, "x-amz-date", amz_date);

    char content_disposition[512];
    snprintf(content_disposition, sizeof(content_disposition), "attachment; filename=%s", filename);
    req->add_header(req, "Content-Disposition", content_disposition);
    req->add_header(req, "Content-Type", mimetype);

    char filesize[32];
    snprintf(filesize, sizeof(filesize), "%ld", data_size);
    req->add_header(req, "Content-Length", filesize);

    req->set_payload_raw(req, data, data_size, mimetype);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code >= 300)
        goto failed;

    result = 1;

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);

    return result;
}

int __file_remove(void* storage, const char* path) {
    storages3_t* s = storage;
    int result = 0;

    const char* method = "DELETE";
    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    httpclient_t* client =  NULL;

    uri = __create_uri(s, "%s", path);
    if (uri == NULL) goto failed;

    url = __create_url(s, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_DELETE, url, timeout);
    if (client == NULL)
        goto failed;

    httprequest_t* req = client->request;

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method, amz_date, EMPTY_PAYLOAD_HASH);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", EMPTY_PAYLOAD_HASH);
    req->add_header(req, "x-amz-date", amz_date);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code != 200)
        goto failed;

    result = 1;

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);

    return result;
}

int __file_exist(void* storage, const char* path) {
    storages3_t* s = storage;
    int result = 0;

    const char* method = "HEAD";
    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    httpclient_t* client = NULL;

    uri = __create_uri(s, "%s", path);
    if (uri == NULL) goto failed;

    url = __create_url(s, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_HEAD, url, timeout);
    if (client == NULL)
        goto failed;

    httprequest_t* req = client->request;

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method, amz_date, EMPTY_PAYLOAD_HASH);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", EMPTY_PAYLOAD_HASH);
    req->add_header(req, "x-amz-date", amz_date);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code != 200)
        goto failed;

    result = 1;

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);

    return result;
}

storage_entry_e __entry_type(void* storage, const char* path) {
    storages3_t* s = storage;
    if (s == NULL || path == NULL || path[0] == 0)
        return STORAGE_ENTRY_NONE;

    if (__file_exist(s, path))
        return STORAGE_ENTRY_FILE;

    // Каталогов в S3 нет: "dir" считается каталогом, если есть хотя бы один
    // ключ, начинающийся с "dir/" (включая маркер "dir/", который создают консоли)
    char prefix[PATH_MAX];
    size_t length = strlen(path);
    while (length > 0 && path[length - 1] == '/') length--;
    if (length == 0 || length + 1 >= sizeof(prefix))
        return STORAGE_ENTRY_NONE;

    memcpy(prefix, path, length);
    prefix[length] = '/';
    prefix[length + 1] = 0;

    return __prefix_has_objects(s, prefix) ? STORAGE_ENTRY_DIRECTORY : STORAGE_ENTRY_NONE;
}

// Есть ли в бакете хотя бы один ключ с этим префиксом. Без delimiter,
// чтобы найти и объекты во вложенных "каталогах"
int __prefix_has_objects(storages3_t* storage, const char* prefix) {
    const char* method = "GET";
    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    char* payload = NULL;
    httpclient_t* client = NULL;
    array_t* list = NULL;
    int result = 0;

    uri = __create_uri(storage, "?max-keys=1&prefix=%s", prefix);
    if (uri == NULL) goto failed;

    url = __create_url(storage, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_GET, url, timeout);
    if (client == NULL) goto failed;

    httprequest_t* req = client->request;

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(storage, client, method, amz_date, EMPTY_PAYLOAD_HASH);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", EMPTY_PAYLOAD_HASH);
    req->add_header(req, "x-amz-date", amz_date);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code != 200)
        goto failed;

    payload = res->get_payload(res);
    if (payload == NULL) goto failed;

    list = __parse_file_list_payload(payload);
    result = list != NULL && array_size(list) > 0;

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);
    if (payload != NULL) free(payload);
    if (list != NULL) array_free(list);

    return result;
}

array_t* __file_list(void* storage, const char* path) {
    storages3_t* s = storage;

    const char* method = "GET";
    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    char* payload = NULL;
    httpclient_t* client = NULL;
    array_t* list = NULL;

    uri = __create_uri(s, "?delimiter=/&max-keys=1000&prefix=%s", path);
    if (uri == NULL) goto failed;

    url = __create_url(s, uri);
    if (url == NULL) goto failed;

    const int timeout = 3;
    client = httpclient_init(ROUTE_GET, url, timeout);
    if (client == NULL) goto failed;

    httprequest_t* req = client->request;

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method, amz_date, EMPTY_PAYLOAD_HASH);
    if (authorization == NULL) goto failed;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", EMPTY_PAYLOAD_HASH);
    req->add_header(req, "x-amz-date", amz_date);

    httpresponse_t* res = client->send(client);
    if (!res)
        goto failed;
    if (res->status_code != 200)
        goto failed;

    payload = res->get_payload(res);

    list = __parse_file_list_payload(payload);

    failed:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);
    if (client != NULL) client->free(client);
    if (payload != NULL) free(payload);

    return list;
}

char* __create_uri(storages3_t* storage, const char* path_format, ...) {
    char path[PATH_MAX];
    va_list args;
    va_start(args, path_format);
    vsnprintf(path, sizeof(path), path_format, args);
    va_end(args);

    size_t uri_length = str_size(&storage->bucket) + strlen(path) + 2;
    char* uri = malloc(uri_length + 1);
    if (uri == NULL) return NULL;

    snprintf(uri, uri_length + 1, "/%s/%s", str_get(&storage->bucket), path);
    storage_merge_slash(uri);

    return uri;
}

char* __create_url(storages3_t* storage, const char* uri) {
    char port[8];
    memset(port, 0, 8);
    if (str_size(&storage->port) > 0)
        snprintf(port, sizeof(port), ":%s", str_get(&storage->port));

    const size_t url_length = str_size(&storage->protocol) + str_size(&storage->host) + strlen(port) + strlen(uri) + 3;
    char* url = malloc(url_length + 1);
    if (url == NULL) return NULL;

    snprintf(url, url_length + 1, "%s://%s%s%s", str_get(&storage->protocol), str_get(&storage->host), port, uri);

    return url;
}

int __host_str(storages3_t* storage, char* string) {
    if (storage == NULL || string == NULL)
        return 0;

    size_t host_len = str_size(&storage->host);
    size_t port_len = str_size(&storage->port);

    if (host_len + port_len > NAME_MAX - 2)
        return 0;

    const char* host_str = str_get(&storage->host);
    const char* port_str = str_get(&storage->port);

    if (host_str == NULL)
        return 0;

    strncpy(string, host_str, host_len);
    string[host_len] = '\0';

    if (port_len > 0 && strcmp(port_str, "443") != 0 && strcmp(port_str, "80") != 0) {
        size_t current_len = host_len;
        size_t remaining = NAME_MAX - current_len - 1;

        if (remaining < 2)  // Место для ":" + null terminator
            return 0;

        strncat(string, ":", remaining);
        current_len = strlen(string);
        remaining = NAME_MAX - current_len - 1;

        if (remaining < port_len)  // Место для port
            return 0;

        strncat(string, port_str, remaining);
    }

    return 1;
}

void __create_amz_date(char* date_str, size_t date_size) {
    time_t now = time(NULL);
    strftime(date_str, date_size, "%Y%m%dT%H%M%SZ", gmtime(&now));
}

void __create_short_date(char* short_date, size_t short_date_size) {
    time_t now = time(NULL);
    strftime(short_date, short_date_size, "%Y%m%d", gmtime(&now));
}

void calculate_signing_key(const char* secret_key, const char* short_date, const char *region, const char *service, unsigned char* signing_key) {
    unsigned char k_date[SHA256_DIGEST_LENGTH];
    unsigned char k_region[SHA256_DIGEST_LENGTH];
    unsigned char k_service[SHA256_DIGEST_LENGTH];
    unsigned char k_signing[SHA256_DIGEST_LENGTH];

    char _signing_key[264] = "AWS4";
    strncat(_signing_key, secret_key, sizeof(_signing_key) - strlen(_signing_key) - 1);

    HMAC(EVP_sha256(), 
         (unsigned char *)(_signing_key), 
         strlen(_signing_key), 
         (unsigned char *)short_date, 
         strlen(short_date), 
         (unsigned char *)k_date, NULL);
    
    // k_region
    HMAC(EVP_sha256(), 
         (unsigned char *)k_date, 
         SHA256_DIGEST_LENGTH, 
         (unsigned char *)region, 
         strlen(region), 
         (unsigned char *)k_region, NULL);
    
    // k_service
    HMAC(EVP_sha256(), 
         (unsigned char *)k_region, 
         SHA256_DIGEST_LENGTH, 
         (unsigned char *)service, 
         strlen(service), 
         (unsigned char *)k_service, NULL);
    
    // k_signing
    HMAC(EVP_sha256(), 
         (unsigned char *)k_service, 
         SHA256_DIGEST_LENGTH, 
         (unsigned char *)"aws4_request", 
         strlen("aws4_request"), 
         (unsigned char *)k_signing, NULL);
    
    memcpy(signing_key, k_signing, SHA256_DIGEST_LENGTH);
}

void calculate_signature(const unsigned char* signing_key,const char* string_to_sign,char* signature) {
    unsigned char signature_bytes[SHA256_DIGEST_LENGTH];
    
    HMAC(EVP_sha256(),
         signing_key,
         SHA256_DIGEST_LENGTH,
         (unsigned char*)string_to_sign,
         strlen(string_to_sign),
         signature_bytes, NULL);
    
    bytes_to_hex(signature_bytes, SHA256_DIGEST_LENGTH, signature);
}

char* __create_authtoken(storages3_t* storage, httpclient_t* client, const char* method, const char* date, const char* payload_hash) {
    char short_date[64];
    __create_short_date(short_date, sizeof(short_date));
    const char *region = str_get(&storage->region);
    const char *service = "s3";

    char host[NAME_MAX] = {0};
    if (!__host_str(storage, host)) return NULL;

    char canonical_headers[350];
    snprintf(canonical_headers, sizeof(canonical_headers), 
        "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
        host,
        payload_hash,
        date
    );

    const char *signed_headers = "host;x-amz-content-sha256;x-amz-date";
    httpclientparser_t* parser = client->parser;

    char* query_str = query_stringify(parser->query);

    char canonical_request[1024];
    snprintf(canonical_request, 1024, 
        "%s\n%s\n%s\n%s\n%s\n%s",
        method,
        parser->path,
        query_str != NULL ? query_str : "",
        canonical_headers,
        signed_headers,
        payload_hash
    );

    if (query_str != NULL)
        free(query_str);

    unsigned char canonical_request_hash[SHA256_DIGEST_LENGTH];
    char canonical_request_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256((unsigned char *)canonical_request, strlen(canonical_request), canonical_request_hash);
    bytes_to_hex(canonical_request_hash, SHA256_DIGEST_LENGTH, canonical_request_hash_hex);

    char string_to_sign[1024];
    snprintf(string_to_sign, 1024,
        "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
        date,
        short_date,
        region,
        service,
        canonical_request_hash_hex
    );

    unsigned char signing_key[SHA256_DIGEST_LENGTH];
    calculate_signing_key(
        str_get(&storage->access_secret),
        short_date,
        region,
        service,
        signing_key
    );

    char signature[SHA256_DIGEST_LENGTH * 2 + 1];
    calculate_signature(
        signing_key,
        string_to_sign,
        signature
    );

    char* authorization_header = malloc(512);
    if (authorization_header == NULL) return NULL;

    snprintf(authorization_header, 512,
        "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request,SignedHeaders=%s,Signature=%s",
        str_get(&storage->access_id),
        short_date,
        region,
        service,
        signed_headers,
        signature
    );

    return authorization_header;
}

int __file_sha256(const int fd, unsigned char* hash) {
    unsigned char buffer[4096];
    ssize_t bytes_read = 0;
    int result = 0;

    if (fd == -1) {
        log_error("__file_sha256: Error opening file fd %d: %s\n", fd, strerror(errno));
        goto failed;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        log_error("__file_sha256: EVP_MD_CTX_new failed\n");
        goto failed;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        log_error("__file_sha256: SHA256 initialization failed\n");
        EVP_MD_CTX_free(ctx);
        goto failed;
    }

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            log_error("__file_sha256: SHA256 update failed\n");
            EVP_MD_CTX_free(ctx);
            goto failed;
        }
    }

    if (bytes_read == -1) {
        log_error("__file_sha256: Error reading file fd %d: %s\n", fd, strerror(errno));
        EVP_MD_CTX_free(ctx);
        goto failed;
    }

    if (EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        log_error("__file_sha256: SHA256 finalization failed\n");
        EVP_MD_CTX_free(ctx);
        goto failed;
    }

    EVP_MD_CTX_free(ctx);
    result = 1;

    failed:

    lseek(fd, 0, SEEK_SET);

    return result;
}

int __data_sha256(const char* data, const size_t data_size, unsigned char* hash) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestUpdate(ctx, data, data_size) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

array_t* __parse_file_list_payload(const char* payload) {
    xmlDocPtr doc = xmlParseMemory(payload, strlen(payload));
    if (doc == NULL) {
        log_error("__parse_file_list_payload: Error xmlParseMemory\n");
        return NULL;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        log_error("__parse_file_list_payload: Error xmlDocGetRootElement\n");
        return NULL;
    }

    array_t* list = array_create();
    if (list == NULL) {
        log_error("__parse_file_list_payload: Error array_create\n");
        xmlFreeDoc(doc);
        return NULL;
    }

    xmlNodePtr node = root->children;
    while (node != NULL) {
        const char* name = (char*)node->name;

        if (strcmp(name, "Contents") == 0) {
            xmlNodePtr key_node = node->children;
            while (key_node != NULL) {
                const char* key_node_name = (char*)key_node->name;
                if (strcmp(key_node_name, "Key") == 0) {
                    xmlChar* key = xmlNodeGetContent(key_node);
                    array_push_back(list, array_create_string((char*)key));
                    xmlFree(key);
                }
                key_node = key_node->next;
            }
        }

        node = node->next;
    }

    xmlFreeDoc(doc);

    return list;
}

int storages3_range_format(char* out, size_t out_size, size_t start, size_t end) {
    if (out == NULL) return 0;
    if (end < start) return 0;

    const int written = snprintf(out, out_size, "bytes=%zu-%zu", start, end);

    return written > 0 && (size_t)written < out_size;
}

int storages3_content_range_parse(const char* value, size_t* start, size_t* end, size_t* total) {
    if (value == NULL || start == NULL || end == NULL || total == NULL) return 0;

    unsigned long long s = 0, e = 0, t = 0;
    if (sscanf(value, "bytes %llu-%llu/%llu", &s, &e, &t) != 3) return 0;
    if (e < s) return 0;

    *start = (size_t)s;
    *end = (size_t)e;
    *total = (size_t)t;

    return 1;
}

int storages3_http_status(int s3_status) {
    switch (s3_status) {
    case 200:
    case 206:
    case 304:
    case 404:
    case 416:
        return s3_status;
    case 403:
        // Креды сервера, а не права клиента на объект: клиенту тут нечего чинить
        return 502;
    case 0:
        // Таймаут или соединение не состоялось — параллель с FILE_UNAVAILABLE
        return 503;
    default:
        return 502;
    }
}

size_t storages3_chunk_size(size_t client_max_body_size) {
    if (client_max_body_size == 0) return STORAGES3_CHUNK_LIMIT;
    if (client_max_body_size < STORAGES3_CHUNK_LIMIT) return client_max_body_size;

    return STORAGES3_CHUNK_LIMIT;
}

/* Один подписанный запрос к объекту. `range` и условные заголовки идут
 * неподписанными, и SigV4 это разрешает: SignedHeaders у нас фиксирован
 * (host;x-amz-content-sha256;x-amz-date), а подписать заголовок, не объявив
 * его там, было бы как раз ошибкой.
 *
 * Возвращает ответ; владение клиентом переходит вызывающему через
 * *client_out, потому что тело ответа живёт в клиенте. NULL — запрос не
 * состоялся, клиент уже освобождён. */
httpresponse_t* __request_object(storages3_t* s, const char* method_name, route_methods_e method,
                                 const char* path, const char* range, const char* if_none_match,
                                 const char* if_modified_since, httpclient_t** client_out) {
    char* uri = NULL;
    char* url = NULL;
    char* authorization = NULL;
    httpclient_t* client = NULL;
    httpresponse_t* res = NULL;

    *client_out = NULL;

    uri = __create_uri(s, "%s", path);
    if (uri == NULL) goto done;

    url = __create_url(s, uri);
    if (url == NULL) goto done;

    client = httpclient_init(method, url, STORAGES3_TIMEOUT);
    if (client == NULL) goto done;

    httprequest_t* req = client->request;

    char amz_date[64];
    __create_amz_date(amz_date, sizeof(amz_date));
    authorization = __create_authtoken(s, client, method_name, amz_date, EMPTY_PAYLOAD_HASH);
    if (authorization == NULL) goto done;

    req->add_header(req, "Authorization", authorization);
    req->add_header(req, "x-amz-content-sha256", EMPTY_PAYLOAD_HASH);
    req->add_header(req, "x-amz-date", amz_date);

    if (range != NULL) req->add_header(req, "Range", range);
    if (if_none_match != NULL) req->add_header(req, "If-None-Match", if_none_match);
    if (if_modified_since != NULL) req->add_header(req, "If-Modified-Since", if_modified_since);

    res = client->send(client);

    done:

    if (uri != NULL) free(uri);
    if (url != NULL) free(url);
    if (authorization != NULL) free(authorization);

    if (res == NULL) {
        if (client != NULL) client->free(client);
        return NULL;
    }

    *client_out = client;

    return res;
}

char* __header_copy(httpresponse_t* res, const char* key) {
    http_header_t* header = res->get_header(res, key);
    if (header == NULL || header->value == NULL) return NULL;

    return strdup(header->value);
}

/* Тело ответа вместе с его длиной. get_payload сам знает, лежит оно в памяти
 * или в файле, а вот размер в этих двух случаях берётся из разных мест —
 * спрашивать strlen у бинарных данных нельзя. */
char* __payload_take(httpresponse_t* res, size_t* size) {
    file_content_t content = res->get_payload_file(res);
    const size_t length = content.ok ? content.size : res->body.size;

    char* data = res->get_payload(res);
    if (data == NULL) {
        *size = 0;
        return NULL;
    }

    *size = length;

    return data;
}

int storages3_head(const char* storage_name, const char* path,
                   const char* if_none_match, const char* if_modified_since,
                   s3fetch_t* out) {
    if (out == NULL) return 0;

    memset(out, 0, sizeof *out);
    out->file = file_alloc();

    storage_t* base = __storage_find(storage_name);
    if (base == NULL || base->type != STORAGE_TYPE_S3) return 0;

    httpclient_t* client = NULL;
    httpresponse_t* res = __request_object((storages3_t*)base, "HEAD", ROUTE_HEAD, path,
                                           NULL, if_none_match, if_modified_since, &client);
    if (res == NULL) {
        out->status = 0;
        return 0;
    }

    out->status = res->status_code;
    out->etag = __header_copy(res, "ETag");
    out->last_modified = __header_copy(res, "Last-Modified");
    out->content_type = __header_copy(res, "Content-Type");

    http_header_t* length = res->get_header(res, "Content-Length");
    if (length != NULL && length->value != NULL)
        out->total_size = strtoull(length->value, NULL, 10);

    client->free(client);

    return out->status == 200 || out->status == 304;
}

int storages3_fetch(const char* storage_name, const char* path,
                    size_t start, size_t end, int whole, s3fetch_t* out) {
    if (out == NULL) return 0;

    memset(out, 0, sizeof *out);
    out->file = file_alloc();

    storage_t* base = __storage_find(storage_name);
    if (base == NULL || base->type != STORAGE_TYPE_S3) return 0;

    storages3_t* s = (storages3_t*)base;

    const size_t chunk = storages3_chunk_size(env()->main.client_max_body_size);
    size_t cursor = whole ? 0 : start;
    size_t last = whole ? cursor + chunk - 1 : end;   /* при whole уточняется из Content-Range */
    int first = 1;

    while (1) {
        size_t chunk_end = cursor + chunk - 1;
        if (chunk_end > last) chunk_end = last;

        char range[64];
        if (!storages3_range_format(range, sizeof(range), cursor, chunk_end))
            goto failed;

        httpclient_t* client = NULL;
        httpresponse_t* res = __request_object(s, "GET", ROUTE_GET, path, range, NULL, NULL, &client);
        if (res == NULL) {
            out->status = 0;
            goto failed;
        }

        out->status = res->status_code;
        if (res->status_code != 206 && res->status_code != 200) {
            client->free(client);
            goto failed;
        }

        if (first) {
            out->etag = __header_copy(res, "ETag");
            out->last_modified = __header_copy(res, "Last-Modified");
            out->content_type = __header_copy(res, "Content-Type");

            http_header_t* content_range = res->get_header(res, "Content-Range");
            size_t range_start = 0, range_end = 0, total = 0;
            if (content_range != NULL && content_range->value != NULL &&
                storages3_content_range_parse(content_range->value, &range_start, &range_end, &total)) {
                out->total_size = total;
                if (whole)
                    last = total > 0 ? total - 1 : 0;
            }
            else {
                /* S3 проигнорировал Range и отдал объект целиком: докачивать
                 * нечего, и второй запрос принёс бы те же байты снова. */
                last = chunk_end;
            }
        }

        size_t size = 0;
        char* data = __payload_take(res, &size);
        if (data == NULL) {
            client->free(client);
            goto failed;
        }

        const int single = first && chunk_end >= last;
        if (single) {
            /* Всё поместилось в одну порцию — тело остаётся в памяти, tmpfile
             * не нужен. */
            out->body = data;
            out->size = size;
            client->free(client);
            break;
        }

        if (first) {
            out->file = file_create_tmp("s3object", env()->main.tmp);
            if (!out->file.ok) {
                free(data);
                client->free(client);
                goto failed;
            }
        }

        const int appended = out->file.append_content(&out->file, data, size);
        free(data);
        client->free(client);

        if (!appended) goto failed;

        out->size += size;
        cursor = chunk_end + 1;
        first = 0;

        if (cursor > last) break;
    }

    return 1;

    failed:

    return 0;
}

void storages3_fetch_free(s3fetch_t* fetch) {
    if (fetch == NULL) return;

    if (fetch->etag != NULL) free(fetch->etag);
    if (fetch->last_modified != NULL) free(fetch->last_modified);
    if (fetch->content_type != NULL) free(fetch->content_type);
    if (fetch->body != NULL) free(fetch->body);

    if (fetch->file.ok)
        fetch->file.close(&fetch->file);

    memset(fetch, 0, sizeof *fetch);
    fetch->file = file_alloc();
}
