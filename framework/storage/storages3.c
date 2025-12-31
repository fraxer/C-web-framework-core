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

    uri = __create_uri(s, path);
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

    uri = __create_uri(s, path);
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

    uri = __create_uri(s, path);
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

    uri = __create_uri(s, path);
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

    uri = __create_uri(s, path);
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
