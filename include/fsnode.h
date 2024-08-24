//
// Created by Jabar Karim on 13/07/2024.
//

#ifndef FSNODE_FSNODE_H
#define FSNODE_FSNODE_H

#include <tgmath.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <uv.h>
#include <duckdb.h>
#include <magic.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string.h>
#include <zlog.h>
#include <jansson.h>

#define KB 1024
#define MB (KB * 1024)
#define GB (MB * 1024)

#define FILE_CHUNK_SIZE (1*MB)

#define unused(x) (void)(x)

/*
 * ###################
 * # SECTION ENV
 * # This section contains const and functions to read environment variables
 * ###################
 */

#define ENV_DISK_DIR            "DISK_DIR"
#define ENV_DISK_SPACE          "DISK_SPACE"
#define ENV_DISK_SPACE_GAP      "DISK_SPACE_GAP"

#define ENV_PORT                "PORT"
#define ENV_HOST                "HOST"
#define ENV_NODE_NAME           "NODE_NAME"
#define ENV_CERT_FILE           "CERT"
#define ENV_KEY_FILE            "KEY"
#define ENV_CA_CERT_FILE        "CA_CERT"

#define ENV_REGISTRY_HOST       "REGISTRY_HOST"
#define ENV_REGISTRY_PORT       "REGISTRY_PORT"
#define ENV_REGISTRY_CERT       "REGISTRY_CERT"
#define ENV_REGISTRY_ACCESS_KEY "REGISTRY_ACCESS_KEY"
#define ENV_REGISTRY_SECRET_KEY "REGISTRY_SECRET_KEY"

#define ENV_API_ACCESS_KEY      "API_ACCESS_KEY"
#define ENV_API_SECRET_KEY      "API_SECRET_KEY"

#define ENV_AWS_SERVICE         "AWS_SERVICE"
#define ENV_AWS_REGION          "AWS_REGION"
#define ENV_AWS_S3_BUCKET       "AWS_S3_BUCKET"
#define ENV_AWS_ACCESS_KEY      "AWS_ACCESS_KEY"
#define ENV_AWS_SECRET_KEY      "AWS_SECRET_KEY"

typedef struct {
    const char *name;
    const char *value;
} env_var_t;

typedef bool (*env_var_cb)(void *container, env_var_t);

int env_load(void *container, env_var_cb var_cb);

/*
 * ###################
 * # SECTION UTILS
 * # This section contains helper functions
 * ###################
 */

char *toLower(const char *);

int sha256(const char *in, size_t in_len, char **out, size_t *out_len);

int hmac_sha256(const char *key, size_t key_len, const char *in, size_t in_len, char **out, size_t *out_len);

char *hex(const char *bytes, size_t length);

char *iso8601_date_from_time(struct tm *tm_info);

char *date_from_time(struct tm *tm_info);

char *trim(const char *str);

char *int_to_str(int value);

int str_to_size_t(const char *str, size_t *val);

int parse_size(const char *str_size, uint64_t *out_size);

int handle_error(int code, const char *msg);

int read_file(const char *name, char **out, size_t *out_len);

/*
 * ###################
 * # SECTION LIST
 * # This section contains definition of map
 * ###################
 */

typedef struct {
    size_t cap;
    size_t len;
    void **items;
} List;

List *list_create();

void list_grow(List *list, size_t count);

void* list_get(List *list, size_t index);

void list_add(List *list, char *item);

void *list_pop(List *list);

void *list_pop_head(List *list);

void list_clear(List *list);

void list_free(List *list);

/*
 * ###################
 * # SECTION MAP
 * # This section contains definition of map
 * ###################
 */

typedef struct {
    size_t cap;
    size_t len;
    char **names;
    char **values;
} Map;

Map *map_create();

int map_grow(Map *map, size_t count);

int map_set(Map *map, char *name, char *value);

const char *map_value(Map *map, char *name);

void map_free(Map *map);

/*
 * ###################
 * # SECTION CRYPTO
 * ###################
 */

EVP_PKEY * generate_rsa_key_pair(int bits);

X509_REQ * generate_certificate_sign_request(EVP_PKEY *pkey);

char *certificate_sign_request_to_bytes(X509_REQ *x509_req, size_t *len);

#define TLS_RECORD_MAX_SIZE     65540 // max size of a TLS record

/*
 * ###################
 * # SECTION SECURE TCP CONNECTION
 * ###################
 */

#define SC_OK                   0
#define SC_WRONG_CA_FILE        1
#define SC_TLS_INIT_ERROR       2
#define SC_TLS_CONNECT_ERROR    3
#define SC_TLS_HANDSHAKE_ERROR  4

typedef struct {
    BIO *bio;
    SSL *ssl;
    size_t written;
    size_t read;
    int error_code;
} SecureConn;

SecureConn * secure_conn_new();

int sc_dial(SSL_CTX *ssl_ctx, const char *host, const char *port, SecureConn *sc);

int sc_read(SecureConn *conn, char * data, size_t size_len);

int sc_write(SecureConn *conn, char * data, size_t size_len);

void sc_free(SecureConn *sc);


/*
 * ###################
 * # SECTION HTTP
 * # This section contains types and helper functions for HTTP
 * ###################
 */

#define HTTP_STATUS_OK                              "200"
#define HTTP_STATUS_PARTIAL_CONTENT                 "206"
#define HTTP_STATUS_BAD_REQUEST                     "400"
#define HTTP_STATUS_NOT_FOUND                       "404"
#define HTTP_STATUS_TOO_MANY_REQUESTS               "429"
#define HTTP_STATUS_INTERNAL                        "500"
#define HTTP_STATUS_SERVICE_UNAVAILABLE             "503"

#define HTTP_HEADER_HOST                            "Host"
#define HTTP_HEADER_CONTENT_RANGE                   "Content-Range"
#define HTTP_HEADER_RANGE                           "Range"
#define HTTP_HEADER_DATE                            "Date"
#define HTTP_HEADER_CONTENT_LENGTH                  "Content-Length"
#define HTTP_HEADER_CONTENT_TYPE                    "Content-Type"
#define HTTP_HEADER_AUTHORIZATION                   "Authorization"
#define HTTP_HEADER_ACCEPT_RANGES                   "Accept-Ranges"
#define HTTP_HEADER_ACCEPT_RANGES_BYTES_VALUE       "bytes"
#define HTTP_HEADER_RETRY_AFTER                     "Retry-After"

#define HTTP_VERSION_1_1                            "HTTP/1.1"

#define HTTP_METHOD_GET                             "GET"
#define HTTP_METHOD_DELETE                          "DELETE"
#define HTTP_METHOD_PUT                             "PUT"

#define HTTP_VERSION_LENGTH                         8
#define HTTP_METHOD_MAX_LENGTH                      10
#define HTTP_URI_MAX_LENGTH                         60
#define HTTP_NEWLINE                                "\r\n"
#define HTTPS_SCHEME                                "https"

#define HTTP_OBJECT_FIRST_LINE \
    char* token1;\
    char* token2;\
    char* token3;\

#define HTTP_OBJECT_FIELDS \
    bool has_content_length;\
    size_t content_length;\
    char* payload_hash;\
    Range range;\
    Map *queries;\
    Map *headers;\


typedef enum {
    range_unspecified = 0,
    range_prefix = 2,
    range_suffix = 4,
    range_full = 6
} RangeType;

typedef struct {
    RangeType type;
    size_t offset;
    size_t limit;
} Range;

typedef struct {
    HTTP_OBJECT_FIRST_LINE
    HTTP_OBJECT_FIELDS
} HTTPObject;

typedef enum {
    PARSE_FIRST_TOKEN = 0,
    PARSE_SECOND_TOKEN,
    PARSE_THIRD_TOKEN,

    PARSE_HEADER_NAME,
    PARSE_HEADER_VALUE,
    PARSE_BODY,
    PARSE_WRONG_SEQUENCE
} HTTPParseState;

typedef struct {
    bool is_request;
    HTTPParseState state;
    char last_char;
    char *header_name;
    HTTPObject *r;
} HTTPParser;

HTTPObject *http_new_object();

void http_object_free(HTTPObject *r);

const char * http_request_method(HTTPObject *r);

void http_set_request_method(HTTPObject *r, char *method);

const char * http_request_uri(HTTPObject *r);

void http_set_request_uri(HTTPObject *r, char *uri);

void http_set_request_version(HTTPObject *r, char *version);

void http_set_response_version(HTTPObject *r, char *version);

const char * http_response_status_code(HTTPObject *r);

void http_set_response_status_code(HTTPObject *r, char *status_code);

void http_set_response_status_text(HTTPObject *r, char *status_text);

const char * http_header_get(HTTPObject *r, char *name);

void http_header_set(HTTPObject *r, char *name, char *value);

int http_parse_content_range(const char *header, Range *range);

HTTPParser *http_new_parser();

char *http_raw(HTTPObject *object);

int http_parse(HTTPParser *parser, const char *buffer, size_t data_len);

void http_parser_free(HTTPParser *parser);

/*
 * ###################
 * # SECTION AWS
 * # This section contains types and helper functions to request AWS-S3 service
 * ###################
 */

#define HTTP_HEADER_X_AMZ_CONTENT_SHA256 "x-amz-content-sha256"
#define HTTP_HEADER_X_AMZ_DATE           "x-amz-date"

#define AWS_SIGNATURE_ALGORITHM         "AWS4-HMAC-SHA256"
#define AWS_REQUEST                     "aws4_request"
#define AWS_SERVER_AUTHORITY            "amazonaws.com"

#define AWS_S3_FILE_DOWNLOAD_BUF_SIZE   (32 * KB)
#define EMPTY_CONTENT_SHA256            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

typedef struct {
    const char *region;
    const char *service;
    const char *bucket;
    const char *access_key;
    const char *secret_key;
    pthread_mutex_t mutex;
} AWS;

typedef struct {
    HTTPParser *parser;
    size_t read;
    size_t read_result;
    size_t written;
    size_t write_result;
    FILE *file;

    BIO *bio;
    SSL *ssl;

    char *filename;
    char *tmp_filename;
    char *buf;
    int con;
} S3Downloader;

char *aws_host(AWS *aws);

char *aws_uri_encode(const char *in, bool encode_slash);

int aws_sign_v4(AWS *aws, HTTPObject* r, const char *request_payload_hash);

void s3_downloader_free(S3Downloader *s3);

int s3_download_clean(S3Downloader *s3);


/*
 * ###################
 * # SECTION FS_NODE
 * # This section contains types and helper functions to request AWS-S3 service
 * ###################
 */

#define FS_NODE_FILE_DOWNLOAD_EXTENSION             ".download"
#define FS_NODE_OK_DOWNLOADED                       0
#define FS_NODE_ERROR_S3_FILE_NOT_FOUND             1
#define FS_NODE_ERROR_S3_NO_SUCCESS                 2
#define FS_NODE_ERROR_S3_CANNOT_CONNECT             3
#define FS_NODE_ERROR_FILE_NOT_FOUND                4
#define FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE          5
#define FS_NODE_ERROR_CANNOT_OPEN_DOWNLOAD_FILE     6
#define FS_NODE_ERROR_CANNOT_SAVE_DOWNLOADED_FILE   7
#define FS_NODE_ERROR_S3_QUEUE_FULL                 8
#define FS_NODE_ERROR_S3_FILE_BEING_DOWNLOADED      9
#define FS_NODE_ERROR_UNKNOWN                       10

#define FS_NODE_DB_NAME                             "records.db"
#define FS_NODE_SERVICE_CERT_FILENAME               "svc.crt"
#define FS_NODE_SERVICE_CA_CRT_FILENAME             "ca.crt"
#define FS_NODE_SERVICE_KEY_FILENAME                "svc.key"

#define FS_NODE_CLIENT_RETRY_AFTER_IN_SECONDS       "3"

#define S3_TLS_SESSION_FILE                         "s3_tls_session.bin"

#define MAX_S3_DOWNLOAD_SLOT_NUMBER                 2

#define FS_NODE_READ_RECORDS_TABLE \
"create table if not exists read_records("\
"    filename varchar not null primary key,"\
"    last_read_at timestamp default CURRENT_TIMESTAMP"\
");"\

#define FS_NODE_INSERT_READ_RECORD_QUERY \
"insert into read_records (filename) values ($1)" \
"on conflict do update set last_read_at=now();"\

#define FS_NODE_SELECT_OLD_FILES_QUERY \
"select filename from read_records order by last_read_at limit 30;" \

#define FS_NODE_DELETE_FILENAME_QUERY "delete from read_records where filename=$1;"

typedef struct {
    SSL_CTX *ssl_ctx;
    char *host;
    char *port;
    char *cert;
    char *access_key;
    char *secret_key;

    char *ca_crt_bytes;
} Registry;

typedef struct {
    char *dir;
    pthread_mutex_t mutex;
    uint64_t capacity;
    uint64_t usage;
    uint64_t gap;
} Disk;

typedef struct {
    char *host;
    uint16_t port;
    char *name;
    char *api_access_key;
    char *api_secret_key;
    char *cert_file;
    char *key_file;
    char *ca_cert_file;
} Node;

typedef struct {
    FILE *handle;
    char *path;
    char *mime_type;
    size_t size;
    size_t limit;
    size_t available;
} File;

typedef struct {
    pthread_mutex_t mutex;
    char *name;
    bool downloading;
    bool available;
} FileDownload;

typedef struct {
    pthread_mutex_t mutex;
    FileDownload **files;
} Downloads;

typedef struct {
    Node *info;
    Registry *registry;
    Disk *disk;
    AWS *aws;
    Downloads *downloads;
    pthread_mutex_t prune_mutex;

    magic_t magic_cookie;
    duckdb_database db;
    duckdb_connection db_con;

    pthread_mutex_t s3_mutex;
    SSL_CTX *s3_ssl_ctx;

    SSL_SESSION *s3_ssl_session;
    SSL_CTX *ssl_server_ctx;
} FSNode;

typedef struct {
    char *name;
    int32_t service_type;
    char *host;
    int port;
    uint64_t disk_capacity;
    uint64_t disk_usage;
} NodeInfo;

char *fs_node_info_to_json(FSNode *node);

void fs_node_load_s3_ssl_session(FSNode *node);

void fs_node_save_s3_ssl_session(FSNode *node, SSL_SESSION* session);

int fs_node_init(FSNode *node);

char *fs_node_full_path(FSNode *node, const char *filepath);

int fs_node_get_oldest_file_from_registry(FSNode *node, List *names);

int fs_node_delete_file_from_registry(FSNode *node, const char *filename);

int fs_node_get_file(FSNode *node, const char *filename, Range range, File *result);

int fs_node_delete_file(FSNode *node, const char *filepath);

int fs_node_publish_info(FSNode *node);

void fs_node_free(FSNode *node);

int fs_node_s3_get2(FSNode *node, const char *filename);

int fs_node_download_file_from_storage(FSNode *node, const char *filename);

int fs_node_pull_storage_file(FSNode *node, const char *filename, bool *downloaded);

int fs_node_get_disk_usage(const char *root_dir, uint64_t *out_size);

int fs_node_register_file_read_record(FSNode *node, const char *filename);

int fs_node_prune(FSNode *node);

void fs_file_free(File *file);

/*
 * ###################
 * # SECTION BINARY TCP COMMUNICATION
 * # This section contains types and helper functions for Networking
 * ###################
 */

typedef void* any_t;

typedef struct {
    SSL *ssl;
    BIO *read;
    BIO *write;
    List *send_queue;
} TLSSession;

typedef struct {
    TLSSession *tls;
    uv_tcp_t handle;
} ClientConn;

typedef struct {
    size_t sent;
} send_info_t;

typedef void (*destroy_cb) (any_t o);

typedef any_t (*create_recv_handler_cb) (any_t input);

typedef struct {
    ClientConn *conn;
    any_t recv_handler;
} context_t;

typedef void (*on_send_cb) (context_t ctx, send_info_t info);

typedef void (*recv_cb) (const context_t ctx, const char *data, size_t len);

typedef struct {
    uv_tcp_t * handle;
    SSL *ssl;
    struct sockaddr_in *addr;
    SSL_CTX *ssl_ctx;
    FSNode *fs_node;
} RegistryContext;

typedef struct {
    FSNode *fs_node;

    any_t svc;
    ClientConn *conn;

    recv_cb recv_cb;

    any_t recv_handler;
    destroy_cb destroy_recv_handler;
} Client;

typedef struct {
    any_t create_param;

    create_recv_handler_cb create_recv_handler;
    destroy_cb destroy_recv_handler;
    recv_cb recv_handle;
} svc_handler_t;

typedef struct {
    const char *name;
    char *ip;
    int port;
    uv_tcp_t tcp;
    SSL_CTX *ssl_ctx;
    struct uv_loop_s *loop;
    RegistryContext *registry;
    svc_handler_t *svc_handler;
} Server;

typedef struct {
    ClientConn *conn;
    on_send_cb send_cb;
    uv_buf_t buffer;
} send_context_t;

#define TLS_IO_RESULT_OK 0
#define TLS_IO_RESULT_ERROR 1
#define TLS_IO_RESULT_NEED_MORE_DATA 2
#define TLS_IO_RESULT_NO_DATA 3

context_t client_ctx(Client *client);

void ctx_send_data(context_t ctx, char *data, size_t len, on_send_cb on_send);

void ctx_close(context_t ctx);

ClientConn *conn_new();

void conn_free(ClientConn *conn);

void conn_close(ClientConn *conn);

TLSSession *tls_session_new(SSL_CTX *ctx);

void tls_session_free(TLSSession * session);

Client *client_new();

void client_free(Client *client);

int tls_encrypt(ClientConn *conn, const char *data, size_t data_len, char **out, size_t *out_len);

int tls_decrypt(ClientConn *conn, const char *data, size_t data_len, char **out, size_t *out_len);

void uv_on_client_close(uv_handle_t *handle);

void uv_on_send_data(uv_write_t *req, int status);

void uv_on_receive_data(uv_stream_t *handle, ssize_t buf_size, const uv_buf_t *buf);

void uv_on_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

void uv_on_new_client(uv_stream_t *server, int status);

/*
 * ###################
 * # HTTP SERVICE HANDLING
 * ###################
 */

typedef HTTPObject* (*http_request_handle_func) (any_t handler, HTTPObject *req, const char *chunk, size_t len);

typedef struct {
    size_t limit;
    size_t offset;
} Upload;

typedef struct {
    uv_buf_t *buf;
    uv_fs_t *fs_req;

    int64_t offset;
    size_t available;
    size_t sent;
} Download;

typedef struct {
    context_t ctx;
    ClientConn *conn;
    Range range;
    Download *download;
    Upload *upload;
} http_ctx_t;

typedef struct {
    Client *client;
    HTTPParser *parser;
    http_ctx_t *ctx;
} http_recv_handler_t;

void http_on_file_chunk_sent(uv_write_t *req, int status);

void http_on_file_read(uv_fs_t *req);

void http_on_file_opened(uv_fs_t *req);

void http_ctx_close(http_ctx_t *hc);

void http_recv(context_t ctx, const char *data, size_t len);

any_t http_create_recv_handler(any_t param);

void http_destroy_recv_handler(any_t handler);

svc_handler_t *new_http_svc_handler();

/*
 * ###################
 * # ECHO SVC
 * ###################
 */

typedef struct {
    Client *client;
} EchoReceiver;

typedef struct {
    Client *client;
} EchoSender;

void echo_recv(context_t ctx, const char *data, size_t len);

any_t echo_create_recv_handler(any_t param);

void echo_destroy_recv_handler(any_t handler);

any_t echo_create_send_handler(any_t param);

void echo_destroy_send_handler(any_t handler);

void echo_send(any_t handler, char *data, size_t len);

any_t echo_get_send_handler(any_t recv_handler);

svc_handler_t *new_echo_svc_handler();

#endif //FSNODE_FSNODE_H
