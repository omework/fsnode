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

#include "env.h"
#include "aws.h"
#include "list.h"
#include "http.h"
#include "conn.h"
#include "crypto.h"

#define KB 1024
#define MB (KB * 1024)
#define GB (MB * 1024)

#define FILE_CHUNK_SIZE (128*KB)

duckdb_timestamp db_timestamp_from_time(struct tm *tm);

bool fs_node_set_env_var(void *container, env_var_t var);

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
    FILE *fd;
    char *path;
    char *mime_type;
    size_t size;
    size_t offset;
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

typedef struct {
    int64_t offset;
    int64_t limit;
    size_t max_chunk_size;
} read_options_t;

char *fs_node_info_to_json(FSNode *node);

FSNode *fs_node_new();

int fs_node_init(FSNode *node);

char *fs_node_full_path(FSNode *node, const char *filepath);

int fs_node_get_oldest_file_from_registry(FSNode *node, List *names);

int fs_node_delete_file_from_registry(FSNode *node, const char *filename);

int fs_node_get_file(FSNode *node, const char *filename, read_options_t opts, File **file);

int fs_node_delete_file(FSNode *node, const char *filepath);

int fs_node_publish_info(FSNode *node);

int fs_node_get_signed_certificate(FSNode *node);

void fs_node_free(FSNode *node);

int fs_node_s3_get2(FSNode *node, const char *filename);

int fs_node_download_file_from_storage(FSNode *node, const char *filename);

int fs_node_pull_storage_file(FSNode *node, const char *filename, bool *downloaded);

int fs_node_get_disk_usage(const char *root_dir, uint64_t *out_size);

int fs_node_register_file_read_record(FSNode *node, const char *filename);

int fs_node_prune(FSNode *node);

void fs_file_free(File *file);

#endif //FSNODE_FSNODE_H
