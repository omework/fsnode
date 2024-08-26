//
// Created by Jabar Karim on 25/08/2024.
//
#ifndef FSNODE_CDN_H
#define FSNODE_CDN_H

#include <uv.h>

#include "fsnode.h"
#include "server.h"
#include "http.h"

typedef struct {
    uv_tcp_t * handle;
    SSL *ssl;
    struct sockaddr_in *addr;
    SSL_CTX *ssl_ctx;
    FSNode *fs_node;
} RegistryContext;

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
    FSNode *fsNode;
} http_ctx_t;

typedef struct {
    Client *client;
    FSNode *fsNode;
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

svc_handler_t* new_http_svc_handler(FSNode *fsNode);

#endif //FSNODE_CDN_H
