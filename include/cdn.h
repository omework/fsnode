//
// Created by Jabar Karim on 25/08/2024.
//
#ifndef FSNODE_CDN_H
#define FSNODE_CDN_H

#include <uv.h>

#include "fsnode.h"
#include "server.h"
#include "http.h"

#define BUFFER_SIZE (150*KB)

typedef struct {
    HTTPParser *parser;
    HTTPObject *request;
    Client *client;
    FSNode *fsNode;
} http_ctx_t;

int http_send_data(http_ctx_t *ctx, char *data, size_t len);

void http_write_response(http_ctx_t *hc, HTTPObject *rsp);

void http_send_response_headers(http_ctx_t *ctx, HTTPObject *rsp);

void http_close(http_ctx_t *hc);

void http_recv(any_t rc, const char *data, size_t len);

any_t http_create_recv_handler(any_t param);

void http_destroy_recv_handler(any_t handler);

svc_handler_t* new_http_svc_handler(FSNode *fsNode);

#endif //FSNODE_CDN_H
