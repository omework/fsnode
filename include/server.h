//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_SERVER_H
#define FSNODE_SERVER_H

#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <uv.h>
#include <zlog.h>

#include "crypto.h"
#include "list.h"

typedef void* any_t;

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
    size_t min_buffer_size;
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

Client *client_new();

void client_free(Client *client);

int tls_encrypt(ClientConn *conn, const char *data, size_t data_len, char **out, size_t *out_len);

int tls_decrypt(ClientConn *conn, const char *data, size_t data_len, char **out, size_t *out_len);

void uv_on_client_close(uv_handle_t *handle);

void uv_on_send_data(uv_write_t *req, int status);

void uv_on_receive_data(uv_stream_t *handle, ssize_t buf_size, const uv_buf_t *buf);

void uv_on_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

void uv_on_new_client(uv_stream_t *server, int status);

int svc_serve(Server *server, uv_connection_cb on_connection);

#endif //FSNODE_SERVER_H
