//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_CONN_H
#define FSNODE_CONN_H

#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

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

#endif //FSNODE_CONN_H
