//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_CRYPTO_H
#define FSNODE_CRYPTO_H

#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdbool.h>

#define _crypto_unused(x) (void)(x)

typedef struct {
    SSL *ssl;
    BIO *read;
    BIO *write;
} TLSSession;

int sha256(const char *in, size_t in_len, char **out, size_t *out_len);

int hmac_sha256(const char *key, size_t key_len, const char *in, size_t in_len, char **out, size_t *out_len);

SSL_CTX * fs_node_init_service_tls_context( const char *certificate_filename, const char *key_filename, bool log_enabled);

int save_rsa_private_key(const char *filename, EVP_PKEY *pkey);

EVP_PKEY *load_rsa_private_key(const char *filename);

X509 *load_certificate(const char *filename);

int attach_ca_cert_to_ssl_context(SSL_CTX **ssl_ctx, const char *ca_cert_path);

EVP_PKEY * generate_rsa_key_pair(int bits);

X509_REQ * generate_certificate_sign_request(EVP_PKEY *pkey);

char *certificate_sign_request_to_bytes(X509_REQ *x509_req, size_t *len);

TLSSession *tls_session_new(SSL_CTX *ctx);

void tls_session_free(TLSSession * session);

#endif //FSNODE_CRYPTO_H
