//
// Created by Jabar Karim on 25/08/2024.
//
#include "crypto.h"



int sha256(const char *in, size_t in_len, char **out, size_t *out_len) {
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    // Get the SHA256 implementation
    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (md == NULL) {
        return 1;
    }

    // Create the message digest context
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        EVP_MD_free(md);
        return 1;
    }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_MD_free(md);
        return 1;
    }

    if (EVP_DigestUpdate(md_ctx, in, in_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_MD_free(md);
        return 1;
    }

    *out = malloc(sizeof(unsigned) * (EVP_MAX_MD_SIZE));
    if (*out == NULL) {
        EVP_MD_CTX_free(md_ctx);
        EVP_MD_free(md);
        return 1;
    }

    if (EVP_DigestFinal_ex(md_ctx, (unsigned char *) *out, (unsigned int *) out_len) <= 0) {
        free(*out);
        EVP_MD_CTX_free(md_ctx);
        EVP_MD_free(md);
        return 1;
    }

    // Clean up
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(md);
    return 0;
}

int hmac_sha256(const char *key, size_t key_len, const char *in, size_t in_len, char **out, size_t *out_len) {
    if (!key || !in || !out) {
        printf("Input parameters cannot be NULL.\n");
        return 1;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        printf("Failed to get HMAC implementation.\n");
        return 1;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        printf("Failed to create MAC context.\n");
        EVP_MAC_free(mac);
        return 1;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, (const unsigned char *) key, key_len, params) <= 0) {
        printf("Failed to initialise MAC.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    if (EVP_MAC_update(ctx, (unsigned char *) in, in_len) <= 0) {
        printf("Failed to update MAC.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    *out = malloc(sizeof(unsigned) * (EVP_MAX_MD_SIZE));
    if (*out == NULL) {
        printf("Failed to allocate memory for output.\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    if (EVP_MAC_final(ctx, (unsigned char *) *out, out_len, EVP_MAX_MD_SIZE) <= 0) {
        printf("Failed to finalise MAC.\n");
        free(*out);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return 0;
}

void ssl_info_callback(const SSL *ssl, int where, int ret) {
    _crypto_unused(ssl);
    _crypto_unused(where);
    _crypto_unused(ret);

    /*
    const char *str;
    int w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
    else str = "undefined";

    if (where & SSL_CB_LOOP) {
        printf("%s:%s\n", str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        printf("SSL alert %s:%s:%s\n",
               (where & SSL_CB_READ) ? "read" : "write",
               SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            printf("%s:failed in %s\n", str, SSL_state_string_long(ssl));
        } else if (ret < 0) {
            printf("%s:error in %s\n", str, SSL_state_string_long(ssl));
        }
    }*/
}

SSL_CTX * fs_node_init_service_tls_context( const char *certificate_filename, const char *key_filename, bool log_enabled) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);  // Minimum supported version is TLS 1.2
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, certificate_filename, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_filename, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (log_enabled) {
        SSL_CTX_set_info_callback(ctx, &ssl_info_callback);
    }

    return ctx;
}

int save_rsa_private_key(const char *filename, EVP_PKEY *pkey) {
    BIO *bio = NULL;

    bio = BIO_new_file(filename, "w");
    if (bio == NULL) return 1;

    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return 1;
    }

    BIO_free(bio);
    return 0; // Return 0 to indicate success
}

EVP_PKEY *load_rsa_private_key(const char *filename) {
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    bio = BIO_new_file(filename, "r");
    if (bio == NULL) return NULL;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return pkey;
}

X509 *load_certificate(const char *filename) {
    BIO *bio = NULL;
    X509 *cert = NULL;

    bio = BIO_new_file(filename, "r");
    if (bio == NULL) return NULL;

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return cert;
}

int attach_ca_cert_to_ssl_context(SSL_CTX **ssl_ctx, const char *ca_cert_path) {
    const SSL_METHOD *method;

    method = TLS_client_method();
    *ssl_ctx = SSL_CTX_new(method);
    if (!*ssl_ctx) {
        return 1;
    }

    if (SSL_CTX_load_verify_locations(*ssl_ctx, ca_cert_path, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(*ssl_ctx, SSL_VERIFY_PEER, NULL);

    return 0;
}

EVP_PKEY *generate_rsa_key_pair(int bits) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

X509_REQ *generate_certificate_sign_request(EVP_PKEY *pkey) {
    X509_REQ *x509_req = NULL;
    X509_NAME *name = NULL;

    x509_req = X509_REQ_new();
    if (!x509_req) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set the version
    if (X509_REQ_set_version(x509_req, X509_REQ_VERSION_1) != 1) {
        ERR_print_errors_fp(stderr);
        X509_REQ_free(x509_req);
        return NULL;
    }

    // Set the subject name
    name = X509_REQ_get_subject_name(x509_req);
    if (!name) {
        ERR_print_errors_fp(stderr);
        X509_REQ_free(x509_req);
        return NULL;
    }

    if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "CI", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *) "Lagunes", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *) "Abidjan", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "Mata 35", -1, -1, 0) != 1 ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "www.mata35.com", -1, -1, 0) != 1) {
        ERR_print_errors_fp(stderr);
        X509_REQ_free(x509_req);
        return NULL;
    }

    // Set the public key
    if (X509_REQ_set_pubkey(x509_req, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        X509_REQ_free(x509_req);
        return NULL;
    }

    if (!X509_REQ_sign(x509_req, pkey, EVP_sha256())) {
        X509_REQ_free(x509_req);
        return NULL;
    }

    return x509_req;
}

char *certificate_sign_request_to_bytes(X509_REQ *x509_req, size_t *len) {
    BIO *bio = NULL;
    BUF_MEM *buf = NULL;
    char *pem_data = NULL;

    // Create a memory BIO
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Write the X509_REQ object to the BIO in PEM format
    if (PEM_write_bio_X509_REQ(bio, x509_req) != 1) {
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return NULL;
    }

    // Get the size of the data
    BIO_get_mem_ptr(bio, &buf);
    if (buf == NULL || buf->data == NULL) {
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return NULL;
    }

    // Allocate memory for the PEM data
    pem_data = (char *) malloc(buf->length + 1);
    if (pem_data == NULL) {
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return NULL;
    }

    // Copy data from the BIO to the PEM data
    memcpy(pem_data, buf->data, buf->length);
    pem_data[buf->length] = '\0'; // Null-terminate the string
    *len = buf->length;

    BIO_free(bio);

    return pem_data;
}

TLSSession *tls_session_new(SSL_CTX *ctx) {
    TLSSession *session = (TLSSession *) malloc(sizeof(TLSSession));
    if (session == NULL) {
        return NULL;
    }

    session->ssl = SSL_new(ctx);
    if (!session->ssl) {
        free(session);
        return NULL;
    }

    SSL_set_accept_state(session->ssl);

    session->read = BIO_new(BIO_s_mem());
    session->write = BIO_new(BIO_s_mem());

    SSL_set_bio(session->ssl, session->read, session->write);
    return session;
}

void tls_session_free(TLSSession *session) {
    if (session == NULL) {
        return;
    }

    if (session->read != NULL) {
        BIO_free(session->read);
    }

    if (session->write != NULL) {
        BIO_free(session->write);
    }

    SSL_shutdown(session->ssl);

    free(session);
    session = NULL;
}