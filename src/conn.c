//
// Created by Jabar Karim on 25/08/2024.
//

#include "conn.h"

SecureConn *secure_conn_new() {
    SecureConn *sc = (SecureConn *) malloc(sizeof(SecureConn));
    if (sc == NULL) return NULL;
    sc->bio = NULL;
    sc->ssl = NULL;
    return sc;
}

/**
 * @brief Establishes a secure TCP connection using SSL/TLS.
 *
 * @param ssl_ctx The SSL context to be used for the connection.
 * @param host The host address or IP.
 * @param port The port number of the destination.
 * @param sc A pointer to a SecureConn structure to store the connection information.
 *
 * @return An error code indicating the result of the operation.
 *         - SC_TLS_INIT_ERROR: Failed to initialize the SSL/TLS connection.
 *         - SC_TLS_CONNECT_ERROR: Failed to establish a TCP connection.
 *         - SC_TLS_HANDSHAKE_ERROR: Failed to perform the SSL/TLS handshake.
 *         - SC_OK: The TCP connection and SSL/TLS handshake were successful.
 */
int sc_dial(SSL_CTX *ssl_ctx, const char *host, const char *port, SecureConn *sc) {
    sc->bio = NULL;
    sc->ssl = NULL;
    sc->read = 0;
    sc->written = 0;

    sc->bio = BIO_new_ssl_connect(ssl_ctx);
    if (sc->bio == NULL) {
        return SC_TLS_INIT_ERROR;
    }

    if (BIO_get_ssl(sc->bio, &sc->ssl) != 1 || sc->ssl == NULL) {
        return SC_TLS_INIT_ERROR;
    }

    SSL_set_mode(sc->ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_set_conn_hostname(sc->bio, host) != 1) {
        return SC_TLS_INIT_ERROR;
    }

    if (BIO_set_conn_port(sc->bio, port) != 1) {
        return SC_TLS_INIT_ERROR;
    }

    if (BIO_do_connect(sc->bio) <= 0) {
        return SC_TLS_CONNECT_ERROR;
    }

    if (BIO_do_handshake(sc->bio) <= 0) {
        return SC_TLS_HANDSHAKE_ERROR;
    }

    return SC_OK;
}

/**
 * @brief Reads encrypted data from the secure connection.
 *
 * This function reads up to `size_len` bytes of encrypted data from the secure connection `sc`, and stores the result in the buffer `data`.
 *
 * @param sc A pointer to a `SecureConn` structure representing the secure connection.
 * @param data A pointer to the buffer where the received data will be stored.
 * @param size_len The maximum number of bytes to read from the secure connection.
 * @return The number of bytes read if successful, or a negative value if an error occurred.
 *         If an error occurred, the error code will be stored in `sc->error_code`.
 *
 * @note It's important to note that the secure connection must already be established and the SSL context within the `SecureConn` structure must be properly initialized before calling this function.
 * @note The secure connection will only be read from the internal SSL object if `read` is greater than 0.
 */
int sc_read(SecureConn *sc, char *data, size_t size_len) {
    int result = SSL_read_ex(sc->ssl, data, (int) size_len, &sc->read);
    if (result <= 0) {
        sc->error_code = SSL_get_error(sc->ssl, result);
    }
    return result;
}

/**
 * Writes data to the SSL connection.
 *
 * @param sc Pointer to the SecureConn structure representing the SSL connection.
 * @param data Pointer to the buffer containing the data to be written.
 * @param size_len The size of the data buffer.
 * @return On success, returns the number of bytes written to the SSL connection.
 *         On error, returns a negative value indicating the error code.
 *
 * The function takes a SecureConn structure pointer (sc), a data buffer pointer (data),
 * and the size of the data buffer (size_len) as parameters. It writes the specified
 * data to the SSL connection using SSL_write_ex function and updates the written field
 * in the SecureConn structure. The written field represents the number of bytes written
 * to the SSL connection.
 *
 * Example usage:
 * ```
 * SecureConn sc;
 * char *data = "Hello, world!";
 * size_t size = strlen(data);
 * int result = sc_write(&sc, data, size);
 * if (result < 0) {
 *     printf("Error: Could not write data to SSL connection. Error code: %d\n", result);
 * } else {
 *     printf("Successfully wrote %d bytes to the SSL connection.\n", result);
 * }
 * ```
 */
int sc_write(SecureConn *sc, char *data, size_t size_len) {
    return SSL_write_ex(sc->ssl, data, (int) size_len, &sc->written);
}

/**
 * @brief Frees the resources used by a SecureConn object.
 *
 * This function frees the resources used by a SecureConn object, including its associated BIO and SSL objects.
 *
 * @param sc A pointer to the SecureConn object to be freed. Must not be NULL.
 */
void sc_free(SecureConn *sc) {
    if (sc == NULL) {
        return;
    }

    if (sc->bio != NULL) {
        BIO_free_all(sc->bio);
        sc->bio = NULL;
        sc->ssl = NULL;
    }

    free(sc);
    sc = NULL;
}