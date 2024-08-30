//
// Created by Jabar Karim on 25/08/2024.
//
#include "server.h"

int client_send_data(Client *client, char *data, size_t len, on_send_cb on_send) {

    uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
    if (write_req == NULL) {
        return 1;
    }

    uv_buf_t buf;
    if (client->conn->tls != NULL) {
        char *encrypted_data = NULL;
        size_t encrypted_data_len = 0;
        int result = tls_encrypt(client, data, len, &encrypted_data, &encrypted_data_len);
        if (result != TLS_IO_RESULT_OK) {
            free(write_req);
            if (encrypted_data != NULL) {
                free(encrypted_data);
            }
            return 1;
        }
        buf = uv_buf_init(encrypted_data, (unsigned int)encrypted_data_len);
    } else {
        char * copy = (char *) malloc(len);
        memcpy(copy, data, len);
        buf = uv_buf_init(copy, (unsigned int) len);
    }

    client->on_send = on_send;
    write_req->data = client;
    int write_status = uv_write(write_req, (uv_stream_t *) &client->conn->handle, &buf, 1, uv_on_send_data);
    if (write_status) {
        dzlog_error("uv_write failed: %s\n", uv_strerror(write_status));
        return 1;
    }
    return 0;
}

void client_close(Client *client) {
    uv_close((uv_handle_t *) &client->conn->handle, uv_on_client_close);
}

/**
 * @brief Frees the Client structure and releases associated resources.
 *
 * This function frees the Client structure and releases resources allocated
 * for the parser, buffer, file name, and SSL context. It also sets the pointer
 * to the Client structure to NULL.
 *
 * @param client The Client structure to be freed.
 */
void client_free(Client *client) {
    if (client == NULL) {
        return;
    }

    if (client->data != NULL && client->svc->destroy_recv_handler != NULL) {
        client->svc->destroy_recv_handler(client->data);
    }

    conn_free(client->conn);

    free(client);
    client = NULL;
}

/**
 * @brief Creates an instance of ClientConn
 *
 * @return Pointer to ClientConn struct
 */
ClientConn *conn_new() {
    ClientConn *conn = (ClientConn*) malloc(sizeof(ClientConn ));
    return conn;
}

/**
 * @brief Frees the ClientConn structure and releases associated resources.
 *
 * @param client The Client structure to be freed.
 */
void conn_free(ClientConn *conn) {
    if (conn->tls != NULL) {
        tls_session_free(conn->tls);
        conn->tls = NULL;
    }

    free(conn);
    conn = NULL;
}

/**
 * @brief Creates a new instance of Client.
 *
 * This function allocates memory for an instance of Client and initializes its members.
 *
 * @return Pointer to the newly created Client instance, or NULL if memory allocation fails.
 */
Client *client_new() {
    Client *client = (Client *) malloc(sizeof(Client));
    client->conn = conn_new();
    return client;
}

/**
 * @brief Creates a new instance of Client.
 *
 * This function allocates memory for an instance of Client and initializes its members.
 *
 * @return Pointer to the newly created Client instance, or NULL if memory allocation fails.
 */
void conn_flush(Client *client) {
    if (client->conn->tls != NULL){
        size_t data_len = (size_t) BIO_pending(client->conn->tls->write);
        if (data_len == 0) {
            return;
        }

        uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
        if (write_req == NULL) {
            client_close(client);
            return;
        }

        char *data = (char *) malloc(data_len);
        if (data == NULL) {
            free(write_req);
            return;
        }

        int read_len = BIO_read(client->conn->tls->write, data, (int) data_len);
        if (read_len < 0) {
            free(write_req);
            free(data);
            client_close(client);
        }

        uv_buf_t buf = uv_buf_init(data, data_len);
        uv_write(write_req, (uv_stream_t *) &client->conn->handle, &buf, 1, uv_on_send_data);
    }
}

/**
 * @brief Encrypt data into out.
 *
 * @return TLS_IO_RESULT_OK on success.
 * @return TLS_IO_RESULT_ERROR on error.
 */
int tls_encrypt(Client *client, const char *data, size_t data_len, char **out, size_t *out_len) {
    size_t total_written = 0;
    while(total_written < data_len) {
        int written = SSL_write(client->conn->tls->ssl, data + total_written, (int) (data_len - total_written));
        if (written <= 0) {
            int ssl_error = SSL_get_error(client->conn->tls->ssl, written);
            if (ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            unsigned long ssl_error_code = ERR_get_error();
            char ssl_error_str[256];
            ERR_error_string_n(ssl_error_code, ssl_error_str, sizeof(ssl_error_str));
            fprintf(stderr, "SSL write error: code=%d details=%s\n", ssl_error, ssl_error_str);
            return TLS_IO_RESULT_ERROR;
        }
        total_written += (size_t) written;
    }

    *out_len = (size_t) BIO_pending(client->conn->tls->write);
    if (*out_len > 0) {
        *out = (char *) malloc(*out_len);
        int bytes_read = BIO_read(client->conn->tls->write, *out, (int) *out_len);
        if (bytes_read <= 0) {
            dzlog_error("BIO_read failed: %d\n", bytes_read);
            free(*out);
            return TLS_IO_RESULT_ERROR;
        }
        *out_len = (size_t) bytes_read;
    }
    return TLS_IO_RESULT_OK;
}

/**
 * @brief Decrypt data into out.
 *
 * @return TLS_IO_RESULT_OK on success.
 * @return TLS_IO_RESULT_NEED_MORE_DATA if TLS record is incomplete.
 */
int tls_decrypt(Client *client, const char *data, size_t data_len, char **out, size_t *out_len) {
    // Write incoming data to the read BIO
    int result = BIO_write(client->conn->tls->read, data, (int) data_len);
    if (result <= 0) {
        return TLS_IO_RESULT_ERROR;  // Error writing to the read BIO
    }

    // Buffer to read decrypted data from SSL layer
    size_t buf_size = 1024;
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return TLS_IO_RESULT_ERROR;  // Memory allocation failure
    }

    while (true) {
        int read = SSL_read(client->conn->tls->ssl, buf, (int) buf_size);
        if (read <= 0) {
            int ssl_error = SSL_get_error(client->conn->tls->ssl, read);
            switch (ssl_error) {
                case SSL_ERROR_WANT_READ:
                    free(buf);
                    if (SSL_is_init_finished(client->conn->tls->ssl)) {
                        return TLS_IO_RESULT_OK;
                    }
                    conn_flush(client);
                    return TLS_IO_RESULT_NEED_MORE_DATA;
                case SSL_ERROR_WANT_WRITE:
                    free(buf);
                    conn_flush(client);
                    return TLS_IO_RESULT_NEED_MORE_DATA;
                case SSL_ERROR_ZERO_RETURN:
                    free(buf);

                    if (SSL_is_init_finished(client->conn->tls->ssl)) {
                        return TLS_IO_RESULT_OK;  // Handshake done, clean shutdown
                    }

                    if (BIO_pending(client->conn->tls->read) > 0) {
                        return TLS_IO_RESULT_NEED_MORE_DATA;
                    }

                    return TLS_IO_RESULT_NO_DATA;  // Connection closed, no more data
                default:
                {
                    unsigned long ssl_error_code = ERR_get_error();
                    char ssl_error_str[256];
                    ERR_error_string_n(ssl_error_code, ssl_error_str, sizeof(ssl_error_str));
                    fprintf(stderr, "SSL read error: code=%d details=%s\n", ssl_error, ssl_error_str);
                }
                    free(buf);
                    if (*out != NULL) {
                        free(*out);  // Clean up any partially allocated output
                    }
                    return TLS_IO_RESULT_ERROR;
            }
        }

        // Append the decrypted data to the output buffer
        char *new_result = realloc(*out, *out_len + (size_t) read);
        if (new_result == NULL) {
            if (*out != NULL) free(*out);
            free(buf);
            return TLS_IO_RESULT_ERROR;  // Memory allocation failure
        }

        *out = new_result;
        memcpy(*out + *out_len, buf, (size_t) read);
        *out_len += (size_t) read;
    }
}

/**
 * @brief Callback function called when the connection is closed.
 *
 * This function handles freeing the resources associated with the HTTP context and the handle.
 *
 * @param handle The handle associated with the connection being closed.
 */
void uv_on_client_close(uv_handle_t *handle) {
    Client *client = (Client *) handle->data;
    client_free(client);
}

/**
 * @brief Callback function for handling HTTP response write.
 *
 * This function is called when the write of an HTTP response is complete.
 * It logs an error if the write was not successful, frees the data associated
 * with the write request, and frees the write request itself.
 *
 * @param req   The uv_write_t structure representing the write request.
 * @param status    The status code indicating the success or failure of the write operation.
 *
 * @remarks The specified req->data is expected to be a pointer to the data associated with the write request.
 *          If req->data is not NULL, this function frees the memory allocated for this data and sets req->data to NULL.
 *          The function also frees the memory allocated for the write request itself.
 */
void uv_on_send_data(uv_write_t *req, int status) {
    Client *client = (Client *) req->data;
    if (status) {
        dzlog_error("conn data write failed: %s", uv_strerror(status));
    }
    free(req);
    if (client != NULL && client->on_send != NULL) {
        send_info_t  info = {};
        client->on_send((any_t) client, info);
    }
}

/**
 * @brief Callback function for handling HTTP requests
 *
 * This function is called when a new HTTP request is received on the specified handle.
 * It parses the request, performs the necessary operations based on the request method and URI,
 * and sends the appropriate HTTP response.
 *
 * @param handle The handle on which the request was received
 * @param buf_size The size of the buffer containing the request
 * @param buf The buffer containing the request
 */
void uv_on_receive_data(uv_stream_t *handle, ssize_t buf_size, const uv_buf_t *buf) {
    if (buf_size < 0) {
        uv_close((uv_handle_t *) handle, uv_on_client_close);
        return;
    }

    Client *client = (Client *) handle->data;
    if (client->svc == NULL) {
        dzlog_warn("no data handler available");
        uv_close((uv_handle_t *) handle, uv_on_client_close);
        return;
    }

    if (client->data == NULL) {
        client->data = client->svc->create_recv_handler(client->svc->create_param);
    }

    if (client->conn->tls != NULL) {
        char *plain_data;
        size_t plain_data_len = 0;
        int result = tls_decrypt(client, buf->base, buf_size, &plain_data, &plain_data_len);
        if (result != TLS_IO_RESULT_OK) {
            switch (result) {
                case TLS_IO_RESULT_NEED_MORE_DATA:
                case TLS_IO_RESULT_NO_DATA:
                    return;
                default:
                    uv_close((uv_handle_t *) handle, uv_on_client_close);
                    return;
            }
        }

        if (plain_data_len == 0) {
            return;
        }
        client->svc->recv_handle(client, plain_data, plain_data_len);
        free(plain_data);
    } else {
        client->svc->recv_handle(client, buf->base, buf_size);
    }
}

/**
 * @brief Allocates a buffer for handling HTTP requests.
 *
 * This function is an implementation of the allocation callback for `uv_read_start`.
 * It allocates a buffer of the suggested size and assigns it to the provided `uv_buf_t` structure.
 * If the buffer allocation fails, the function closes the handle and invokes the callback `uv_on_client_close`.
 *
 * @param handle The handle associated with the request.
 * @param suggested_size The suggested size to allocate for the buffer.
 * @param buf A pointer to the `uv_buf_t` structure where the buffer will be assigned.
 *             The allocated buffer is stored in the `base` field and the size in the `len` field.
 */
void uv_on_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    Client *client = (Client *) handle->data;
    if (client->conn->tls != NULL && suggested_size < TLS_BUFFER_SIZE) {
        suggested_size = TLS_BUFFER_SIZE;
    }

    char *buffer = (char *) malloc(suggested_size);
    if (buffer == NULL) {
        uv_close((uv_handle_t *) handle, uv_on_client_close);
        return;
    }
    buf->len = suggested_size;
    buf->base = buffer;
}

/**
 * @brief Handles new HTTP connection.
 *
 * This function is called when a new connection is established with the HTTP server.
 * It creates a new Client, initializes the TCP handle, and starts reading data from the connection.
 * If an error occurs during setup, the handle is closed and the context is freed.
 *
 * @param server The server that received the new connection.
 * @param status The status of the connection.
 */
void uv_on_new_client(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }

    Server* svc = (Server *) server->data;

    Client *client = client_new();
    if (uv_tcp_init(server->loop, &client->conn->handle) != 0) {
        uv_close((uv_handle_t *) &client->conn->handle, uv_on_client_close);
        return;
    }

    if (uv_accept(server, (uv_stream_t *) &client->conn->handle) == 0) {
        if (client->conn == NULL) {
            uv_close((uv_handle_t *) &client->conn->handle, uv_on_client_close);
            return;
        }

        if (svc->ssl_ctx != NULL) {
            client->conn->tls = tls_session_new(svc->ssl_ctx);
            if (client->conn->tls == NULL) {
                ERR_print_errors_fp(stderr);
                uv_close((uv_handle_t *) &client->conn->handle, uv_on_client_close);
                return;
            }
        }
        client->svc = svc->svc_handler;
        client->conn->handle.data = client;

        uv_read_start((uv_stream_t *) &client->conn->handle, uv_on_alloc_buffer, uv_on_receive_data);
    } else {
        uv_close((uv_handle_t *) &client->conn->handle, uv_on_client_close);
        client_free(client);
    }
}

/**
 * @brief Start serving connections on the specified server.
 *
 * This function initializes the TCP server, binds it to the specified IP address
 * and port, and starts listening for incoming connections. When a new connection
 * is established, the specified callback function `on_connection` will be called.
 *
 * @param server The server to serve connections on.
 * @param on_connection The callback function to be called when a new connection is established.
 * @return 0 if successful, non-zero otherwise.
 */
int svc_serve(Server *server, uv_connection_cb on_connection) {
    uv_tcp_init(uv_default_loop(), &server->tcp);

    struct sockaddr_in sa;
    int status = uv_ip4_addr("0.0.0.0", server->port, &sa);
    if (status != 0) {
        return status;
    }

    server->tcp.data = server;

    uv_tcp_bind(&server->tcp, (const struct sockaddr *) &sa, 0);
    int result = uv_listen((uv_stream_t *) &server->tcp, 1024, on_connection);
    if (result) {
        dzlog_error("Listen error %s", uv_strerror(result));
        return 1;
    }

    dzlog_info("%s server: port %d", server->name, server->port);
    return 0;
}