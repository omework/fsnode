//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_CDN_C_H
#define FSNODE_CDN_C_H

#include "cdn.h"

/**
 * @brief Creates an HTTPObject with the response status code, version, status text, and headers set.
 *
 * This function creates a new HTTPObject and sets the response status code, version, status text, and headers based on the provided parameters.
 * The response version is set to "HTTP_VERSION_1_1" by default. The function returns the created HTTPObject.
 *
 * @param code The response status code.
 * @param content_length The value of the "Content-Length" header.
 * @param content_type The value of the "Content-Type" header.
 * @return HTTPObject* The created HTTPObject with the response data.
 */
HTTPObject *http_OK_response(const char *code, int content_length, const char *content_type) {
    HTTPObject *rsp = http_new_object();
    if (rsp != NULL) {
        http_set_response_status_code(rsp, strdup(code));
        http_set_response_version(rsp, strdup(HTTP_VERSION_1_1));
        http_set_response_status_text(rsp, strdup("OK"));
        http_header_set(rsp, strdup(HTTP_HEADER_DATE), http_get_current_date());
        http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_LENGTH), int_to_str(content_length));
        http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_TYPE), strdup(content_type));
    }
    return rsp;
}

/**
 * @brief Creates an HTTPObject representing a retry response with the specified number of seconds.
 *
 * @param[in] seconds The number of seconds to include in the Retry-After header.
 *
 * @return A pointer to the newly created HTTPObject, or NULL if an error occurred.
 */
HTTPObject *http_retry_response(const char *seconds) {
    HTTPObject *rsp = http_new_object();
    if (rsp != NULL) {
        http_set_response_status_code(rsp, strdup(HTTP_STATUS_SERVICE_UNAVAILABLE));
        http_set_response_version(rsp, strdup(HTTP_VERSION_1_1));
        http_set_response_status_text(rsp, strdup("OK"));
        http_header_set(rsp, strdup(HTTP_HEADER_DATE), http_get_current_date());
        http_header_set(rsp, strdup(HTTP_HEADER_RETRY_AFTER), strdup(seconds));
    }
    return rsp;
}

/**
 * @brief Create an HTTP response object.
 *
 * This function creates and initializes an HTTP response object with the given status code and status text.
 *
 * @param code The status code of the response.
 * @param status_text The status text of the response.
 * @return HTTPObject* The created HTTP response object.
 */
HTTPObject *http_response(const char *code, const char *status_text) {
    HTTPObject *rsp = http_new_object();
    http_set_response_status_code(rsp, strdup(code));
    http_set_response_version(rsp, strdup(HTTP_VERSION_1_1));
    http_set_response_status_text(rsp, strdup(status_text));
    http_header_set(rsp, strdup(HTTP_HEADER_DATE), http_get_current_date());
    return rsp;
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
void uv_on_write_data(uv_write_t *req, int status) {
    if (status) {
        dzlog_error("HTTP response write failed: %s", uv_strerror(status));
    }

    char *data = req->data;
    if (data != NULL) {
        free(data);
        req->data = NULL;
    }
    free(req);
}

void task_after_prune(uv_work_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "Work failed: %s\n", uv_strerror(status));
    } else {
        printf("Pruning completed.\n");
    }
    free(req);
}

void task_prune_work(uv_work_t *req) {
    FSNode *node = (FSNode *) req->data;
    if (node == NULL) {
        return;
    }
    fs_node_prune(node);
}

/**
 * @brief Callback function for freeing upload file resources.
 *
 * @param req The file request
 */
void uv_on_file_uploaded(uv_fs_t *req) {
    uv_fs_req_cleanup(req);
    free(req);
}

/*
 * #######################
 * # HTTP SERVICE HANDLING
 * #######################
 */

void http_ctx_close(http_ctx_t *hc) {
    ctx_close(hc->ctx);
}

void http_ctx_send(http_ctx_t *hc, char *data, size_t len, uv_write_cb after_write) {
    unused(hc);
    unused(data);
    unused(len);
    unused(after_write);

    ctx_close(hc->ctx);
}

/**
 * @brief Callback function for handling file write operation in the HTTP server
 *
 * This function is called when the file write operation is completed. It checks the
 * status of the operation and handles the following scenarios:
 *   - If the status is non-zero, it indicates an error occurred or the client connection
 *     was closed. The function cleans up the resources and closes the connection.
 *   - If the status is zero and the number of bytes sent is equal to the total bytes
 *     of the file, it means that the file write operation is completed successfully.
 *     The function cleans up the resources, closes the file, and closes the connection.
 *   - If the status is zero but the number of bytes sent is not equal to the total bytes
 *     of the file, it means that there is more data to send. The function initiates a
 *     file read operation to read the next chunk of data and continue the sending process.
 *
 * @param req The UV write request object
 * @param status The status of the file write operation
 */
void http_on_file_chunk_sent(uv_write_t *req, int status) {
    http_ctx_t *ctx = (http_ctx_t *) req->data;
    if (status || ctx->download->sent == ctx->download->available) {
        uv_fs_t close_req;
        uv_fs_close(uv_default_loop(), &close_req, ctx->download->fs_req->file, NULL);
        uv_fs_req_cleanup(ctx->download->fs_req);
        http_ctx_close(ctx);
        return;
    }
    uv_fs_read(uv_default_loop(), ctx->download->fs_req, ctx->download->fs_req->file, ctx->download->buf, 1, ctx->download->offset, http_on_file_read);
}

/**
 * @brief Callback function for reading file data and sending it over a HTTP connection
 *
 * This function is called when the file read operation is completed. It checks the result
 * of the operation and handles the following scenarios:
 *   - If the result is less than or equal to 0, it means that the client connection was closed
 *     or an error occurred. The function cleans up the resources and closes the connection.
 *   - If the result is greater than 0, it means that file data has been read successfully.
 *     The function prepares a buffer with the read data and sends it over the HTTP connection
 *     using the uv_write function. It also keeps track of the number of bytes sent and the
 *     file offset.
 *
 * @param req The UV file system request object
 */
void http_on_file_read(uv_fs_t *req) {
    http_ctx_t *ctx = (http_ctx_t *) req->data;
    if (req->result <= 0) {
        uv_fs_req_cleanup(req);
        uv_fs_close(uv_default_loop(), req, req->file, NULL);
        http_ctx_close(ctx);
        return;
    }

    size_t chunk_size = req->result;
    if (ctx->download->sent + chunk_size > ctx->download->available) {
        chunk_size = ctx->download->available - ctx->download->sent;
    }

    http_ctx_send(ctx, ctx->download->buf->base, chunk_size, http_on_file_chunk_sent);
    ctx->download->sent += chunk_size;
    ctx->download->offset += (int64_t) chunk_size;
}

/**
 * @brief Callback function for handling after file opens.
 *
 * This function is called when a file is successfully opened for reading.
 * It prepares the HTTP response headers based on the file information and sends them to the client.
 * If any error occurs during the process, it sends an appropriate error response and closes the connection.
 *
 * @param req: pointer to the uv_fs_t structure representing the file open request
 */
void http_on_file_opened(uv_fs_t *req) {
    http_ctx_t *ctx = (http_ctx_t *) req->data;
    if (req->result <= 0) {
        http_ctx_close(ctx);
        return;
    }

    Download *download = ctx->download;
    char *chunk_buffer = (char *) malloc(FILE_CHUNK_SIZE);
    if (chunk_buffer == NULL) {
        uv_fs_close(uv_default_loop(), req, req->file, NULL);
        http_ctx_close(ctx);
        return;
    }

    download->buf = (uv_buf_t *) malloc(sizeof(uv_buf_t ));
    download->buf->base = chunk_buffer;
    download->buf->len = FILE_CHUNK_SIZE;
    download->fs_req = req;

    uv_fs_read(uv_default_loop(), req, req->file, download->buf, 1, download->offset, http_on_file_read);
}

void http_send_response(http_ctx_t *ctx, HTTPObject *rsp) {
    char *raw_rsp = http_raw(rsp);
    ctx_send_data(ctx->ctx, raw_rsp, strlen(raw_rsp), NULL);
    free(rsp);
}

void http_handle_get(any_t handler, HTTPObject *req, const char *chunk, size_t len) {
    unused(chunk);
    unused(req);
    unused(len);

    http_ctx_t *ctx = (http_ctx_t *) (handler);

    const char *uri = http_request_uri(req);

    int pull_file_result;
    bool downloaded = false;

    if ((pull_file_result = fs_node_pull_storage_file(ctx->fsNode, uri, &downloaded)) != 0) {
        HTTPObject *rsp;
        switch (pull_file_result) {
            case FS_NODE_ERROR_FILE_NOT_FOUND:
            case FS_NODE_ERROR_S3_FILE_NOT_FOUND:
                rsp = http_response(HTTP_STATUS_NOT_FOUND, "NOT FOUND");
                break;
            case FS_NODE_ERROR_S3_CANNOT_CONNECT:
                rsp = http_response(HTTP_STATUS_SERVICE_UNAVAILABLE, "SERVICE UNAVAILABLE");
                break;
            case FS_NODE_ERROR_S3_QUEUE_FULL:
                rsp = http_response(HTTP_STATUS_TOO_MANY_REQUESTS, "TOO MANY REQUESTS");
                break;
            case FS_NODE_ERROR_S3_FILE_BEING_DOWNLOADED:
                rsp = http_retry_response(FS_NODE_CLIENT_RETRY_AFTER_IN_SECONDS);
                break;
            default:
                rsp = http_response(HTTP_STATUS_INTERNAL, "INTERNAL SERVER ERROR");
                break;
        }
        http_send_response(ctx, rsp);
        http_ctx_close(ctx);
        return;
    }

    if (downloaded) {
        uv_work_t *work_req = (uv_work_t *) malloc(sizeof(uv_work_t));
        work_req->data = ctx->fsNode;
        uv_queue_work(uv_default_loop(), work_req, task_prune_work, task_after_prune);
    }

    File *file = malloc(sizeof(File));
    if (file == NULL) {
        http_send_response(ctx, http_response(HTTP_STATUS_INTERNAL, "INTERNAL SERVER ERROR"));
        http_ctx_close(ctx);
        return;
    }

    read_options_t  opts = {
            .limit = req->range.limit,
            .offset = req->range.offset,
            .max_chunk_size = 1 * MB
    };
    if (fs_node_get_file(ctx->fsNode, uri, &opts, file) != 0) {
        http_send_response(ctx, http_response(HTTP_STATUS_INTERNAL, "INTERNAL SERVER ERROR"));
        http_ctx_close(ctx);
        return;
    }

    const char *code =
            req->range.type != range_unspecified && file->available == file->size
            ? HTTP_STATUS_OK : HTTP_STATUS_PARTIAL_CONTENT;
    HTTPObject *rsp = http_OK_response(code, (int) file->available, file->mime_type);
    if (rsp == NULL) {
        fs_file_free(file);
        http_ctx_close(ctx);
        return;
    }
    if (req->range.type != range_unspecified) {
        char *range_bytes = malloc(100);
        if (range_bytes == NULL) {
            fs_file_free(file);
            http_ctx_close(ctx);
            return;
        }

        sprintf(range_bytes, "bytes %lld-%lu/%lu", req->range.offset, file->limit, file->size);
        http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_RANGE), range_bytes);
    }
    http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_LENGTH), int_to_str((int) file->available));
    http_header_set(rsp, strdup(HTTP_HEADER_ACCEPT_RANGES), strdup(HTTP_HEADER_ACCEPT_RANGES_BYTES_VALUE));
    http_send_response(ctx, rsp);


    Download *download = (Download *) malloc(sizeof (Download));
    download->available = file->available;
    download->sent = 0;
    ctx->download = download;

    uv_fs_t *uv_file = (uv_fs_t *) malloc(sizeof(uv_fs_t));
    if (file == NULL) {
        ctx_close(ctx->ctx);
        return;
    }
    uv_file->data = ctx;
    uv_fs_open(uv_default_loop(), uv_file, file->path, O_RDONLY, 0, http_on_file_opened);
    fs_file_free(file);
}

void http_handle_put(any_t handler, HTTPObject *req, const char *chunk, size_t len) {
    unused(handler);
    unused(req);
    unused(chunk);
    unused(len);
}

void http_handle_delete(any_t handler, HTTPObject *req, const char *chunk, size_t len) {
    unused(handler);
    unused(req);
    unused(chunk);
    unused(len);
}

void http_recv(const context_t ctx, const char *data, size_t len) {
    http_recv_handler_t *h = (http_recv_handler_t *) ctx.recv_handler;
    if (h->parser == NULL) {
        h->parser = http_new_parser();
    }

    int data_index = 0;
    if ((data_index = http_parse(h->parser, data, len)) < 0) {
        HTTPObject *rsp = http_response(HTTP_STATUS_BAD_REQUEST, "BAD REQUEST");
        char *raw_rsp = http_raw(rsp);
        ctx_send_data(ctx,  raw_rsp, strlen(raw_rsp), NULL);
        ctx_close(  ctx);
        return;
    }

    if (h->parser->state != PARSE_BODY) {
        return;
    }

    HTTPObject *req = h->parser->r;

    if (strcmp(http_request_method(req), HTTP_METHOD_GET) == 0) {
        http_handle_get(NULL, req, data + data_index, len - data_index);

    } else if  (strcmp(http_request_method(req), HTTP_METHOD_PUT) == 0) {
        http_handle_put(NULL, req, data + data_index, len - data_index);

    } else if  (strcmp(http_request_method(req), HTTP_METHOD_DELETE) == 0) {
        http_handle_delete(NULL, req, data + data_index, len - data_index);

    } else {
        HTTPObject *rsp = http_response(HTTP_STATUS_NOT_FOUND, "NOT FOUND");
        char *raw_rsp = http_raw(rsp);
        ctx_send_data(ctx, raw_rsp, strlen(raw_rsp), NULL);
        ctx_close(ctx);
        return;
    }
}

any_t http_create_recv_handler(any_t param) {
    unused(param);
    http_recv_handler_t *handler = (http_recv_handler_t *) malloc(sizeof (http_recv_handler_t));
    handler->parser = http_new_parser();
    handler->fsNode = (FSNode *) param;
    return handler;
}

void http_destroy_recv_handler(any_t handler) {
    if (handler == NULL) {
        return;
    }

    http_recv_handler_t *h = (http_recv_handler_t *) handler;
    if (h->parser != NULL) {
        http_parser_free(h->parser);
        h->parser = NULL;
    }

    free(h);
    h = NULL;
}

svc_handler_t* new_http_svc_handler(FSNode *fsNode) {
    svc_handler_t* handler = (svc_handler_t *) malloc(sizeof(svc_handler_t));
    if (handler == NULL) {
        return NULL;
    }

    handler->create_param = fsNode;
    handler->create_recv_handler = http_create_recv_handler;
    handler->destroy_recv_handler = http_destroy_recv_handler;
    handler->recv_handle = http_recv;

    return handler;
}

#endif //FSNODE_CDN_C_H
