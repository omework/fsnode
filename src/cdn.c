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
    fs_node_prune(node);
}

/*
 * #######################
 * # HTTP SERVICE HANDLING
 * #######################
 */

void http_close(http_ctx_t *hc) {
    client_close(hc->client);
}

void http_write_response(http_ctx_t *hc, HTTPObject *rsp) {
    if (rsp != NULL) {
        http_send_response_headers(hc, rsp);
    }
    client_close(hc->client);
}

int http_send_data(http_ctx_t *ctx, char *data, size_t len) {
    return client_send_data(ctx->client, data, len, NULL);
}

void http_send_response_headers(http_ctx_t *ctx, HTTPObject *rsp) {
    char *raw_rsp = http_raw(rsp);
    client_send_data(ctx->client, raw_rsp, strlen(raw_rsp), NULL);
    free(raw_rsp);
    free(rsp);
}

void http_handle_get(http_ctx_t *ctx) {
    const char *uri = http_request_uri(ctx->request);

    int pull_file_result;
    bool downloaded;
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
        http_write_response(ctx, rsp);
        return;
    }

    if (downloaded) {
        uv_work_t *work_req = (uv_work_t *) malloc(sizeof(uv_work_t));
        work_req->data = ctx->fsNode;
        uv_queue_work(uv_default_loop(), work_req, task_prune_work, task_after_prune);
    }

    read_options_t opts = {
        .offset = ctx->request->range.offset,
        .limit = ctx->request->range.limit,
        .max_chunk_size = BUFFER_SIZE
    };

    File *file = NULL;
    if (fs_node_get_file(ctx->fsNode, uri, opts, &file) != 0) {
        http_write_response(ctx, http_response(HTTP_STATUS_INTERNAL, "INTERNAL SERVER ERROR"));
        return;
    }

    const char *code = ctx->request->range.type != range_unspecified && file->available == file->size ? HTTP_STATUS_OK : HTTP_STATUS_PARTIAL_CONTENT;
    HTTPObject *rsp = http_OK_response(code, (int) file->available, file->mime_type);
    if (rsp == NULL) {
        fs_file_free(file);
        http_close(ctx);
        return;
    }

    char *range_bytes = malloc(100);
    if (range_bytes == NULL) {
        fs_file_free(file);
        http_close(ctx);
        return;
    }
    sprintf(range_bytes, "bytes %lld-%lu/%lu",
            ctx->request->range.offset,
            file->offset + file->available - 1, file->size);

    http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_RANGE), range_bytes);
    http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_LENGTH), int_to_str((int) file->available));
    http_header_set(rsp, strdup(HTTP_HEADER_ACCEPT_RANGES), strdup(HTTP_HEADER_ACCEPT_RANGES_BYTES_VALUE));
    http_send_response_headers(ctx, rsp);

    size_t left = file->available;
    char buffer[BUFFER_SIZE];
    size_t read, buf_size;
    while(left > 0) {
        if (left < (buf_size = BUFFER_SIZE)) {
            buf_size = left;
        }

        read = fread(buffer, 1, buf_size, file->fd);
        if (read == 0) {
            break;
        }

        if (http_send_data(ctx, buffer, read) != 0) {
            break;
        }
        left -= buf_size;
    }

    fs_file_free(file);
    http_close(ctx);
}

void http_handle_put(http_ctx_t *hc, const char *chunk, size_t len) {
    unused(hc);
    unused(chunk);
    unused(len);
}

void http_handle_delete(http_ctx_t *hc) {
    unused(hc);
}

void http_recv(any_t rc, const char *data, size_t len) {
    Client *client = (Client *) rc;
    http_ctx_t *ctx = (http_ctx_t *) client->data;
    ctx->client = client;

    int data_index;
    if ((data_index = http_parse(ctx->parser, data, len)) < 0) {
        HTTPObject *rsp = http_response(HTTP_STATUS_BAD_REQUEST, "BAD REQUEST");
        http_send_response_headers(ctx, rsp);
        client_close(rc);
        return;
    }

    if (ctx->parser->state != PARSE_BODY) {
        // header parsing is not done yet.
        return;
    }
    ctx->request = ctx->parser->r;

    if (strcmp(http_request_method(ctx->request), HTTP_METHOD_GET) == 0) {
        http_handle_get(ctx);

    } else if  (strcmp(http_request_method(ctx->request), HTTP_METHOD_PUT) == 0) {
        http_handle_put(ctx, data + data_index, len - data_index);

    } else if  (strcmp(http_request_method(ctx->request), HTTP_METHOD_DELETE) == 0) {
        http_handle_delete(ctx);

    } else {
        HTTPObject *rsp = http_response(HTTP_STATUS_NOT_FOUND, "NOT FOUND");
        http_send_response_headers(rc, rsp);
        client_close(rc);
        return;
    }
}

any_t http_create_recv_handler(any_t param) {
    unused(param);
    http_ctx_t *ctx = (http_ctx_t *) malloc(sizeof (http_ctx_t));
    ctx->parser = http_new_parser();
    ctx->fsNode = (FSNode *) param;
    return ctx;
}

void http_destroy_recv_handler(any_t handler) {
    if (handler == NULL) {
        return;
    }

    http_ctx_t *ctx = (http_ctx_t *) handler;
    if (ctx->parser != NULL) {
        http_parser_free(ctx->parser);
        ctx->parser = NULL;
    }

    free(ctx);
    handler = NULL;
}

svc_handler_t* new_http_svc_handler(FSNode *fsNode) {
    svc_handler_t* handler = (svc_handler_t *) malloc(sizeof(svc_handler_t));
    handler->create_param = fsNode;
    handler->create_recv_handler = http_create_recv_handler;
    handler->destroy_recv_handler = http_destroy_recv_handler;
    handler->recv_handle = http_recv;

    return handler;
}

#endif //FSNODE_CDN_C_H
