//
// Created by Jabar Karim on 25/08/2024.
//
#include "http.h"

/**
 * @brief Generates the "Date" header for an HTTP response.
 *
 * This function returns a string containing the "Date" header for an HTTP response.
 * The header is formatted according to the HTTP/1.1 specifications.
 *
 * @return A dynamically allocated string containing the "Date" header.
 *         The caller is responsible for freeing the memory.
 */
char *http_get_current_date() {
    char *date = malloc(37);
    // Get the current time
    time_t now = time(NULL);
    // Convert it to GMT (UTC) time
    struct tm *gmt = gmtime(&now);
    // Format the time according to HTTP/1.1 specifications
    // Example: Sun, 06 Nov 1994 08:49:37 GMT
    strftime(date, 37, "Date: %a, %d %b %Y %H:%M:%S GMT", gmt);
    return date;
}

/**
 * @brief Creates a new HTTPObject.
 *
 * This function allocates memory for a new HTTPObject and initializes its fields.
 * It also creates empty headers and queries maps for the object.
 *
 * @return A pointer to the newly created HTTPObject if successful, otherwise NULL.
 */
HTTPObject *http_new_object() {
    HTTPObject *r = (HTTPObject *) malloc(sizeof(HTTPObject));
    if (r != NULL) {
        r->headers = map_create();
        if (r->headers == NULL) {
            return NULL;
        }

        r->queries = map_create();
        if (r->queries == NULL) {
            map_free(r->headers);
            free(r);
            return NULL;
        }

        r->payload_hash = NULL;
        r->has_content_length = false;
        r->content_length = 0;

        http_set_request_version(r, strdup(HTTP_VERSION_1_1));
    }
    return r;
}

/**
 * @brief Free an HTTP object and its associated resources.
 *
 * This function frees the memory allocated by an HTTP object and sets all its pointers to NULL.
 *
 * @param r The HTTP object to free.
 */
void http_object_free(HTTPObject *r) {
    if (r == NULL) {
        return;
    }

    map_free(r->queries);

    map_free(r->headers);

    if (r->token1 != NULL) {
        free(r->token1);
        r->token1 = NULL;
    }

    if (r->token2 != NULL) {
        free(r->token2);
        r->token2 = NULL;
    }

    if (r->token3 != NULL) {
        free(r->token3);
        r->token3 = NULL;
    }

    if (r->payload_hash != NULL) {
        free(r->payload_hash);
        r->payload_hash = NULL;
    }
    r = NULL;
}

const char *http_request_method(HTTPObject *r) {
    return r->token1;
}

void http_set_request_method(HTTPObject *r, char *method) {
    r->token1 = method;
}

const char *http_request_uri(HTTPObject *r) {
    return r->token2;
}

void http_set_request_uri(HTTPObject *r, char *uri) {
    r->token2 = uri;
}

void http_set_request_version(HTTPObject *r, char *version) {
    r->token3 = version;
}

void http_set_response_version(HTTPObject *r, char *version) {
    r->token1 = version;
}

const char *http_response_status_code(HTTPObject *r) {
    return r->token2;
}

void http_set_response_status_code(HTTPObject *r, char *status_code) {
    r->token2 = status_code;
}

void http_set_response_status_text(HTTPObject *r, char *status_text) {
    r->token3 = status_text;
}

const char *http_header_get(HTTPObject *r, char *name) {
    return map_value(r->headers, name);
}

void http_header_set(HTTPObject *r, char *name, char *value) {
    map_set(r->headers, name, value);
}

/**
 * @brief Get the content range of an HTTP request.
 *
 * This function parses the "Range" header of an HTTP request and determines the content range specified by the client.
 * If the "Range" header is not present, it assumes the client wants the full content range.
 * The function updates the Range structure with the type, offset, and limit of the content range.
 *
 * @param r The HTTPObject representing the request.
 * @param header The string containing HTTP Range header value.
 * @param range A pointer to the Range structure to store the content range information.
 * @return 0 if successful, 1 if there was an error parsing the "Range" header.
 */
int http_parse_content_range(const char *header, Range *range) {
    const char* pos = header;
    if (pos == NULL) {
        return 0;
    }

    range->type = range_unspecified;
    range->offset = 0;
    range->limit = 0;

    while (*pos != '=') pos++;
    pos++;

    range->offset = 0;
    while (*pos != '-') {
        if (!isdigit(*pos)) {
            return 1;
        }
        range->type |= range_prefix;
        range->offset = (range->offset * 10) + (*pos - '0');
        pos++;
    }

    pos++;
    range->limit = 0;
    while (*pos != '\0') {
        if (!isdigit(*pos)) {
            return 1;
        }
        range->type |= range_suffix;
        range->limit = (range->limit * 10) + (*pos - '0');
        pos++;
    }
    return 0;
}

/**
 * Generates a raw HTTP request or response string based on the given HTTPObject.
 *
 * @param ho The HTTPObject to generate the raw string from.
 * @return A dynamically allocated string containing the raw HTTP request or response, or NULL if memory allocation fails.
 * @note The caller is responsible for freeing the returned string.
 */
char *http_raw(HTTPObject *ho) {
    char *raw = malloc(1024);
    if (raw == NULL) {
        return NULL;
    }

    char *pos = raw;

    // http first line
    pos += sprintf(pos, "%s %s %s%s", ho->token1, ho->token2, ho->token3, HTTP_NEWLINE);

    // http headers
    for (size_t i = 0; i < ho->headers->len; i++) {
        char *name = *(ho->headers->names + i);
        char *value = *(ho->headers->values + i);
        pos += sprintf(pos, "%s: %s%s", name, value, HTTP_NEWLINE);
    }

    // end of the request or body start
    sprintf(pos, HTTP_NEWLINE);
    return raw;
}

HTTPParser *http_new_parser() {
    HTTPParser *parser = (HTTPParser *) malloc(sizeof(HTTPParser));
    if (parser == NULL) {
        return NULL;
    }
    parser->state = PARSE_FIRST_TOKEN;
    parser->r = NULL;
    parser->last_char = '\0';
    return parser;
}

/**
 * @brief Parses an HTTP message from the given buffer.
 *
 * This function parses the HTTP message in the buffer and populates the HTTPObject structure
 * in the HTTPParser object. It iterates through the buffer character by character, updating
 * the state of the parser as it goes along. The parsed tokens are stored in the HTTPObject
 * structure.
 *
 * @param parser Pointer to the HTTPParser object.
 * @param buffer Pointer to the buffer containing the HTTP message.
 * @param data_len The length of the data in the buffer.
 * @return The number of bytes read from the buffer if successful, or a negative value if an error occurred.
 */
int http_parse(HTTPParser *parser, const char *buffer, size_t data_len) {
    if (parser->r == NULL) {
        parser->r = http_new_object();
        if (parser->r == NULL) {
            return -1;
        }
    }
    HTTPObject *r = parser->r;

    size_t token_len;
    const char *token_start = buffer;
    const char *pos = NULL;
    const char *end = buffer + data_len;

    for (pos = buffer; pos != end && parser->state != PARSE_BODY; pos++) {
        token_len = pos - token_start;

        if (parser->state == PARSE_FIRST_TOKEN && (*pos == ' ' || token_len > HTTP_METHOD_MAX_LENGTH)) {
            if (token_len > HTTP_METHOD_MAX_LENGTH) {
                parser->state = PARSE_WRONG_SEQUENCE;
                return 1;
            }

            r->token1 = strndup(token_start, token_len);
            token_start = pos + 1;

            parser->is_request = strncmp(r->token1, HTTP_VERSION_1_1, token_len);
            parser->state = PARSE_SECOND_TOKEN;
            parser->last_char = *pos;
            continue;
        }

        if (parser->state == PARSE_SECOND_TOKEN && (*pos == ' ' || token_len > HTTP_URI_MAX_LENGTH)) {
            if (parser->is_request && token_len > HTTP_URI_MAX_LENGTH) {
                parser->state = PARSE_WRONG_SEQUENCE;
                return 1;
            }

            r->token2 = strndup(token_start, token_len);
            token_start = pos + 1;
            parser->state = PARSE_THIRD_TOKEN;
            parser->last_char = *pos;
            continue;
        }

        if (parser->state == PARSE_THIRD_TOKEN &&
            (*pos == '\n' || (parser->is_request && token_len > HTTP_VERSION_LENGTH))) {
            if ((parser->is_request && token_len > HTTP_VERSION_LENGTH + 1)) {
                parser->state = PARSE_WRONG_SEQUENCE;
                return 1;
            }

            if (*pos == '\n' && parser->last_char != '\r') {
                parser->state = PARSE_WRONG_SEQUENCE;
                return 1;
            }

            parser->last_char = '\0';
            if (parser->is_request && strncmp(token_start, HTTP_VERSION_1_1, token_len - 1) != 0) {
                parser->state = PARSE_WRONG_SEQUENCE;
                return 1;
            }

            r->token3 = strndup(token_start, token_len - 1);
            token_start = pos + 1;
            parser->state = PARSE_HEADER_NAME;
            parser->last_char = *pos;
            continue;
        }

        if (parser->state == PARSE_HEADER_NAME) {
            if (*pos == '\n') {
                if (parser->last_char != '\r') {
                    parser->state = PARSE_WRONG_SEQUENCE;
                }

                token_start = pos + 1;
                parser->state = PARSE_BODY;
                continue;
            } else if (*pos == ':') {
                parser->header_name = strndup(token_start, token_len);
                parser->last_char = *pos;
                token_start = pos + 1;
                parser->state = PARSE_HEADER_VALUE;
            }

            parser->last_char = *pos;
            continue;
        }

        if (parser->state == PARSE_HEADER_VALUE && *pos == '\n') {
            if (parser->last_char != '\r') {
                parser->state = PARSE_WRONG_SEQUENCE;
                continue;
            }

            char *value = strndup(token_start, token_len - 1);
            if (value == NULL) {
                return -1;
            }

            char *trimmed = trim(value);
            free(value);

            if (trimmed == NULL) {
                return -1;
            }
            http_header_set(r, parser->header_name, trimmed);
            if (strcasecmp(parser->header_name, HTTP_HEADER_CONTENT_LENGTH) == 0) {
                parser->r->has_content_length = str_to_size_t(trimmed, &parser->r->content_length) == 0;
            } else if (strcasecmp(parser->header_name, HTTP_HEADER_RANGE) == 0) {
                if (http_parse_content_range(trimmed, &parser->r->range) != 0) {
                    return -1;
                }
            }
            parser->header_name = NULL;
            parser->state = PARSE_HEADER_NAME;
            parser->last_char = *pos;
            token_start = pos + 1;
            continue;
        }
        parser->last_char = *pos;
    }

    int read = (int) (pos - buffer);
    return read;
}

void http_parser_free(HTTPParser *parser) {
    if (parser == NULL) {
        return;
    }

    if (parser->header_name != NULL) {
        free(parser->header_name);
        parser->header_name = NULL;
    }

    if (parser->r != NULL) {
        http_object_free(parser->r);
        parser->r = NULL;
    }

    parser = NULL;
}