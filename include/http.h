//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_HTTP_H
#define FSNODE_HTTP_H

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>

#include "map.h"
#include "utils.h"


#define HTTP_STATUS_OK                              "200"
#define HTTP_STATUS_PARTIAL_CONTENT                 "206"
#define HTTP_STATUS_BAD_REQUEST                     "400"
#define HTTP_STATUS_NOT_FOUND                       "404"
#define HTTP_STATUS_TOO_MANY_REQUESTS               "429"
#define HTTP_STATUS_INTERNAL                        "500"
#define HTTP_STATUS_SERVICE_UNAVAILABLE             "503"

#define HTTP_HEADER_HOST                            "Host"
#define HTTP_HEADER_CONTENT_RANGE                   "Content-Range"
#define HTTP_HEADER_RANGE                           "Range"
#define HTTP_HEADER_DATE                            "Date"
#define HTTP_HEADER_CONTENT_LENGTH                  "Content-Length"
#define HTTP_HEADER_CONTENT_TYPE                    "Content-Type"
#define HTTP_HEADER_AUTHORIZATION                   "Authorization"
#define HTTP_HEADER_ACCEPT_RANGES                   "Accept-Ranges"
#define HTTP_HEADER_ACCEPT_RANGES_BYTES_VALUE       "bytes"
#define HTTP_HEADER_RETRY_AFTER                     "Retry-After"

#define HTTP_VERSION_1_1                            "HTTP/1.1"

#define HTTP_METHOD_GET                             "GET"
#define HTTP_METHOD_DELETE                          "DELETE"
#define HTTP_METHOD_PUT                             "PUT"

#define HTTP_VERSION_LENGTH                         8
#define HTTP_METHOD_MAX_LENGTH                      10
#define HTTP_URI_MAX_LENGTH                         60
#define HTTP_NEWLINE                                "\r\n"
#define HTTPS_SCHEME                                "https"

#define HTTP_OBJECT_FIRST_LINE \
    char* token1;\
    char* token2;\
    char* token3;\

#define HTTP_OBJECT_FIELDS \
    bool has_content_length;\
    size_t content_length;\
    char* payload_hash;\
    Range range;\
    Map *queries;\
    Map *headers;\

typedef enum {
    range_unspecified = 0,
    range_prefix = 2,
    range_suffix = 4,
    range_full = 6
} RangeType;

typedef struct {
    RangeType type;
    int64_t offset;
    int64_t limit;
} Range;

typedef struct {
    HTTP_OBJECT_FIRST_LINE
    HTTP_OBJECT_FIELDS
} HTTPObject;

typedef enum {
    PARSE_FIRST_TOKEN = 0,
    PARSE_SECOND_TOKEN,
    PARSE_THIRD_TOKEN,

    PARSE_HEADER_NAME,
    PARSE_HEADER_VALUE,
    PARSE_BODY,
    PARSE_WRONG_SEQUENCE
} HTTPParseState;

typedef struct {
    bool is_request;
    HTTPParseState state;
    char last_char;
    char *header_name;
    HTTPObject *r;
} HTTPParser;

char * http_get_current_date();

HTTPObject *http_new_object();

void http_object_free(HTTPObject *r);

const char * http_request_method(HTTPObject *r);

void http_set_request_method(HTTPObject *r, char *method);

const char * http_request_uri(HTTPObject *r);

void http_set_request_uri(HTTPObject *r, char *uri);

void http_set_request_version(HTTPObject *r, char *version);

void http_set_response_version(HTTPObject *r, char *version);

const char * http_response_status_code(HTTPObject *r);

void http_set_response_status_code(HTTPObject *r, char *status_code);

void http_set_response_status_text(HTTPObject *r, char *status_text);

const char * http_header_get(HTTPObject *r, char *name);

void http_header_set(HTTPObject *r, char *name, char *value);

int http_parse_content_range(const char *header, Range *range);

HTTPParser *http_new_parser();

char *http_raw(HTTPObject *object);

int http_parse(HTTPParser *parser, const char *buffer, size_t data_len);

void http_parser_free(HTTPParser *parser);


#endif //FSNODE_HTTP_H
