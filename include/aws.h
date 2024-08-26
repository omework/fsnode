//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_AWS_H
#define FSNODE_AWS_H

#include <pthread.h>
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "http.h"
#include "crypto.h"
#include "utils.h"

#define HTTP_HEADER_X_AMZ_CONTENT_SHA256 "x-amz-content-sha256"
#define HTTP_HEADER_X_AMZ_DATE           "x-amz-date"

#define AWS_SIGNATURE_ALGORITHM         "AWS4-HMAC-SHA256"
#define AWS_REQUEST                     "aws4_request"
#define AWS_SERVER_AUTHORITY            "amazonaws.com"

#define AWS_S3_FILE_DOWNLOAD_BUF_SIZE   (32 * KB)
#define EMPTY_CONTENT_SHA256            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

typedef struct {
    const char *region;
    const char *service;
    const char *bucket;
    const char *access_key;
    const char *secret_key;
    pthread_mutex_t mutex;
} AWS;

typedef struct {
    HTTPParser *parser;
    size_t read;
    size_t read_result;
    size_t written;
    size_t write_result;
    FILE *file;

    BIO *bio;
    SSL *ssl;

    char *filename;
    char *tmp_filename;
    char *buf;
    int con;
} S3Downloader;

char *aws_host(AWS *aws);

char *aws_uri_encode(const char *in, bool encode_slash);

int aws_sign_v4(AWS *aws, HTTPObject* r, const char *request_payload_hash);

int verify_aws_sign_v4(AWS *aws, HTTPObject* r, bool *verify_result);

void s3_downloader_empty(S3Downloader *s3);

void s3_downloader_free(S3Downloader *s3);

int s3_download_clean(S3Downloader *s3);

#endif //FSNODE_AWS_H
