//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_AWS_C_H
#define FSNODE_AWS_C_H

#include "aws.h"

/**
 * @brief Generate the host for AWS service.
 *
 * This function constructs the host for the AWS service by concatenating the bucket,
 * service, and server authority using the format "<bucket>.<service>.<server_authority>".
 *
 * @param aws A pointer to the AWS structure containing the necessary information.
 * @return A dynamically allocated string containing the constructed host.
 *
 * @note The returned string must be freed by the caller after use to avoid memory leaks.
 */
char *aws_host(AWS *aws) {
    size_t size = strlen(aws->service) + strlen(aws->bucket) + strlen(AWS_SERVER_AUTHORITY) + 3;
    char *host = malloc(size);
    if (host == NULL) {
        return NULL;
    }
    snprintf(host, size, "%s.%s.%s", aws->bucket, aws->service, AWS_SERVER_AUTHORITY);
    return host;
}

/**
 * @brief Encodes a URI string according to AWS URI encoding rules.
 *
 * This function takes an input string and encodes it according to the URI encoding
 * rules specified by Amazon Web Services (AWS). It supports the encoding of all
 * alphanumeric characters, as well as the characters '-', '_', '.', and '~'. The
 * forward slash character ('/') is encoded as '%2F' if the `encode_slash` parameter
 * is set to `true`, otherwise it is preserved as is. All other characters are
 * percent-encoded using the hexadecimal representation of their ASCII value.
 *
 * @param[in] in The input string to be encoded.
 * @param[in] encode_slash Determines whether to encode the forward slash character.
 * @return The encoded URI string. The caller is responsible for freeing the memory
 * allocated for the returned string.
 */
char *aws_uri_encode(const char *in, bool encode_slash) {
    const char *hex = "0123456789ABCDEF";
    char *output = malloc((strlen(in) * 3 + 1)); // Maximum size needed
    if (output == NULL) {
        return NULL;
    }

    char *ptr = output;
    while (*in) {
        if (isalnum((unsigned char) *in) || *in == '-' || *in == '_' || *in == '.' || *in == '~') {
            *ptr++ = *in;
        } else if (*in == '/') {
            if (encode_slash) {
                *ptr++ = '%';
                *ptr++ = '2';
                *ptr++ = 'F';
            } else {
                *ptr++ = *in;
            }
        } else {
            *ptr++ = '%';
            *ptr++ = hex[(unsigned char) *in >> 4];
            *ptr++ = hex[(unsigned char) *in & 0x0F];
        }
        in++;
    }
    *ptr = '\0';
    return output;
}

/**
 * Signs a request using AWS Signature Version 4.
 *
 * @param aws The AWS configuration containing region, service, bucket, access key, and secret key.
 * @param r The HTTPObject representing the request to be signed.
 * @param request_payload_hash The hash of the request payload.
 * @return Returns 0 on success, 1 on failure.
 */
int aws_sign_v4(AWS *aws, HTTPObject *r, const char *request_payload_hash) {
    if (request_payload_hash == NULL || strlen(request_payload_hash) == 0) {
        return 1;
    }

    time_t t = time(NULL);
    pthread_mutex_lock(&aws->mutex);
    struct tm *time = gmtime(&t);
    pthread_mutex_unlock(&aws->mutex);

    /*
    time = malloc(sizeof(struct tm));
    char date_string[] = "20130524T000000Z";
    strptime(date_string, "%Y%m%dT%H%M%SZ", time);*/


    char *date = date_from_time(time);
    if (date == NULL) {
        return 1;
    }

    char *iso_time = iso8601_date_from_time(time);
    if (iso_time == NULL) {
        free(date);
        return 1;
    }

    http_header_set(r, strdup(HTTP_HEADER_X_AMZ_CONTENT_SHA256), strdup(EMPTY_CONTENT_SHA256));
    http_header_set(r, strdup(HTTP_HEADER_X_AMZ_DATE), strdup(iso_time));

    char *canonical_request = (char *) calloc(1024, sizeof(char));
    if (canonical_request == NULL) {
        free(date);
        return 1;
    }

    strcpy(canonical_request, http_request_method(r));
    strcat(canonical_request, "\n");

    char *encoded_uri = aws_uri_encode(http_request_uri(r), false);
    if (encoded_uri == NULL) {
        free(date);
        free(iso_time);
        free(canonical_request);
        return 1;
    }
    strcat(canonical_request, encoded_uri);
    free(encoded_uri);
    strcat(canonical_request, "\n");

    for (size_t i = 0; i < r->queries->len; i++) {
        char *param = aws_uri_encode(r->queries->names[i], true);
        if (param == NULL) {
            free(date);
            free(iso_time);
            free(canonical_request);
            return 1;
        }
        char *value = aws_uri_encode(r->queries->values[i], true);
        if (value == NULL) {
            free(date);
            free(iso_time);
            free(param);
            free(canonical_request);
            return 1;
        }

        strcat(canonical_request, param);
        strcat(canonical_request, "=");
        strcat(canonical_request, value);
        if (i < r->queries->len - 1) {
            strcat(canonical_request, "&");
        }
        free(param);
        free(value);
    }
    strcat(canonical_request, "\n");

    for (size_t i = 0; i < r->headers->len; i++) {
        const char *header = r->headers->names[i];
        if (strcmp(HTTP_HEADER_AUTHORIZATION, header) == 0) {
            continue;
        }

        char *name = toLower(header);
        if (name == NULL) {
            free(date);
            free(iso_time);
            free(canonical_request);
            return 1;
        }

        char *value = trim(r->headers->values[i]);
        if (value == NULL) {
            free(date);
            free(iso_time);
            free(name);
            free(canonical_request);
            return 1;
        }

        strcat(canonical_request, name);
        strcat(canonical_request, ":");
        strcat(canonical_request, value);
        strcat(canonical_request, "\n");
        free(name);
        free(value);
    }
    strcat(canonical_request, "\n");

    for (size_t i = 0; i < r->headers->len; i++) {
        const char *header = r->headers->names[i];
        if (strcmp(HTTP_HEADER_AUTHORIZATION, header) == 0) {
            continue;
        }

        char *name = toLower(header);
        if (name == NULL) {
            free(date);
            free(iso_time);
            free(canonical_request);
            return 1;
        }

        strcat(canonical_request, name);
        if (i < r->headers->len - 1) {
            strcat(canonical_request, ";");
        }
        free(name);
    }
    strcat(canonical_request, "\n");
    strcat(canonical_request, request_payload_hash);

    //printf("\nCANONICAL REQUEST:\n%s\n", canonical_request);
    size_t canonical_request_len = strlen(canonical_request);

    char *canonical_request_hash;
    size_t canonical_request_hash_len;
    int sha256_result = sha256(canonical_request, canonical_request_len, &canonical_request_hash,
                               &canonical_request_hash_len);
    free(canonical_request);
    if (sha256_result != 0) {
        if (canonical_request_hash != NULL) {
            free(canonical_request_hash);
        }
        return 1;
    }

    char *canonical_request_hash_hex = hex(canonical_request_hash, canonical_request_hash_len);
    free(canonical_request_hash);
    if (canonical_request_hash_hex == NULL) {
        return 1;
    }

    // StringToSign
    char *str_to_sign = calloc(512, sizeof(char));
    if (str_to_sign == NULL) {
        free(canonical_request_hash_hex);
        return 1;
    }

    strcpy(str_to_sign, AWS_SIGNATURE_ALGORITHM);
    strcat(str_to_sign, "\n");
    strcat(str_to_sign, iso_time);
    strcat(str_to_sign, "\n");
    free(iso_time);

    strcat(str_to_sign, date);
    strcat(str_to_sign, "/");
    strcat(str_to_sign, aws->region);
    strcat(str_to_sign, "/");
    strcat(str_to_sign, aws->service);
    strcat(str_to_sign, "/");
    strcat(str_to_sign, AWS_REQUEST);
    strcat(str_to_sign, "\n");
    strcat(str_to_sign, canonical_request_hash_hex);
    free(canonical_request_hash_hex);

    // printf("\nStringToSign:\n%s\n", str_to_sign);
    // Signing key

    char *first_key = calloc(strlen("AWS4") + strlen(aws->secret_key) + 1, sizeof(char));
    if (first_key == NULL) {
        free(date);
        free(str_to_sign);
        return 1;
    }
    strcpy(first_key, "AWS4");
    strcat(first_key, aws->secret_key);

    char *date_key;
    size_t date_key_len;
    hmac_sha256(first_key, strlen(first_key), date, strlen(date), &date_key, &date_key_len);
    free(first_key);

    char *date_region_key;
    size_t date_region_key_len;
    hmac_sha256(date_key, date_key_len, aws->region, strlen(aws->region), &date_region_key, &date_region_key_len);
    free(date_key);

    char *date_region_service_key;
    size_t date_region_service_key_len;
    hmac_sha256(date_region_key, date_region_key_len, aws->service, strlen(aws->service), &date_region_service_key,
                &date_region_service_key_len);
    free(date_region_key);

    char *signing_key;
    size_t signing_key_len;
    hmac_sha256(date_region_service_key, date_region_service_key_len, AWS_REQUEST, strlen(AWS_REQUEST), &signing_key,
                &signing_key_len);
    free(date_region_service_key);

    char *signature;
    size_t signature_len;
    hmac_sha256(signing_key, signing_key_len, str_to_sign, strlen(str_to_sign), &signature, &signature_len);
    free(str_to_sign);
    free(signing_key);

    char *signature_hex = hex(signature, signature_len);
    free(signature);

    // authorization header
    char *authorization = (char *) calloc(256, sizeof(char));
    if (authorization == NULL) {
        free(date);
        free(signature_hex);
        return 1;
    }

    strcpy(authorization, AWS_SIGNATURE_ALGORITHM);
    strcat(authorization, " Credential=");
    strcat(authorization, aws->access_key);
    strcat(authorization, "/");
    strcat(authorization, date);
    free(date);
    strcat(authorization, "/");
    strcat(authorization, aws->region);
    strcat(authorization, "/");
    strcat(authorization, aws->service);
    strcat(authorization, "/");
    strcat(authorization, AWS_REQUEST);
    strcat(authorization, ",SignedHeaders=");
    for (size_t i = 0; i < r->headers->len; i++) {
        const char *name = r->headers->names[i];
        if (strcmp(HTTP_HEADER_AUTHORIZATION, name) == 0) continue;
        char *lowercase_name = toLower(name);
        strcat(authorization, lowercase_name);
        if (i < r->headers->len - 1) strcat(authorization, ";");
    }
    strcat(authorization, ",Signature=");
    strcat(authorization, signature_hex);

    free(signature_hex);

    http_header_set(r, strdup(HTTP_HEADER_AUTHORIZATION), authorization);
    return 0;
}

/**
 * Verify the AWS Signature Version 4 of the request using a provided config.
 *
 * @param aws The AWS configuration containing region, service, bucket, access key, and secret key.
 * @param r The HTTPObject representing the request to be signed.
 * @param request_payload_hash The hash of the request payload.
 * @return Returns 0 on success, 1 on failure.
 */
int verify_aws_sign_v4(AWS *aws, HTTPObject* r, bool *verify_result) {
    const char * request_payload_hash = http_header_get(r, strdup(HTTP_HEADER_X_AMZ_CONTENT_SHA256));
    if (request_payload_hash == NULL) {
        *verify_result = false;
        return 0;
    }

    const char * iso_time = http_header_get(r, strdup(HTTP_HEADER_X_AMZ_DATE));
    if (iso_time == NULL) {
        *verify_result = false;
        return 0;
    }

    struct tm time;
    parse_iso8601_date(iso_time, &time);

    char *date = date_from_time(&time);
    if (date == NULL) {
        return 1;
    }


    char *canonical_request = (char *) calloc(1024, sizeof(char));
    if (canonical_request == NULL) {
        free(date);
        return 1;
    }

    strcpy(canonical_request, http_request_method(r));
    strcat(canonical_request, "\n");

    char *encoded_uri = aws_uri_encode(http_request_uri(r), false);
    if (encoded_uri == NULL) {
        free(date);
        free(canonical_request);
        return 1;
    }
    strcat(canonical_request, encoded_uri);
    free(encoded_uri);
    strcat(canonical_request, "\n");

    for (size_t i = 0; i < r->queries->len; i++) {
        char *param = aws_uri_encode(r->queries->names[i], true);
        if (param == NULL) {
            free(date);
            free(canonical_request);
            return 1;
        }
        char *value = aws_uri_encode(r->queries->values[i], true);
        if (value == NULL) {
            free(date);
            free(param);
            free(canonical_request);
            return 1;
        }

        strcat(canonical_request, param);
        strcat(canonical_request, "=");
        strcat(canonical_request, value);
        if (i < r->queries->len - 1) {
            strcat(canonical_request, "&");
        }
        free(param);
        free(value);
    }
    strcat(canonical_request, "\n");

    for (size_t i = 0; i < r->headers->len; i++) {
        const char *header = r->headers->names[i];
        if (strcmp(HTTP_HEADER_AUTHORIZATION, header) == 0) {
            continue;
        }

        char *name = toLower(header);
        if (name == NULL) {
            free(date);
            free(canonical_request);
            return 1;
        }

        char *value = trim(r->headers->values[i]);
        if (value == NULL) {
            free(date);
            free(name);
            free(canonical_request);
            return 1;
        }

        strcat(canonical_request, name);
        strcat(canonical_request, ":");
        strcat(canonical_request, value);
        strcat(canonical_request, "\n");
        free(name);
        free(value);
    }
    strcat(canonical_request, "\n");

    for (size_t i = 0; i < r->headers->len; i++) {
        const char *header = r->headers->names[i];
        if (strcmp(HTTP_HEADER_AUTHORIZATION, header) == 0) {
            continue;
        }

        char *name = toLower(header);
        if (name == NULL) {
            free(date);
            free(canonical_request);
            return 1;
        }

        strcat(canonical_request, name);
        if (i < r->headers->len - 1) {
            strcat(canonical_request, ";");
        }
        free(name);
    }
    strcat(canonical_request, "\n");
    strcat(canonical_request, request_payload_hash);

    //printf("\nCANONICAL REQUEST:\n%s\n", canonical_request);
    size_t canonical_request_len = strlen(canonical_request);

    char *canonical_request_hash;
    size_t canonical_request_hash_len;
    int sha256_result = sha256(canonical_request, canonical_request_len, &canonical_request_hash,
                               &canonical_request_hash_len);
    free(canonical_request);
    if (sha256_result != 0) {
        if (canonical_request_hash != NULL) {
            free(canonical_request_hash);
        }
        return 1;
    }

    char *canonical_request_hash_hex = hex(canonical_request_hash, canonical_request_hash_len);
    free(canonical_request_hash);
    if (canonical_request_hash_hex == NULL) {
        return 1;
    }

    // StringToSign
    char *str_to_sign = calloc(512, sizeof(char));
    if (str_to_sign == NULL) {
        free(canonical_request_hash_hex);
        return 1;
    }

    strcpy(str_to_sign, AWS_SIGNATURE_ALGORITHM);
    strcat(str_to_sign, "\n");
    strcat(str_to_sign, iso_time);
    strcat(str_to_sign, "\n");

    strcat(str_to_sign, date);
    strcat(str_to_sign, "/");
    strcat(str_to_sign, aws->region);
    strcat(str_to_sign, "/");
    strcat(str_to_sign, aws->service);
    strcat(str_to_sign, "/");
    strcat(str_to_sign, AWS_REQUEST);
    strcat(str_to_sign, "\n");
    strcat(str_to_sign, canonical_request_hash_hex);
    free(canonical_request_hash_hex);

    // printf("\nStringToSign:\n%s\n", str_to_sign);
    // Signing key

    char *first_key = calloc(strlen("AWS4") + strlen(aws->secret_key) + 1, sizeof(char));
    if (first_key == NULL) {
        free(date);
        free(str_to_sign);
        return 1;
    }
    strcpy(first_key, "AWS4");
    strcat(first_key, aws->secret_key);

    char *date_key;
    size_t date_key_len;
    hmac_sha256(first_key, strlen(first_key), date, strlen(date), &date_key, &date_key_len);
    free(first_key);

    char *date_region_key;
    size_t date_region_key_len;
    hmac_sha256(date_key, date_key_len, aws->region, strlen(aws->region), &date_region_key, &date_region_key_len);
    free(date_key);

    char *date_region_service_key;
    size_t date_region_service_key_len;
    hmac_sha256(date_region_key, date_region_key_len, aws->service, strlen(aws->service), &date_region_service_key,
                &date_region_service_key_len);
    free(date_region_key);

    char *signing_key;
    size_t signing_key_len;
    hmac_sha256(date_region_service_key, date_region_service_key_len, AWS_REQUEST, strlen(AWS_REQUEST), &signing_key,
                &signing_key_len);
    free(date_region_service_key);

    char *signature;
    size_t signature_len;
    hmac_sha256(signing_key, signing_key_len, str_to_sign, strlen(str_to_sign), &signature, &signature_len);
    free(str_to_sign);
    free(signing_key);

    char *signature_hex = hex(signature, signature_len);
    free(signature);

    // authorization header
    char *authorization = (char *) calloc(256, sizeof(char));
    if (authorization == NULL) {
        free(date);
        free(signature_hex);
        return 1;
    }

    strcpy(authorization, AWS_SIGNATURE_ALGORITHM);
    strcat(authorization, " Credential=");
    strcat(authorization, aws->access_key);
    strcat(authorization, "/");
    strcat(authorization, date);
    free(date);
    strcat(authorization, "/");
    strcat(authorization, aws->region);
    strcat(authorization, "/");
    strcat(authorization, aws->service);
    strcat(authorization, "/");
    strcat(authorization, AWS_REQUEST);
    strcat(authorization, ",SignedHeaders=");
    for (size_t i = 0; i < r->headers->len; i++) {
        const char *name = r->headers->names[i];
        if (strcmp(HTTP_HEADER_AUTHORIZATION, name) == 0) continue;
        char *lowercase_name = toLower(name);
        strcat(authorization, lowercase_name);
        if (i < r->headers->len - 1) strcat(authorization, ";");
    }
    strcat(authorization, ",Signature=");
    strcat(authorization, signature_hex);

    free(signature_hex);

    *verify_result = strcmp(http_header_get(r, strdup(HTTP_HEADER_AUTHORIZATION)), authorization) == 0;
    return 0;
}

void s3_downloader_empty(S3Downloader *s3) {
    s3->tmp_filename = NULL;
    s3->filename = NULL;
    s3->file = NULL;
    s3->parser = NULL;
    s3->ssl = NULL;
    s3->buf = NULL;
    s3->bio = NULL;
    s3->con = 0;
    s3->tmp_filename = NULL;
}

/**
 * @brief Frees the memory allocated for the S3Downloader object and its associated resources.
 *
 * @param s3 The S3Downloader object to be freed.
 */
void s3_downloader_free(S3Downloader *s3) {
    if (s3->file != NULL) {
        fclose(s3->file);
        s3->file = NULL;
    }

    if (s3->buf != NULL) {
        free(s3->buf);
        s3->buf = NULL;
    }

    if (s3->parser != NULL) {
        http_parser_free(s3->parser);
        s3->parser = NULL;
    }

    if (s3->tmp_filename != NULL) {
        free(s3->tmp_filename);
        s3->tmp_filename = NULL;
    }

    if (s3->filename != NULL) {
        free(s3->filename);
        s3->filename = NULL;
    }

    if (s3->bio != NULL) {
        BIO_free_all(s3->bio);
        s3->bio = NULL;
    } else if (s3->ssl != NULL) {
        SSL_free(s3->ssl);
    }

    if (s3->con > 0) {
        close(s3->con);
        s3->con = 0;
    }
}

/**
 * @brief Cleans up and finalizes a download from S3.
 *
 * This function renames the temporary handle to the final filename if the SSL error code
 * is either SSL_ERROR_NONE or SSL_ERROR_ZERO_RETURN. It then frees all resources used
 * by the S3Downloader object and returns the result of the rename operation.
 *
 * @param s3 The S3Downloader object to clean up and finalize.
 * @return 0 if the rename operation was successful, or a non-zero value if an error occurred.
 */
int s3_download_clean(S3Downloader *s3) {
    int result = 0;
    int code = SSL_get_error(s3->ssl, (int) s3->read_result);
    if (code == SSL_ERROR_NONE || code == SSL_ERROR_ZERO_RETURN) {
        result = rename(s3->tmp_filename, s3->filename);
    }
    s3_downloader_free(s3);
    return result;
}


#endif //FSNODE_AWS_C_H
