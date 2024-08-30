//
// Created by Jabar Karim on 25/08/2024.
//

#include "fsnode.h"

duckdb_timestamp db_timestamp_from_time(struct tm *tm) {
    duckdb_timestamp_struct ts;
    ts.date.year = tm->tm_year + 1900;
    ts.date.month = (int8_t) (tm->tm_mon + 1);
    ts.date.day = (int8_t) tm->tm_mday;

    ts.time.hour = (int8_t) tm->tm_hour;
    ts.time.min = (int8_t) tm->tm_min;
    ts.time.sec = (int8_t) tm->tm_sec;
    return duckdb_to_timestamp(ts);
}

bool fs_node_set_env_var(void *container, env_var_t var) {
    FSNode *node = (FSNode *) container;

    if (strcmp(var.name, ENV_DISK_DIR) == 0) {
        node->disk->dir = strdup(var.value);
        return strlen(var.value) > 0;
    }

    if (strcmp(var.name, ENV_DISK_SPACE) == 0) {
        node->disk->capacity = 0;
        return parse_size(var.value, &node->disk->capacity) == 0;
    }

    if (strcmp(var.name, ENV_DISK_SPACE_GAP) == 0) {
        node->disk->gap = 0;
        return parse_size(var.value, &node->disk->gap) == 0;
    }

    if (strcmp(var.name, ENV_PORT) == 0) {
        char *res;
        node->info->port = (uint16_t) strtol(var.value, &res, 10);
        return node->info->port > 0;
    }

    if (strcmp(var.name, ENV_HOST) == 0) {
        node->info->host = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_NODE_NAME) == 0) {
        node->info->name = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_CERT_FILE) == 0) {
        node->info->cert_file = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_KEY_FILE) == 0) {
        node->info->key_file = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_CA_CERT_FILE) == 0) {
        node->info->ca_cert_file = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_REGISTRY_HOST) == 0) {
        node->registry->host = strdup(var.value);
        return strlen(var.value) > 0;
    }

    if (strcmp(var.name, ENV_REGISTRY_PORT) == 0) {
        node->registry->port = strdup(var.value);
        return strlen(var.value) > 0;
    }

    if (strcmp(var.name, ENV_REGISTRY_CERT) == 0) {
        node->registry->cert = strdup(var.value);
        return strlen(var.value) > 0;
    }

    if (strcmp(var.name, ENV_REGISTRY_ACCESS_KEY) == 0) {
        node->registry->access_key = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_REGISTRY_SECRET_KEY) == 0) {
        node->registry->secret_key = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_API_ACCESS_KEY) == 0) {
        node->info->api_access_key = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_API_SECRET_KEY) == 0) {
        node->info->api_secret_key = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_AWS_SERVICE) == 0) {
        node->aws->service = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_AWS_REGION) == 0) {
        node->aws->region = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_AWS_S3_BUCKET) == 0) {
        node->aws->bucket = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_AWS_ACCESS_KEY) == 0) {
        node->aws->access_key = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    if (strcmp(var.name, ENV_AWS_SECRET_KEY) == 0) {
        node->aws->secret_key = strdup(var.value);
        bool result = strlen(var.value) > 0;
        if (!result) {
            dzlog_error("env var %s should not be empty", var.name);
        }
        return result;
    }

    return true;
}

FSNode *fs_node_new() {
    FSNode *node = (FSNode *) malloc(sizeof(FSNode));
    if (node == NULL) {
        return NULL;
    }

    // init fields
    node->info = (Node *) malloc(sizeof(Node));
    if (node->info == NULL) {
        free(node->info);
        return NULL;
    }

    node->registry = (Registry *) calloc(1, sizeof(Registry));
    if (node->registry == NULL) {
        free(node->info);
        free(node);
        return NULL;
    }

    node->disk = (Disk *) malloc(sizeof(Disk));
    if (node->disk == NULL) {
        free(node->registry);
        free(node->info);
        free(node);
        return NULL;
    }

    node->aws = (AWS *) malloc(sizeof(AWS));
    if (node->aws == NULL) {
        free(node->disk);
        free(node->registry);
        free(node->info);
        free(node);
        return NULL;
    }
    pthread_mutex_init(&node->aws->mutex, NULL);

    node->downloads = (Downloads *) malloc(sizeof(Downloads));
    if (node->downloads == NULL) {
        free(node->aws);
        free(node->disk);
        free(node->registry);
        free(node->info);
        free(node);
        return NULL;
    }

    node->downloads->files = (FileDownload **) calloc(MAX_S3_DOWNLOAD_SLOT_NUMBER, sizeof(FileDownload *));
    if (node->downloads->files == NULL) {
        free(node->downloads);
        free(node->aws);
        free(node->disk);
        free(node->registry);
        free(node->info);
        free(node);
        return NULL;
    }

    pthread_mutex_init(&node->downloads->mutex, NULL);
    pthread_mutex_init(&node->s3_mutex, NULL);
    pthread_mutex_init(&node->prune_mutex, NULL);
    return node;
}

int fs_node_init(FSNode *node) {
    node->magic_cookie = magic_open(MAGIC_MIME);
    if (node->magic_cookie == NULL || magic_load(node->magic_cookie, NULL) != 0) {
        magic_close(node->magic_cookie);
        return 1;
    }

    node->s3_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_session_cache_mode(node->s3_ssl_ctx, SSL_SESS_CACHE_CLIENT);  // Enable client-side caching
    SSL_CTX_sess_set_cache_size(node->s3_ssl_ctx, 2048);

    node->registry->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (attach_ca_cert_to_ssl_context(&node->registry->ssl_ctx, "ca.crt") != 0) {
        fs_node_free(node);
        return 1;
    }


    SSL_CTX_set_session_cache_mode(node->registry->ssl_ctx, SSL_SESS_CACHE_CLIENT);  // Enable client-side caching
    SSL_CTX_sess_set_cache_size(node->registry->ssl_ctx, 10);

    // check data directory
    struct stat info;
    if (stat(node->disk->dir, &info) != 0 || (info.st_mode & S_IFDIR) == 0) {
        return 1;
    }

    // Database
    if (duckdb_open(FS_NODE_DB_NAME, &node->db) == DuckDBError) {
        magic_close(node->magic_cookie);
        return 1;
    }

    if (duckdb_connect(node->db, &node->db_con) == DuckDBError) {
        duckdb_close(&node->db);
        magic_close(node->magic_cookie);
        return 1;
    }

    // create a table
    duckdb_state state = duckdb_query(node->db_con, FS_NODE_READ_RECORDS_TABLE, NULL);
    if (state == DuckDBError) {
        magic_close(node->magic_cookie);
        fs_node_free(node);
        return 1;
    }

    return 0;
}

void fs_node_free(FSNode *node) {
    if (node == NULL) {
        return;
    }

    duckdb_disconnect(&node->db_con);
    duckdb_close(&node->db);

    if (node->magic_cookie != NULL) {
        magic_close(node->magic_cookie);
        node->magic_cookie = NULL;
    }

    if (node->disk != NULL) {
        if (node->disk->dir != NULL) free(node->disk->dir);
        if (node->info->host != NULL) free(node->info->host);
        free(node->disk);
        node->disk = NULL;
    }

    if (node->info != NULL) {
        if (node->info->name != NULL) free(node->info->name);
        if (node->info->api_access_key != NULL) free(node->info->api_access_key);
        if (node->info->api_secret_key != NULL) free(node->info->api_secret_key);
        if (node->info->cert_file != NULL) free(node->info->cert_file);
        if (node->info->key_file != NULL) free(node->info->key_file);
        if (node->info->ca_cert_file != NULL) free(node->info->ca_cert_file);

        free(node->info);
        node->info = NULL;
    }

    if (node->aws != NULL) {
        if (node->aws->region != NULL) free((char *) node->aws->region);
        if (node->aws->service != NULL) free((char *) node->aws->service);
        if (node->aws->bucket != NULL) free((char *) node->aws->bucket);
        if (node->aws->access_key != NULL) free((char *) node->aws->access_key);
        if (node->aws->secret_key != NULL) free((char *) node->aws->secret_key);
        pthread_mutex_destroy(&node->aws->mutex);
        free(node->aws);
        node->aws = NULL;
    }

    if (node->downloads != NULL) {
        free(node->downloads->files);
        pthread_mutex_destroy(&node->downloads->mutex);
        free(node->downloads);
        node->downloads = NULL;
    }

    if (node->s3_ssl_ctx != NULL) {
        pthread_mutex_destroy(&node->s3_mutex);
        SSL_CTX_free(node->s3_ssl_ctx);
        node->s3_ssl_ctx = NULL;
    }

    if (node->registry != NULL) {
        if (node->registry->cert != NULL) {
            free(node->registry->cert);
        }
        node->registry->cert = NULL;

        if (node->registry->host != NULL) {
            free(node->registry->host);
        }
        node->registry->host = NULL;
    }

    node = NULL;
}

char *fs_node_info_to_json(FSNode *node) {
    json_t *root = json_object();
    json_object_set_new(root, "name", json_string(node->info->name));
    json_object_set_new(root, "type", json_integer(1));
    json_object_set_new(root, "host", json_string(node->info->host));
    json_object_set_new(root, "port", json_integer((json_int_t) node->info->port));
    json_object_set_new(root, "disk_capacity", json_integer((json_int_t) node->disk->capacity));
    json_object_set_new(root, "disk_usage", json_integer((json_int_t) node->disk->usage));
    char *str = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    return str;
}

/**
 * @brief Retrieves the names of the oldest files from the given FSNode and stores them in a List.
 *
 * This function queries the given FSNode's database connection for the oldest files using the
 * FS_NODE_SELECT_OLD_FILES_QUERY. It then retrieves the filenames from the query result and stores
 * them in the provided List.
 *
 * @param node The FSNode object to retrieve the oldest file names from.
 * @param names The List to store the oldest file names in.
 * @return 0 if successful, 1 if an error occurs.
 */
int fs_node_get_oldest_file_from_registry(FSNode *node, List *names) {
    duckdb_result result;
    duckdb_state state = duckdb_query(node->db_con, FS_NODE_SELECT_OLD_FILES_QUERY, &result);
    if (state == DuckDBError) {
        return 1;
    }

    char **filenames = (char **) duckdb_column_data(&result, 0);
    idx_t row_count = duckdb_row_count(&result);

    list_grow(names, row_count);
    for (size_t row = 0; row < row_count; row++) {
        list_add(names, strdup(filenames[row]));
    }
    duckdb_destroy_result(&result);
    return 0;
}

/**
 * Deletes a file from the file registry of a given FSNode.
 *
 * @param node      Pointer to the FSNode structure representing the file system node.
 * @param filename  Pointer to the name of the file to be deleted from the registry.
 * @return          0 on success, 1 on failure.
 */
int fs_node_delete_file_from_registry(FSNode *node, const char *filename) {
    duckdb_prepared_statement stmt;
    duckdb_state state = duckdb_prepare(node->db_con, FS_NODE_DELETE_FILENAME_QUERY, &stmt);
    if (state == DuckDBError) {
        return 1;
    }

    if (duckdb_bind_varchar(stmt, 1, filename) == DuckDBError) {
        duckdb_destroy_prepare(&stmt);
        return 1;
    }
    state = duckdb_execute_prepared(stmt, NULL);
    duckdb_destroy_prepare(&stmt);
    return state;
}

/**
 * Registers a file read record in the database for the given FSNode with the specified filename.
 *
 * @param node The FSNode for which to register the file read record.
 * @param filename The filename of the file to register the read record for.
 * @return Returns 0 if the file read record was successfully registered, or 1 if an error occurred.
 */
int fs_node_register_file_read_record(FSNode *node, const char *filename) {
    duckdb_prepared_statement stmt;
    duckdb_state state = duckdb_prepare(node->db_con, FS_NODE_INSERT_READ_RECORD_QUERY, &stmt);
    if (state == DuckDBError) {
        return 1;
    }

    if (duckdb_bind_varchar(stmt, 1, filename) == DuckDBError) {
        duckdb_destroy_prepare(&stmt);
        return 1;
    }

    if (duckdb_execute_prepared(stmt, NULL) == DuckDBError) {
        return 1;
    }

    duckdb_destroy_prepare(&stmt);
    return 0;
}

/**
 * @brief Calculates the total disk usage of a directory.
 *
 * This function calculates the total size in bytes of all the files within a given directory,
 * including files in subdirectories.
 *
 * @param root_dir The root directory to calculate disk usage for.
 * @param[out] out_size A pointer to a uint64_t variable to store the total disk usage in bytes.
 * @return If the operation was successful, the function returns 0. Otherwise, it returns a positive
 *         integer indicating an error.
 */
int fs_node_get_disk_usage(const char *root_dir, uint64_t *out_size) {
    uint64_t total_size = 0;
    struct dirent *entry;
    struct stat sb;

    List *dir_paths = list_create();
    list_add(dir_paths, strdup(root_dir));

    char path[PATH_MAX];
    while (dir_paths->len > 0) {
        char *dir_path = list_pop(dir_paths);
        DIR *dir = opendir(dir_path);

        while ((entry = readdir(dir)) != NULL) {
            sprintf(path, "%s/%s", dir_path, entry->d_name);
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            if (entry->d_type == DT_DIR) {
                list_add(dir_paths, strdup(path));
                continue;
            }

            if (lstat(path, &sb) == -1) {
                closedir(dir);
                free(dir_path);
                list_free(dir_paths);
                return 1;
            }
            total_size += sb.st_size;
        }
        free(dir_path);
        closedir(dir);
    }

    list_free(dir_paths);
    *out_size = total_size;
    return 0;
}

/**
 * @brief Initializes the S3 downloader for the given FSNode.
 *
 * This function initializes the S3 downloader by performing the necessary steps for establishing
 * a connection to the S3 host. It sets up the SSL context, sets the connection hostname and port,
 * and performs the connection and handshake. If any of these steps fail, the S3 downloader is freed
 * and an error code is returned.
 *
 * @param node The FSNode for which the S3 downloader is being initialized.
 * @param s3 The S3Downloader structure to be initialized.
 * @return 0 on success, or an error code indicating the reason for failure.
 */
int fs_node_init_s3_downloader(FSNode *node, S3Downloader *s3) {
    s3_downloader_empty(s3);

    char *host = aws_host(node->aws);
    if (host == NULL) {
        s3_downloader_free(s3);
        return FS_NODE_ERROR_UNKNOWN;
    }

    s3->bio = BIO_new_ssl_connect(node->s3_ssl_ctx);
    if (s3->bio == NULL) {
        free(host);
        s3_downloader_free(s3);
        return FS_NODE_ERROR_S3_CANNOT_CONNECT;
    }

    if (BIO_get_ssl(s3->bio, &s3->ssl) != 1 || s3->ssl == NULL) {
        free(host);
        s3_downloader_free(s3);
        return FS_NODE_ERROR_S3_CANNOT_CONNECT;
    }

    SSL_set_mode(s3->ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_set_conn_hostname(s3->bio, host) != 1) {
        free(host);
        s3_downloader_free(s3);
        return FS_NODE_ERROR_S3_CANNOT_CONNECT;
    }

    if (BIO_set_conn_port(s3->bio, HTTPS_SCHEME) != 1) {
        free(host);
        s3_downloader_free(s3);
        return FS_NODE_ERROR_S3_CANNOT_CONNECT;
    }

    if (BIO_do_connect(s3->bio) <= 0 || BIO_do_handshake(s3->bio) <= 0) {
        free(host);
        s3_downloader_free(s3);
        return FS_NODE_ERROR_S3_CANNOT_CONNECT;
    }

    free(host);
    return 0;
}

/**
 * @brief Creates an S3 GET request for a given file.
 *
 * This function creates an S3 GET request for the specified file
 * using the provided FSNode and filename. It signs the request using AWS v4
 * and returns the raw request as a string.
 *
 * @param node A pointer to the FSNode structure containing the necessary information.
 * @param filename The name of the file to get.
 * @return A dynamically allocated string containing the raw GET request if successful,
 *         otherwise NULL.
 *
 * @note The returned string must be freed by the caller after use to avoid memory leaks.
 */
char *create_s3_get_request(FSNode *node, const char *filename) {
    HTTPObject *req = http_new_object();
    if (req == NULL) {
        return NULL;
    }

    http_set_request_method(req, strdup(HTTP_METHOD_GET));
    http_set_request_uri(req, strdup(filename));
    http_set_request_version(req, strdup(HTTP_VERSION_1_1));
    http_header_set(req, strdup(HTTP_HEADER_HOST), aws_host(node->aws));

    int sign_result = aws_sign_v4(node->aws, req, EMPTY_CONTENT_SHA256);
    if (sign_result != 0) {
        http_object_free(req);
        return NULL;
    }

    char *raw_request = http_raw(req);
    http_object_free(req);

    return raw_request;
}

/**
 * @brief Downloads a file from an AWS S3 bucket.
 *
 * This function builds an AWS S3 signed request and sends it to the bucket to download the specified file.
 * It connects to the bucket, downloads the file, and saves it locally.
 *
 * @param node The FSNode representing the file system node.
 * @param filename The name of the file to download from the bucket.
 * @return Returns an integer indicating the status of the download operation. Possible return values are:
 *         - FS_NODE_ERROR_UNKNOWN: If the signed request creation fails.
 *         - FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE: If the connection fails or the download fails.
 *         - FS_NODE_ERROR_S3_FILE_NOT_FOUND: If the file does not exist on the bucket.
 *         - FS_NODE_ERROR_S3_NO_SUCCESS: If the download operation is not successful.
 *         - FS_NODE_ERROR_CANNOT_OPEN_DOWNLOAD_FILE: If the local file cannot be opened.
 *         - FS_NODE_ERROR_CANNOT_SAVE_DOWNLOADED_FILE: If the downloaded file cannot be saved.
 *         - 0: If the download operation is successful.
 */
int fs_node_s3_get2(FSNode *node, const char *filename) {
    // Build AWS S3 signed request
    char *raw_request = create_s3_get_request(node, filename);
    if (raw_request == NULL) {
        return FS_NODE_ERROR_UNKNOWN;
    }

    // Connect to bucket and download
    S3Downloader s3;
    int result = fs_node_init_s3_downloader(node, &s3);
    if (result != 0) {
        free(raw_request);
        return result;
    }

    int raw_request_len = (int) strlen(raw_request);
    if (SSL_write(s3.ssl, raw_request, raw_request_len) != raw_request_len) {
        free(raw_request);
        s3_downloader_free(&s3);
        return FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE;
    }
    free(raw_request);
    dzlog_info("Request sent!");

    // parsing response
    s3.buf = malloc(AWS_S3_FILE_DOWNLOAD_BUF_SIZE);
    if (s3.buf == NULL) {
        s3_downloader_free(&s3);
        dzlog_error("s3 response buffer allocation failed");
        return FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE;
    }

    size_t data_index;

    s3.parser = http_new_parser();
    while (s3.parser->state != PARSE_BODY) {

        s3.read_result = BIO_read_ex(s3.bio, s3.buf, AWS_S3_FILE_DOWNLOAD_BUF_SIZE, &s3.read);
        if (s3.read_result <= 0) {
            s3_downloader_free(&s3);
            return FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE;
        }

        data_index = http_parse(s3.parser, s3.buf, s3.read);
        if (data_index < 0) {
            s3_downloader_free(&s3);
            return FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE;
        }
    }

    const char *status = http_response_status_code(s3.parser->r);
    if (strcmp(status, HTTP_STATUS_OK) != 0) {
        dzlog_error("failed to download %s from s3 bucket. (CODE %s)", filename, status);
        int is_not_found = strcmp(status, HTTP_STATUS_NOT_FOUND);
        s3_downloader_free(&s3);
        return is_not_found ? FS_NODE_ERROR_S3_FILE_NOT_FOUND : FS_NODE_ERROR_S3_NO_SUCCESS;
    }

    // saving body to handle
    s3.filename = fs_node_full_path(node, filename);
    size_t size = strlen(node->disk->dir) + strlen(filename) + strlen(FS_NODE_FILE_DOWNLOAD_EXTENSION) + 1;

    s3.tmp_filename = malloc(size);
    if (s3.tmp_filename == NULL) {
        s3_downloader_free(&s3);
        dzlog_error("download tmp filename memory allocation failed");
        return FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE;
    }

    sprintf(s3.tmp_filename, "%s%s%s", node->disk->dir, filename, FS_NODE_FILE_DOWNLOAD_EXTENSION);

    s3.file = fopen(s3.tmp_filename, "w");
    if (s3.file == NULL) {
        s3_downloader_free(&s3);
        return FS_NODE_ERROR_CANNOT_OPEN_DOWNLOAD_FILE;
    }

    if (data_index < s3.read) {
        size_t count = s3.read - (size_t) data_index;
        if (fwrite(s3.buf + data_index, 1, s3.read - data_index, s3.file) != count) {
            s3_downloader_free(&s3);
            return FS_NODE_ERROR_CANNOT_SAVE_DOWNLOADED_FILE;
        }
    }

    while (true) {
        s3.read_result = BIO_read_ex(s3.bio, s3.buf, AWS_S3_FILE_DOWNLOAD_BUF_SIZE, &s3.read);
        if (s3.read_result <= 0) {
            return s3_download_clean(&s3);
        }

        s3.write_result = fwrite((void *) s3.buf, 1, s3.read, s3.file);
        if (s3.write_result < s3.read) {
            s3_downloader_free(&s3);
            return FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE;
        }
    }

    return s3_download_clean(&s3);
}

/**
 * Acquires or creates a FileDownload object for the given FSNode and filename.
 *
 * If a FileDownload object with the same filename already exists in the FSNode's
 * downloads, it will be assigned to the 'download' parameter.
 *
 * If no FileDownload object with the same filename exists, a new FileDownload object
 * will be created and assigned to the 'download' parameter.
 *
 * @param node      The FSNode that owns the downloads.
 * @param filename  The name of the file to acquire or create the FileDownload for.
 * @param download  A pointer to a FileDownload pointer to assign the acquired or created FileDownload object to.
 *
 * @return None.
 */
void acquire_s3_download_file(FSNode *node, const char *filename, FileDownload **download) {
    // get download token
    pthread_mutex_lock(&node->downloads->mutex);
    int i;
    for (i = 0; i < MAX_S3_DOWNLOAD_SLOT_NUMBER; i++) {
        FileDownload *slot = node->downloads->files[i];
        if (slot != NULL && slot->name != NULL && strcmp(slot->name, filename) == 0) {
            *download = slot;
            break;
        }
    }

    if (*download == NULL) {
        for (i = 0; i < MAX_S3_DOWNLOAD_SLOT_NUMBER; i++) {
            FileDownload *slot = node->downloads->files[i];
            if (slot == NULL) {
                slot = (FileDownload *) malloc(sizeof(FileDownload));
                if (slot == NULL) {
                    break;
                }
                node->downloads->files[i] = slot;
                slot->name = strdup(filename);
                pthread_mutex_init(&slot->mutex, NULL);
                *download = slot;
                break;
            }
        }
    }
    pthread_mutex_unlock(&node->downloads->mutex);
}

/**
 * @brief Downloads a file from storage for a given FSNode.
 *
 * This function attempts to download the specified file from the storage
 * associated with the FSNode. It acquires a download token for the file, and
 * if successful, proceeds to download the file from the storage. If the file
 * is already being downloaded by another thread, or if the download queue is
 * full, the function returns an appropriate error code.
 *
 * @param node The FSNode from which to download the file.
 * @param filename The name of the file to download.
 * @return The result of the download operation. Returns 0 if the download
 * was successful. Possible error codes are:
 *   - FS_NODE_ERROR_S3_QUEUE_FULL: If the download queue is full.
 *   - FS_NODE_ERROR_S3_FILE_BEING_DOWNLOADED: If the file is already being downloaded.
 *   - FS_NODE_ERROR_UNKNOWN: If an unknown error occurred during the download.
 *   - FS_NODE_ERROR_CANNOT_DOWNLOAD_FILE: If the file download failed.
 *   - FS_NODE_ERROR_S3_FILE_NOT_FOUND: If the file was not found in the storage.
 *   - FS_NODE_ERROR_S3_NO_SUCCESS: If the download was not successful for other reasons.
 *   - FS_NODE_ERROR_CANNOT_OPEN_DOWNLOAD_FILE: If the downloaded file could not be opened.
 *   - FS_NODE_ERROR_CANNOT_SAVE_DOWNLOADED_FILE: If the downloaded file could not be saved.
 */
int fs_node_download_file_from_storage(FSNode *node, const char *filename) {
    FileDownload *download = NULL;
    acquire_s3_download_file(node, filename, &download);
    if (download == NULL) {
        dzlog_warn("s3 download queue is full");
        return FS_NODE_ERROR_S3_QUEUE_FULL;
    }

    // try to acquire it
    int status = pthread_mutex_trylock(&download->mutex);
    if (status == EBUSY) {
        dzlog_warn("s3 file is being downloaded");
        return FS_NODE_ERROR_S3_FILE_BEING_DOWNLOADED;
    }

    if (download->available) {
        pthread_mutex_unlock(&download->mutex);
        return 0;
    }

    dzlog_info("S3 start download of: %s", download->name);
    int result = fs_node_s3_get2(node, download->name);
    dzlog_info("S3 downloaded: %s, res=%d", download->name, result);
    download->available = (result == 0);

    pthread_mutex_unlock(&download->mutex);
    return result;
}

int fs_node_pull_storage_file(FSNode *node, const char *filename, bool *downloaded) {
    char *full_path = fs_node_full_path(node, filename);
    if (full_path == NULL) {
        return 1;
    }

    FILE *file;
    int attempts = 0, result = 0;

    while (attempts++ < 2) {
        file = fopen(full_path, "r");
        if (file != NULL) {
            break;
        }

        *downloaded = true;
        result = fs_node_download_file_from_storage(node, filename);
        if (result != 0) {
            free(full_path);
            return result;
        }
    }

    if (fs_node_register_file_read_record(node, filename) != 0) {
        dzlog_error("failed to register read record for file: %s", filename);
    }

    free(full_path);
    fclose(file);
    return result;
}

/**
 * @brief Prunes the FSNode's disk by deleting files until disk usage is within capacity.
 *
 * This function attempts to lock the prune_mutex of the FSNode. If the mutex is already locked,
 * it returns 0. Otherwise, it calculates the total disk usage of the FSNode's directory and compares
 * it with the current disk usage. If they are not equal, it publishes the updated disk usage and
 * updates the disk->usage field. Then, it retrieves the oldest files from the FSNode's registry and
 * starts deleting them until the disk usage is within the capacity. After deleting files, it publishes
 * the updated disk usage again if any files were deleted. Finally, it releases the prune_mutex and returns 0.
 *
 * @param node The FSNode object to prune the disk for.
 * @return 0 if successful, 1 if an error occurs.
 */
int fs_node_prune(FSNode *node) {
    int mut_status = pthread_mutex_trylock(&node->prune_mutex);
    if (mut_status == EBUSY) {
        return 0;
    }

    uint64_t disk_usage;
    if (fs_node_get_disk_usage(node->disk->dir, &disk_usage) != 0) {
        pthread_mutex_unlock(&node->prune_mutex);
        return 1;
    }

    if (disk_usage != node->disk->usage) {
        fs_node_publish_info(node);
    }
    node->disk->usage = disk_usage;

    size_t count_deleted = 0;
    List *names = list_create();
    while ((disk_usage + node->disk->gap) > node->disk->capacity) {
        if (fs_node_get_oldest_file_from_registry(node, names) != 0) {
            dzlog_error("failed retrieve oldest filenames from the database");
            break;
        }

        for (size_t i = 0; i < names->len; i++) {
            char *filename = (char *) names->items[i];
            if (fs_node_delete_file(node, filename) == 0) {
                count_deleted++;
                fs_node_delete_file_from_registry(node, filename);
            } else {
                dzlog_warn("could not delete %s", filename);
            }
        }

        list_clear(names);
        if (fs_node_get_disk_usage(node->disk->dir, &disk_usage) != 0) {
            break;
        }
        node->disk->usage = disk_usage;
    }

    dzlog_info("deleted %zu files", count_deleted);
    if (count_deleted > 0) {
        fs_node_publish_info(node);
    }

    list_free(names);
    pthread_mutex_unlock(&node->prune_mutex);
    return 0;
}

void fs_file_free(File *file) {
    if (file == NULL) {
        return;
    }

    if (file->path != NULL) {
        free(file->path);
        file->path = NULL;
    }

    if (file->fd != NULL) {
        fclose(file->fd);
        file->fd = NULL;
    }

    if (file->mime_type != NULL) {
        free(file->mime_type);
        file->mime_type = NULL;
    }

    file = NULL;
}

char *fs_node_full_path(FSNode *node, const char *filepath) {
    size_t size = strlen(node->disk->dir) + strlen(filepath) + 1;
    char *full_path = (char *) malloc(size);
    if (full_path != NULL) {
        sprintf(full_path, "%s%s", node->disk->dir, filepath);
    }
    return full_path;
}

int fs_node_get_file(FSNode *node, const char *filename, read_options_t opts, File **file) {
    char *path = fs_node_full_path(node, filename);
    if (path == NULL) {
        return 1;
    }

    const char *mime = magic_file(node->magic_cookie, path);
    char *mime_type = strdup(mime);

    FILE *fd;
    while ((fd = fopen(path, "r")) == NULL) {
        if (errno != ENOENT || fs_node_download_file_from_storage(node, filename) != 0) {
            free(path);
            free(mime_type);
            return 1;
        }
    }

    // handle offset and limit
    int res = fseek(fd, 0L, SEEK_END);
    if (res < 0) {
        free(path);
        free(mime_type);
        return 1;
    }
    size_t size = (size_t) ftell(fd);

    res = fseek(fd, 0, SEEK_SET);
    if (res < 0) {
        free(path);
        free(mime_type);
        return 1;
    }

    size_t available, offset;
    size_t max_available_content = opts.max_chunk_size;
    if (max_available_content == 0 || max_available_content > size) {
        max_available_content = size;
    }

    if (opts.limit <= 0 && opts.offset <= 0) {
        offset = 0;
        available = (long) max_available_content;

    } else if (opts.limit <= 0) {
        res = fseek(fd, (long) opts.offset, SEEK_SET);
        if (res < 0) {
            fclose(fd);
            free(path);
            free(mime_type);
            return 1;
        }
        available = max_available_content;
        offset = opts.offset;
        if (opts.offset + available > size) {
            available = size - opts.offset;
        }

    } else {
        if (opts.limit > (long) max_available_content) {
            opts.limit = (long) max_available_content;
        }
        if (fseek(fd, -1 * ((long) opts.limit), SEEK_END) != 0) {
            fclose(fd);
            free(path);
            free(mime_type);
            return 1;
        }
        available = (long) opts.limit;
        offset = (long) size - available;
    }

    *file = (File *) malloc(sizeof(File));
    if (*file == NULL) {
        fclose(fd);
        free(path);
        free(mime_type);
        return 1;
    }

    (*file)->fd = fd;
    (*file)->path = path;
    (*file)->mime_type = mime_type;
    (*file)->available = available;
    (*file)->offset = offset;
    (*file)->size = size;
    return 0;
}

int fs_node_delete_file(FSNode *node, const char *filepath) {
    char *full_path = fs_node_full_path(node, filepath);
    int result = remove(full_path);
    free(full_path);
    if (result == 0 || errno == ENOENT) {
        return 0;
    }
    return result;
}

/**
 * @brief Publishes the information of a File System Node to the registry server.
 *
 * This function takes a FSNode object and publishes its information to the registry server.
 * It converts the node's information to JSON format, calculates the SHA256 hash of the JSON payload,
 * signs the HTTP request with AWS credentials, and sends the request to the registry server.
 * If successful, it returns 0. Otherwise, it returns 1.
 *
 * @param node The FSNode object to publish the information.
 * @return 0 if successful, 1 otherwise.
 */
int fs_node_publish_info(FSNode *node) {
    char *json = fs_node_info_to_json(node);
    size_t content_len = strlen(json);

    char *payload_hash_bytes = NULL;
    size_t payload_hash_len = 0;
    if (sha256(json, content_len, &payload_hash_bytes, &payload_hash_len) != 0) {
        free(json);
        return 1;
    }

    char *payload_hash = hex(payload_hash_bytes, payload_hash_len);
    free(payload_hash_bytes);

    if (payload_hash == NULL) {
        free(json);
        return 1;
    }

    HTTPObject *req = http_new_object();
    http_set_request_method(req, strdup("POST"));
    http_set_request_uri(req, strdup("/services"));
    http_header_set(req, strdup(HTTP_HEADER_HOST), strdup(node->registry->host));
    http_header_set(req, strdup(HTTP_HEADER_CONTENT_LENGTH), int_to_str((int) content_len));

    if (aws_sign_v4(node->aws, req, payload_hash) != 0) {
        free(json);
        http_object_free(req);
        return 1;
    }
    char *http_headers_bytes = http_raw(req);
    http_object_free(req);

    SecureConn *sc = secure_conn_new();
    if (sc == NULL) {
        free(json);
        free(http_headers_bytes);
        return 1;
    }

    int result = sc_dial(node->registry->ssl_ctx, node->registry->host, node->registry->port, sc);
    if (result != SC_OK) {
        free(json);
        free(http_headers_bytes);
        sc_free(sc);
        return 1;
    }

    result = 0;
    result = sc_write(sc, http_headers_bytes, strlen(http_headers_bytes));
    free(http_headers_bytes);
    if (result == 0) {
        free(json);
        sc_free(sc);
        return 1;
    }

    result += sc_write(sc, json, content_len);
    free(json);
    if (result == 0) {
        sc_free(sc);
        return 1;
    }

    const size_t buf_len = 4096;
    char buf[buf_len];

    HTTPParser *parser = http_new_parser();
    while (parser->state != PARSE_BODY) {
        if (sc_read(sc, buf, buf_len) < 0) {
            break;
        }

        if (http_parse(parser, buf, sc->read) < 0) {
            http_parser_free(parser);
            sc_free(sc);
            return 1;
        }
    }

    const char *status = http_response_status_code(parser->r);
    if (strcmp(status, HTTP_STATUS_OK) != 0) {
        dzlog_error("Registry HTTP server responded with a %s status: ", status);
        http_parser_free(parser);
        sc_free(sc);
        return 1;
    }

    http_parser_free(parser);
    sc_free(sc);
    return sc->error_code == SSL_ERROR_NONE || sc->error_code == SSL_ERROR_ZERO_RETURN ? 0 : 1;
}

/**
 * @brief Get the signed certificate for the FSNode.
 *
 * This function loads the X.509 certificate from the specified file.
 * If the certificate does not exist, it generates a new RSA key pair,
 * saves it to the specified file, and generates a certificate signing request (CSR).
 * The CSR is then sent to the CA HTTP server for signing.
 * Once the certificate is signed, it is saved to the specified file.
 *
 * @param node The FSNode.
 * @return 0 if the signed certificate was obtained successfully, 1 otherwise.
 */
int fs_node_get_signed_certificate(FSNode *node) {
    X509 *crt = load_certificate(FS_NODE_SERVICE_CERT_FILENAME);
    if (crt != NULL) {
        X509_free(crt);
        return 0;
    }

    EVP_PKEY *p_key = load_rsa_private_key(FS_NODE_SERVICE_KEY_FILENAME);
    if (p_key == NULL) {
        p_key = generate_rsa_key_pair(2048);
        if (p_key == NULL) {
            return 1;
        }
    }

    if (save_rsa_private_key(FS_NODE_SERVICE_KEY_FILENAME, p_key) != 0) {
        dzlog_error("failed to save generated RSA key pair.");
        EVP_PKEY_free(p_key);
        return 1;
    }

    X509_REQ *csr = generate_certificate_sign_request(p_key);
    EVP_PKEY_free(p_key);
    if (csr == NULL) {
        dzlog_error("failed to generate certificate sign request.");
        return 1;
    }

    size_t csr_len = 0;
    char *csr_bytes = certificate_sign_request_to_bytes(csr, &csr_len);
    X509_REQ_free(csr);
    if (csr_bytes == NULL) {
        dzlog_error("failed to encode certificate sign request.");
        return 1;
    }

    char *payload_hash_bytes = NULL;
    size_t payload_hash_len = 0;
    if (sha256(csr_bytes, csr_len, &payload_hash_bytes, &payload_hash_len) != 0) {
        free(csr_bytes);
        return 1;
    }

    char *payload_hash = hex(payload_hash_bytes, payload_hash_len);
    free(payload_hash_bytes);

    if (payload_hash == NULL) {
        free(csr_bytes);
        return 1;
    }

    AWS aws;
    aws.service = "node";
    aws.region = "wa";
    aws.bucket = "cache";
    aws.access_key = node->registry->access_key;
    aws.secret_key = node->registry->secret_key;

    HTTPObject *req = http_new_object();
    http_set_request_method(req, strdup("POST"));
    http_set_request_uri(req, strdup("/certificates"));
    http_header_set(req, strdup(HTTP_HEADER_HOST), strdup(node->registry->host));
    http_header_set(req, strdup(HTTP_HEADER_CONTENT_LENGTH), int_to_str((int) csr_len));
    http_header_set(req, strdup(HTTP_HEADER_X_AMZ_CONTENT_SHA256), payload_hash);
    if (aws_sign_v4(&aws, req, payload_hash) != 0) {
        http_object_free(req);
        return 1;
    }
    char *http_headers_bytes = http_raw(req);
    http_object_free(req);

    SecureConn *sc = calloc(1, sizeof(SecureConn));
    if (sc == NULL) {
        free(http_headers_bytes);
        free(csr_bytes);
        return 1;
    }

    int result = sc_dial(node->registry->ssl_ctx, node->registry->host, node->registry->port, sc);
    if (result != SC_OK) {
        free(http_headers_bytes);
        free(csr_bytes);
        sc_free(sc);
        return 1;
    }

    result = 0;
    result = sc_write(sc, http_headers_bytes, strlen(http_headers_bytes));
    free(http_headers_bytes);
    if (result == 0) {
        sc_free(sc);
        free(csr_bytes);
        return 1;
    }

    result += sc_write(sc, csr_bytes, csr_len);
    free(csr_bytes);
    if (result == 0) {
        sc_free(sc);
        return 1;
    }

    const size_t buf_len = 4096;
    char buf[buf_len];

    int body_start_index = 0;

    HTTPParser *parser = http_new_parser();
    while (parser->state != PARSE_BODY) {
        if (sc_read(sc, buf, buf_len) < 0) {
            break;
        }
        body_start_index = http_parse(parser, buf, sc->read);
        if (body_start_index < 0) {
            http_parser_free(parser);
            sc_free(sc);
            return 1;
        }
    }

    const char *status = http_response_status_code(parser->r);
    if (strcmp(status, HTTP_STATUS_OK) != 0) {
        http_parser_free(parser);
        sc_free(sc);
        dzlog_error("CA HTTP server responded with a %s status: ", status);
        return 1;
    }

    size_t content_len;
    if (str_to_size_t(http_header_get(parser->r, HTTP_HEADER_CONTENT_LENGTH), &content_len) != 0) {
        content_len = 0;
    }

    FILE *crt_file = fopen(FS_NODE_SERVICE_CERT_FILENAME, "w");
    if (crt_file == NULL) {
        sc_free(sc);
        return 1;
    }

    if ((size_t) body_start_index < sc->read) {
        size_t count = sc->read - (size_t) body_start_index;
        if (fwrite(buf + body_start_index, 1, count, crt_file) != count) {
            fclose(crt_file);
            http_parser_free(parser);
            sc_free(sc);
            return 1;
        }
        if (content_len > 0) {
            content_len -= count;
        }
    }

    while (content_len > 0 && sc_read(sc, buf, buf_len) > 0) {
        if (fwrite((void *) buf, 1, sc->read, crt_file) < sc->read) {
            fclose(crt_file);
            http_parser_free(parser);
            sc_free(sc);
            return 1;
        }
        if (content_len > 0) {
            content_len -= sc->read;
        }
    }

    char *ca_cert_bytes = NULL;
    size_t len = 0;
    if (read_file(FS_NODE_SERVICE_CA_CRT_FILENAME, &ca_cert_bytes, &len) != 0) {
        fclose(crt_file);
        http_parser_free(parser);
        sc_free(sc);
        return 1;
    }

    if (fwrite((void *) ca_cert_bytes, 1, len, crt_file) < len) {
        fclose(crt_file);
        http_parser_free(parser);
        sc_free(sc);
        free(ca_cert_bytes);
        return 1;
    }
    free(ca_cert_bytes);

    http_parser_free(parser);
    fclose(crt_file);
    result = sc->error_code == SSL_ERROR_NONE || sc->error_code == SSL_ERROR_ZERO_RETURN ? 0 : 1;
    sc_free(sc);
    return result;
}
