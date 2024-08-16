#include "include/fsnode.h"

/*
 * ###################
 * # SECTION ENV
 * ###################
 */

/**
 * @brief Load environment variables from the .env file and invoke the callback for each variable.
 *
 * This function reads the .env file and processes each line as an environment variable.
 * Lines starting with '#' or containing only whitespace characters are ignored.
 * Each environment variable is expected to be in the format 'name=value'.
 * The callback function provided by the user is invoked for each valid environment variable,
 * passing the provided container and the env_var_t structure containing the variable name and value.
 *
 * @param container A pointer to the container object that will be passed to the callback function.
 * @param var_cb The callback function to be invoked for each environment variable.
 * @return 0 on success, -1 if there was an error opening the .env file, 1 if the callback function returned false.
 */
int env_load(void *container, env_var_cb var_cb) {
    FILE *env_file = fopen(".env", "r");
    if (env_file == NULL) {
        perror("error opening .env handle");
        return -1;
    }

    env_var_t var;
    size_t line_len = 0;
    bool ok = true;
    while (ok) {
        char *line = NULL;
        if (-1 == getline(&line, &line_len, env_file)) {
            if (line != NULL) free(line);
            break;
        }

        char *clean_line = trim(line);
        free(line);

        if (*clean_line == '#' || *clean_line == '\n' || *clean_line == '\0') {
            free(clean_line);
            continue;
        }

        char *pos;
        char *start;
        pos = start = clean_line;

        while (*pos != '=' && *pos != ':') pos++;
        if (!*pos) {
            free(clean_line);
            break;
        }
        var.name = strndup(start, pos - start);

        pos++;

        while (*pos == ' ') pos++;
        start = pos;

        while (*pos != '\n' && *pos != '\0') pos++;
        var.value = strndup(start, pos - start);

        printf("ENV %s=%s\n", var.name, var.value);

        ok = var_cb(container, var);
        free(clean_line);
        free((char *) var.name);
        if (var.value != NULL) {
            free((char *) var.value);
        }
        if (!ok) {
            return 1;
        }
    }
    fclose(env_file);
    return 0;
}

/*
 * ###################
 * # SECTION UTILS
 * ###################
 */

char *toLower(const char *str) {
    char *out = strdup(str);
    if (out == NULL) {
        return NULL;
    }

    char *ptr = out;
    while (*ptr != '\0') {
        *ptr = (char) tolower(*ptr);
        ptr++;
    }
    if (strlen(str) != strlen(out)) {
        return NULL;
    }
    return out;
}

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

char *hex(const char *bytes, size_t length) {
    char *hex_string = malloc((2 * length + 1));
    static char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        hex_string[i * 2] = hex_digits[(bytes[i] >> 4) & 0xF];
        hex_string[i * 2 + 1] = hex_digits[bytes[i] & 0xF];
    }
    hex_string[length * 2] = '\0'; // Null-terminate the string
    return hex_string;
}

char *iso8601_date_from_time(struct tm *tm_info) {
    char *buffer = malloc(18);
    if (buffer == NULL) {
        return NULL;
    }

    size_t len = strftime(buffer, 17, "%Y%m%dT%H%M%SZ", tm_info);
    buffer[len] = '\0';
    return buffer;
}

char *date_from_time(struct tm *tm_info) {
    char *buffer = malloc(10);
    strftime(buffer, 9, "%Y%m%d", tm_info);
    return buffer;
}

char *trim(const char *str) {
    size_t str_len = strlen(str);
    if (str_len == 0 || (str_len == 1 && *str != ' ')) {
        return strdup(str);
    }

    const char *ptr = str;
    size_t start = 0;
    size_t end = strlen(str) - 1;

    while (*(ptr + start) == ' ') start++;
    while (*(ptr + end) == ' ') end--;

    size_t len = end - start + 1;
    char *result = malloc(len + 1);
    if (result == NULL) {
        return NULL;
    }
    result[len] = '\0';
    size_t i = 0;
    while (i <= len) {
        result[i] = str[start + i];
        i++;
    }
    return result;
}

char *int_to_str(int value) {
    int digit_count;
    if (value == 0) {
        digit_count = 2;
    } else {
        digit_count = (int) log10(value) + 2;
    }
    char *str = malloc(digit_count);
    sprintf(str, "%d", value);
    return str;
}

int str_to_size_t(const char *str, size_t *val) {
    *val = 0;
    while (*str != '\0') {
        if (!isdigit(*str)) return 1;
        *val = (*val * 10) + (*str - '0');
        str++;
    }
    return 0;
}

int parse_size(const char *str_size, uint64_t *out_size) {
    char c;
    const char *ptr = str_size;
    const char *ends = ptr + strlen(ptr);
    while (isdigit(*ptr) && ptr < ends) {
        c = *ptr;
        *out_size = *out_size * 10 + (c - '0');
        ptr++;
    }

    c = *ptr;
    if (isdigit(c)) {
        return 0;
    }

    ptr++;
    while (ptr < ends) {
        if (*ptr != ' ')
            return 1;
        ptr++;
    }

    switch (c) {
        case 'K':
            *out_size *= KB;
            break;
        case 'M':
            *out_size *= MB;
            break;
        case 'G':
            *out_size *= GB;
            break;
        default:
            return 1;
    }
    return 0;
}

int handle_error(int code, const char *msg) {
    dzlog_error("%s", msg);
    return code;
}

int read_file(const char *name, char **out, size_t *out_len) {
    FILE *file = fopen(name, "rb");
    if (file == NULL) {
        return 1;
    }

    // Seek to the end of the file to determine the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);  // Go back to the beginning of the file

    // Allocate buffer to hold the file content
    char *buffer = (char*)malloc(file_size + 1);  // +1 for the null terminator
    if (buffer == NULL) {
        fclose(file);
        return 1;
    }

    // Read file content into the buffer
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != file_size) {
        free(buffer);
        fclose(file);
        return 1;
    }

    // Null-terminate the buffer (in case of a text file)
    buffer[file_size] = '\0';

    // Close the file
    fclose(file);

    *out = buffer;
    *out_len = (size_t) file_size;
    return 0;
}

/*
 * ###################
 * # SECTION LIST
 * ###################
 */

List *list_create() {
    List *list = (List *) malloc(sizeof(List));
    if (list == NULL) {
        return NULL;
    }

    list->len = 0;
    list->cap = 5;

    list->items = malloc(sizeof(void *) * list->cap);
    if (list->items == NULL) {
        free(list);
        list = NULL;
    }

    return list;
}

void list_grow(List *list, size_t count) {
    size_t new_len = list->cap + count;

    void **new_items = malloc(sizeof(void *) * new_len);
    for (size_t i = 0; i < list->cap; i++) {
        *(new_items + i) = *(list->items + i);
    }

    if (list->cap > 0) {
        free(list->items);
    }

    list->cap = new_len;
    list->items = new_items;
}

void list_add(List *list, char *item) {
    if (list->len == list->cap) {
        list_grow(list, 5);
    }

    *(list->items) = (char *) item;
    list->len++;
}

void *list_get(List *list, size_t index) {
    return list->items[index];
}

void *list_pop(List *list) {
    size_t last_index = list->len - 1;
    void *item = list->items[last_index];
    list->items[last_index] = NULL;
    list->len--;
    return item;
}

void *list_pop_head(List *list) {
    if (list->len == 0) {
        return NULL;
    }

    void * item = list->items[0];
    list->items[0] = NULL;

    for (int i = 0; i < list->len - 1; i++) {
        list->items[i] = list->items[i + 1];
        list->items[i + 1] = NULL;
    }
    list->len--;
    return item;
}

void list_clear(List *list) {
    if (list->len > 0) {
        for (size_t i = 0; i < list->len; i++) {
            free(list->items[i]);
        }
    }
    list->len = 0;
}

void list_free(List *list) {
    if (list == NULL) {
        return;
    }

    if (list->len > 0) {
        for (size_t i = 0; i < list->len; i++) {
            free(list->items[i]);
        }
    }

    free(list->items);
    free(list);
    list = NULL;
}

/*
 * ###################
 * # SECTION MAP
 * ###################
 */

Map *map_create() {
    Map *map = NULL;
    map = (Map *) malloc(sizeof(Map));
    if (map == NULL) {
        return NULL;
    }

    map->cap = 0;
    map->len = 0;
    map->names = NULL;
    map->values = NULL;
    if (map_grow(map, 10) != 0) {
        free(map);
        return NULL;
    }

    return map;
}

int map_grow(Map *map, size_t count) {
    if (map == NULL) {
        return 1;
    }

    if (map->names == NULL) {
        map->names = (char **) malloc(sizeof(char *) * count);
        if (map->names == NULL) return 1;

        map->values = (char **) malloc(sizeof(char *) * count);
        if (map->values == NULL) {
            free(map->names);
            return 1;
        }

        map->cap = count;
        return 0;
    }

    size_t new_len = map->cap + count;
    char **new_names = (char **) realloc(map->names, sizeof(char *) * new_len);
    if (new_names == NULL) {
        return 1;
    }

    char **new_values = (char **) realloc(map->values, sizeof(char *) * new_len);
    if (new_values == NULL) {
        free(new_names);
        return 1;
    }

    map->names = new_names;
    map->values = new_values;
    map->cap = new_len;
    return 0;
}

int map_set(Map *map, char *name, char *value) {
    for (size_t i = 0; i < map->len; i++) {
        if (strcmp(name, map->names[i]) == 0) {
            char *old_value = map->values[i];
            if (old_value != NULL) {
                free(old_value);
            }
            map->values[i] = (char *) value;
            return 0;
        }
    }

    if (map->len == map->cap) {
        if (map_grow(map, 2) != 0) return 1;
    }

    map->names[map->len] = name;
    map->values[map->len] = value;
    map->len++;
    return 0;
}

const char *map_value(Map *map, char *name) {
    for (size_t i = 0; i < map->len; i++) {
        if (strcmp(name, *(map->names + i)) == 0) {
            return *(map->values + i);
        }
    }
    return NULL;
}

void map_free(Map *map) {
    if (map == NULL) {
        return;
    }

    for (size_t i = 0; i < map->len; i++) {
        char *name = map->names[i];
        char *value = map->values[i];

        if (name != NULL) {
            free(name);
        }

        if (value != NULL) {
            free(value);
        }
    }

    free(map->names);
    free(map->values);
    free(map);
    map = NULL;
}

/*
 * ###################
 * # SECTION CRYPTO
 * ###################
 */

int save_rsa_private_key(const char *filename, EVP_PKEY *pkey) {
    BIO *bio = NULL;

    bio = BIO_new_file(filename, "w");
    if (bio == NULL) return handle_error(1, "Failed to create BIO for private key file");

    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return handle_error(1, "Failed to write private key to file");
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

BIO* streamBIO_new(const char *name) {
    StreamBIO *sb = (StreamBIO*) OPENSSL_malloc(sizeof(StreamBIO));
    if (sb == NULL) {
        return NULL;
    }

    sb->name = name;
    sb->offset = sb->limit = 0;
    sb->capacity = STREAM_BIO_BUFFER_SIZE;
    sb->buffer = OPENSSL_malloc(STREAM_BIO_BUFFER_SIZE);
    if (sb->buffer == NULL) {
        OPENSSL_free(sb);
        return NULL;
    }

    BIO_METHOD *method = BIO_meth_new(BIO_TYPE_MEM, "Custom memory BIO");
    if (method == NULL) {
        OPENSSL_free(sb->buffer);
        OPENSSL_free(sb);
        return NULL;
    }

    BIO_meth_set_read(method, streamBIO_read);
    BIO_meth_set_write(method, streamBIO_write);
    BIO_meth_set_ctrl(method, streamBIO_crtl);
    BIO_meth_set_destroy(method, streamBIO_destroy);

    sb->bio = BIO_new(method);
    if (sb->bio == NULL) {
        BIO_meth_free(method);
        OPENSSL_free(sb->buffer);
        OPENSSL_free(sb);
        return NULL;
    }

    BIO_set_data(sb->bio, sb);
    BIO_set_init(sb->bio, 1);
    return sb->bio;
}

int streamBIO_write(BIO *bio, const char *data, int len) {
    StreamBIO *sb = BIO_get_data(bio);

    size_t buffered = sb->limit - sb->offset;
    if (sb->offset > 0) {
        memmove(sb->buffer, sb->buffer + sb->offset, buffered);
        sb->limit = buffered;
        sb->offset = 0;
    }

    size_t available_space = sb->capacity - sb->limit;
    if ((size_t) len > available_space) {
        size_t needed_space = (size_t) (len - available_space);

        size_t new_size = sb->capacity + needed_space;
        char *new_buffer = (char *) realloc(sb->buffer, new_size);
        if (new_buffer == NULL) {
            return -1;
        }
        sb->buffer = new_buffer;
        sb->capacity = new_size;
    }

    memcpy(sb->buffer + sb->limit, data, len);
    sb->limit += (size_t) len;
    return len;
}

int streamBIO_read(BIO *bio, char *data, int len) {
    StreamBIO *sb = BIO_get_data(bio);

    size_t available = sb->limit - sb->offset;

    if (available == 0) {
        BIO_set_retry_read(bio);  // Should retry reading, not writing
        return -1;
    }

    if (available > (size_t) len) {
        available = (size_t) len;
    }

    memcpy(data, sb->buffer + sb->offset, available);
    sb->offset += available;
    return (int) available;
}

long streamBIO_crtl(BIO *bio, int cmd, long arg1, void *arg2) {
    unused(arg1);
    unused(arg2);

    StreamBIO *sb = BIO_get_data(bio);
    switch (cmd) {
        case BIO_CTRL_INFO:
            return (long) (sb->limit - sb->offset);
        case BIO_CTRL_RESET:
            sb->offset = 0;
            sb->limit = 0;
            return 1;
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            return (long) (sb->limit - sb->offset);
        case BIO_CTRL_FLUSH:
            sb->should_flush = (sb->limit - sb->offset);
            return 1;
        case BIO_CTRL_PUSH:
            return 1;
        default:
            dzlog_warn("received command that is not handled: %d", cmd);
            return 1;
    }
}

int streamBIO_destroy(BIO *bio) {
    StreamBIO *sb = BIO_get_data(bio);

    if (sb == NULL) return 1;

    if (sb->buffer != NULL){
      free(sb->buffer);
      sb->buffer = NULL;
    }

    BIO_free(sb->bio);

    free(sb);
    sb = NULL;

    return 1;
}

TLSSession *tls_session_new(SSL_CTX *ctx) {
    TLSSession * session = (TLSSession *) malloc(sizeof(TLSSession ));
    if (session == NULL) {
        return NULL;
    }

    session->ssl = SSL_new(ctx);
    if (!session->ssl) {
        free(session);
        return NULL;
    }

    SSL_set_accept_state(session->ssl);

    session->read = streamBIO_new("read");
    if (session->read == NULL) {
        free(session);
        SSL_free(session->ssl);
        return NULL;
    }

    session->write = streamBIO_new("write");
    if (session->write == NULL) {
        BIO_free(session->read);
        free(session);
        SSL_free(session->ssl);
        return NULL;
    }

    SSL_set_bio(session->ssl, session->read, session->write);
    return session;
}

void tls_session_free(TLSSession * session) {
    if (session == NULL) {
        return;
    }

    if (session->read != NULL) {
        BIO_free(session->read);
    }

    if (session->write != NULL) {
        BIO_free(session->write);
    }

    if (session->ssl != NULL) {
        SSL_free(session->ssl);
    }

    free(session);
    session = NULL;
}

/*
 * ###################
 * # SECTION SECURE TCP CONNECTION
 * ###################
 */

 SecureConn * secure_conn_new() {
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
    if (read <= 0) {
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

/*
 * ###################
 * # SECTION HTTP
 * ###################
 */

/**
 * @brief Generates the "Date" header for an HTTP response.
 *
 * This function returns a string containing the "Date" header for an HTTP response.
 * The header is formatted according to the HTTP/1.1 specifications.
 *
 * @return A dynamically allocated string containing the "Date" header.
 *         The caller is responsible for freeing the memory.
 */
char *http_get_date_header() {
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
 * @param range A pointer to the Range structure to store the content range information.
 * @return 0 if successful, 1 if there was an error parsing the "Range" header.
 */
int http_get_content_range(HTTPObject *r, Range *range) {
    const char *pos = map_value(r->headers, HTTP_HEADER_RANGE);
    range->type = range_unspecified;
    if (pos == NULL) {
        range->type = range_full;
        range->offset = 0;
        range->limit = FILE_CHUNK_SIZE - 1;
        return 0;
    }

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

    switch (range->type) {
        case range_unspecified:
            range->type = range_full;
            range->offset = 0;
            range->limit = FILE_CHUNK_SIZE - 1;
            break;

        case range_prefix:
            range->type = range_full;
            range->limit = range->offset + FILE_CHUNK_SIZE - 1;
            break;

        case range_suffix:
            range->type = range_prefix;
            range->offset = range->limit;
            break;

        case range_full:
            if (range->limit - range->offset + 1 > FILE_CHUNK_SIZE) {
                range->limit = range->offset + FILE_CHUNK_SIZE - 1;
            }
            break;
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
int http_parse(HTTPParser *parser, char *buffer, size_t data_len) {
    if (parser->r == NULL) {
        parser->r = http_new_object();
        if (parser->r == NULL) {
            return -1;
        }
    }
    HTTPObject *r = parser->r;

    size_t token_len;
    char *token_start = buffer;
    char *pos = NULL;
    char *end = buffer + data_len;

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

/*
 * ###################
 * # SECTION AWS
 * ###################
 */

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
        dzlog_info("downloaded %s", s3->filename);
        result = rename(s3->tmp_filename, s3->filename);
    } else {
        dzlog_error("failed to download %s", s3->filename);
    }
    s3_downloader_free(s3);
    return result;
}

/*
 * ###################
 * # SECTION FS_NODE
 * ###################
 */

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
        return strlen(var.value) > 0;
    }

    if (strcmp(var.name, ENV_REGISTRY_SECRET_KEY) == 0) {
        node->registry->secret_key = strdup(var.value);
        return strlen(var.value) > 0;
    }

    if (strcmp(var.name, ENV_API_ACCESS_KEY) == 0) {
        node->info->api_access_key = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_API_SECRET_KEY) == 0) {
        node->info->api_secret_key = strdup(var.value);
        return var.value > 0;
    }

    if (strcmp(var.name, ENV_AWS_SERVICE) == 0) {
        node->aws->service = strdup(var.value);
        return true;
    }

    if (strcmp(var.name, ENV_AWS_REGION) == 0) {
        node->aws->region = strdup(var.value);
        return true;
    }

    if (strcmp(var.name, ENV_AWS_S3_BUCKET) == 0) {
        node->aws->bucket = strdup(var.value);
        return true;
    }

    if (strcmp(var.name, ENV_AWS_ACCESS_KEY) == 0) {
        node->aws->access_key = strdup(var.value);
        return true;
    }

    if (strcmp(var.name, ENV_AWS_SECRET_KEY) == 0) {
        node->aws->secret_key = strdup(var.value);
        return true;
    }

    return true;
}

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

    if (file->handle != NULL) {
        fclose(file->handle);
        file->handle = NULL;
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

int fs_node_get_file(FSNode *node, const char *filename, Range range, File *out) {
    char *full_path = fs_node_full_path(node, filename);
    if (full_path == NULL) {
        return 1;
    }

    const char *mime = magic_file(node->magic_cookie, full_path);
    out->mime_type = strdup(mime);

    FILE *file;
    while ((file = fopen(full_path, "r")) == NULL) {
        if (errno != ENOENT || fs_node_download_file_from_storage(node, filename) != 0) {
            return 1;
        }
    }
    free(full_path);

    // handle offset and limit
    int res = fseek(file, 0L, SEEK_END);
    if (res < 0) {
        return 1;
    }
    out->size = ftell(file);

    switch (range.type) {
        case range_full:
            res = fseek(file, (long) range.offset, SEEK_SET);
            if (res < 0) {
                fclose(file);
                return 1;
            }

            if (range.limit <= 0 || range.limit > out->size) {
                out->limit = out->size - 1;
            } else {
                out->limit = (long) range.limit;
            }
            out->available = (long) (out->limit - range.offset + 1);
            break;
        case range_prefix:
            res = fseek(file, (long) range.offset, SEEK_SET);
            if (res < 0) {
                fclose(file);
                return 1;
            }
            out->limit = out->size - 1;
            out->available = (long) (out->limit - range.offset + 1);
            break;
        case range_suffix:
            if (fseek(file, -1 * ((long) range.limit), SEEK_END) != 0) {
                fclose(file);
                return 1;
            }
            out->limit = out->size - 1;
            out->available = (long) (out->limit - range.offset + 1);
            break;
        case range_unspecified:
            out->available = out->size;
            break;
    }

    out->handle = file;
    return 0;
}

int fs_node_delete_file(FSNode *node, const char *filepath) {
    char *full_path = fs_node_full_path(node, filepath);
    int result = remove(full_path);
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
        return handle_error(1, "failed to update node info.");
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
            handle_error(1, "failed to generate RSA key pair.");
            return 1;
        }
    }

    if (save_rsa_private_key(FS_NODE_SERVICE_KEY_FILENAME, p_key) != 0) {
        handle_error(1, "failed to save generated RSA key pair.");
        EVP_PKEY_free(p_key);
        return 1;
    }

    X509_REQ *csr = generate_certificate_sign_request(p_key);
    EVP_PKEY_free(p_key);
    if (csr == NULL) {
        handle_error(1, "failed to generate certificate sign request.");
        return 1;
    }

    size_t csr_len = 0;
    char *csr_bytes = certificate_sign_request_to_bytes(csr, &csr_len);
    X509_REQ_free(csr);
    if (csr_bytes == NULL) {
        handle_error(1, "failed to encode certificate sign request.");
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
        return handle_error(1, "failed to sign certificate.");
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

void ssl_info_callback(const SSL *ssl, int where, int ret) {
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
    }
}

int fs_node_init_service_tls_context(FSNode *node) {
    node->ssl_server_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(node->ssl_server_ctx, TLS1_2_VERSION);  // Minimum supported version is TLS 1.2
    SSL_CTX_set_max_proto_version(node->ssl_server_ctx, TLS1_3_VERSION);

    if (SSL_CTX_use_certificate_file(node->ssl_server_ctx, FS_NODE_SERVICE_CERT_FILENAME, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(node->ssl_server_ctx, FS_NODE_SERVICE_KEY_FILENAME, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (!SSL_CTX_check_private_key(node->ssl_server_ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_info_callback(node->ssl_server_ctx, &ssl_info_callback);

    return 0;
}
/*
 * ###################
 * # HTTP SERVICE REQUEST HANDLING
 * ###################
*/

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
        http_header_set(rsp, strdup(HTTP_HEADER_DATE), http_get_date_header());
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
        http_header_set(rsp, strdup(HTTP_HEADER_DATE), http_get_date_header());
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
    http_header_set(rsp, strdup(HTTP_HEADER_DATE), http_get_date_header());
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
void http_on_write(uv_write_t *req, int status) {
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
 * @brief Creates a new instance of Client.
 *
 * This function allocates memory for an instance of Client and initializes its members.
 *
 * @return Pointer to the newly created Client instance, or NULL if memory allocation fails.
 */
Client *client_new() {
    Client *client = (Client *) malloc(sizeof(Client));
    if (client == NULL) {
        return NULL;
    }

    client->buf = NULL;
    client->file_fullname = NULL;

    client->parser = http_new_parser();
    if (client->parser == NULL) {
        free(client);
        client = NULL;
    }

    client->uploaded_bytes_count = 0;
    client->upload_dst = 0;
    client->upload_dst_open_req = NULL;
    return client;
}

int uv_tls_encrypt(Client *client, const char *data, size_t data_len, char **out, size_t *out_len) {
    if (SSL_write(client->tls->ssl, data, (int) data_len) <= 0) {
        return 1;
    }

    *out_len = BIO_ctrl(client->tls->write, BIO_CTRL_INFO, 0, NULL);
    if (*out_len < 0) {
        return 1;
    }

    *out = malloc(*out_len);
    if (*out == NULL) {
        return 1;
    }

    int read = BIO_read(client->tls->write, *out, (int) *out_len);
    if (read <= 0) return read;

    *out_len = (size_t) read;
    return 0;
}

int uv_tls_decrypt(Client *client, const char *data, size_t data_len, char **out, size_t *out_len) {
    StreamBIO *write_stream = BIO_get_data(client->tls->write);
    if (write_stream->should_flush) {
        if (write_stream->limit - write_stream->offset > 0) {
            return DECRYPT_RESULT_SHOULD_WRITE_DATA;
        }
        write_stream->should_flush = false;
    }

    int result = BIO_write(client->tls->read, data, (int) data_len);
    if (result <= 0) {
        return DECRYPT_RESULT_ERROR;
    }

    size_t total_read = 0;
    char *buf = malloc(1024);
    if (buf == NULL) {
        return DECRYPT_RESULT_ERROR;
    }

    while(true) {
        int read = SSL_read(client->tls->ssl, buf, 1024);
        if (read <= 0) {

            int ssl_error = SSL_get_error(client->tls->ssl, read);
            unsigned long ssl_error_code = ERR_get_error();
            char ssl_error_str[256];
            ERR_error_string_n(ssl_error_code, ssl_error_str, sizeof(ssl_error_str));
            free(buf);

            switch(ssl_error) {
                case SSL_ERROR_WANT_READ:
                    if (write_stream->should_flush) {
                        return DECRYPT_RESULT_SHOULD_WRITE_DATA;
                    }
                    return DECRYPT_RESULT_NEED_MORE_DATA;
                case SSL_ERROR_WANT_WRITE:
                    return DECRYPT_RESULT_SHOULD_WRITE_DATA;
                default:
                    fprintf(stderr, "SSL error: %s\n", ssl_error_str);
                    if (*out != NULL) {
                        free(*out);
                    }
                    return DECRYPT_RESULT_ERROR;
            }
            return read;
        }

        char *new_result = realloc(*out, total_read + (size_t) read);
        if (new_result == NULL) {
            if (*out != NULL) free(*out);
            free(buf);
            return DECRYPT_RESULT_ERROR;
        }

        *out = new_result;
        memcpy(*out + total_read, buf, read);
        total_read += (size_t) read;
    }

    free(buf);
    *out_len = total_read;
    return DECRYPT_RESULT_OK;
}

void uv_tls_send_written(Client *client) {
    size_t size = (size_t) BIO_pending(client->tls->write);
    if (size == 0) {
        return;
    }

    char *buf = (char *) malloc(size);
    if (buf == NULL) {
        return;
    }

    int read_len = BIO_read(client->tls->write, buf, (int) size);
    if (read_len < 0) {
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    uv_client_send(client, buf, read_len);
}

void uv_tls_write_data(Client *client, const char* data, size_t data_len) {

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

    if (client->parser != NULL) {
        http_parser_free(client->parser);
        client->parser = NULL;
    }

    if (client->buf != NULL) {
        free(client->buf);
        client->buf = NULL;
    }

    if (client->file_fullname != NULL) {
        free(client->file_fullname);
        client->file_fullname = NULL;
    }

    if (client->upload_dst_open_req != NULL) {
        free(client->upload_dst_open_req);
        client->upload_dst_open_req = NULL;
    }

    client = NULL;
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
    free(handle);
}

/**
 * Writes response headers to the given Client
 *
 * @param client The Client to write response headers to
 * @param data The response headers to write
 */
void uv_client_send(Client *client, const char *data, size_t len) {
    uv_write_t *wr = (uv_write_t *) malloc(sizeof(uv_write_t));
    if (wr == NULL) {
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    uv_buf_t buf = uv_buf_init((char *) data, len);
    wr->data = (char *) data;
    uv_write(wr, (uv_stream_t *) &client->handle, &buf, 1, http_on_write);
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
void uv_on_file_bytes_written(uv_write_t *req, int status) {
    Client *client = (Client *) req->data;
    if (status || client->bytes_sent == client->bytes_total) {
        uv_fs_req_cleanup(&client->req);
        uv_fs_t close_req;
        uv_fs_close(uv_default_loop(), &close_req, client->req.file, NULL);
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    uv_buf_t buf = uv_buf_init(client->buf, client->buf_len);
    uv_fs_read(uv_default_loop(), &client->req, client->req.file, &buf, 1, (int64_t) client->file_offset, uv_on_file_read);
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
void uv_on_file_read(uv_fs_t *req) {
    Client *client = (Client *) req->data;
    if (req->result <= 0) {
        dzlog_info("client connexion closed");
        uv_fs_req_cleanup(&client->req);
        uv_fs_t close_req;
        uv_fs_close(uv_default_loop(), &close_req, req->file, NULL);
        uv_close((uv_handle_t *) req->data, uv_on_client_close);
        return;
    }

    size_t bytes_to_send = req->result;
    if (client->bytes_sent + bytes_to_send > client->bytes_total) {
        bytes_to_send = client->bytes_total - client->bytes_sent;
    }

    uv_write_t *wr = malloc(sizeof(uv_write_t));
    wr->data = client;
    uv_buf_t buf = uv_buf_init(client->buf, bytes_to_send);
    uv_write(wr, (uv_stream_t *) &client->handle, &buf, 1, uv_on_file_bytes_written);

    client->bytes_sent += bytes_to_send;
    client->file_offset += bytes_to_send;
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
void uv_on_file_opened(uv_fs_t *req) {
    Client *client = (Client *) req->data;
    if (req->result <= 0) {
        uv_fs_req_cleanup(&client->req);
        HTTPObject *rsp = http_response("500", "INTERNAL SERVER ERROR");
        char *raw_rsp = http_raw(rsp);
        uv_client_send(client, raw_rsp, strlen(raw_rsp));
        http_object_free(rsp);
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    const char *uri = http_request_uri(client->parser->r);

    File *info = malloc(sizeof(File));
    if (info == NULL) {
        uv_fs_close(uv_default_loop(), &client->req, client->req.file, NULL);
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    if (fs_node_get_file(client->fs_node, uri, client->range, info) != 0) {
        uv_fs_close(uv_default_loop(), &client->req, client->req.file, NULL);
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    client->bytes_total = info->available;
    client->file_offset = client->range.offset;

    const char *code = client->range.type != range_unspecified && info->available == info->size ? HTTP_STATUS_OK
                                                                                                : HTTP_STATUS_PARTIAL_CONTENT;
    HTTPObject *rsp = http_OK_response(code, (int) info->available, info->mime_type);
    if (rsp == NULL) {
        uv_fs_close(uv_default_loop(), &client->req, client->req.file, NULL);
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    if (client->range.type != range_unspecified) {
        char *range_bytes = malloc(100);
        if (range_bytes == NULL) {
            uv_fs_close(uv_default_loop(), &client->req, client->req.file, NULL);
            uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
            return;
        }

        sprintf(range_bytes, "bytes %lu-%lu/%lu", client->range.offset, info->limit, info->size);
        http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_RANGE), range_bytes);
    }

    http_header_set(rsp, strdup(HTTP_HEADER_CONTENT_LENGTH), int_to_str((int) info->available));
    http_header_set(rsp, strdup(HTTP_HEADER_ACCEPT_RANGES), strdup(HTTP_HEADER_ACCEPT_RANGES_BYTES_VALUE));
    char *raw_rsp = http_raw(rsp);
    uv_client_send(client, raw_rsp, strlen(raw_rsp));
    http_object_free(rsp);
    fs_file_free(info);

    client->buf = (char *) malloc(FILE_CHUNK_SIZE);
    if (client->buf == NULL) {
        uv_fs_close(uv_default_loop(), &client->req, client->req.file, NULL);
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    client->buf_len = FILE_CHUNK_SIZE;
    client->req.file = (uv_file) req->result;
    client->req.data = client;

    int64_t offset = (int64_t) client->range.offset;
    uv_buf_t buf = uv_buf_init(client->buf, client->buf_len);
    uv_fs_read(uv_default_loop(), &client->req, client->req.file, &buf, 1, offset, uv_on_file_read);
}

void uv_on_file_uploaded(uv_fs_t *req) {
    uv_fs_req_cleanup(req);
    free(req);
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
void uv_on_client_data(uv_stream_t *handle, ssize_t buf_size, const uv_buf_t *buf) {
    if (buf_size < 0) {
        uv_close((uv_handle_t *) handle, uv_on_client_close);
        return;
    }

    Client *client = (Client *) handle->data;

    char *data = NULL;
    size_t data_len = 0;
    int result = uv_tls_decrypt(client, buf->base, buf_size, &data, &data_len);
    if (result != DECRYPT_RESULT_OK) {
        switch (result) {
            case DECRYPT_RESULT_NEED_MORE_DATA:
                return;
            case DECRYPT_RESULT_SHOULD_WRITE_DATA:
                uv_tls_send_written(client);
                return;
            default:
                uv_close((uv_handle_t *) handle, uv_on_client_close);
                return;
        }
    }

    int data_index = 0;
    if ((data_index = http_parse(client->parser, data, data_len)) < 0) {
        uv_close((uv_handle_t *) handle, uv_on_client_close);
        return;
    }

    if (client->parser->state != PARSE_BODY) {
        return;
    }

    HTTPObject *r = client->parser->r;
    const char *method = http_request_method(r);
    const char *uri = http_request_uri(r);

    // Validating the URI
    if (strstr(uri, "..") != NULL) {
        dzlog_error("uri contains '..'");
        HTTPObject *rsp = http_response(HTTP_STATUS_BAD_REQUEST, "BAD REQUEST");
        char *raw_rsp = http_raw(rsp);
        uv_client_send(client, raw_rsp, strlen(raw_rsp));
        http_object_free(rsp);
        uv_close((uv_handle_t *) handle, uv_on_client_close);
        return;
    }

    const char *c = uri;
    int slash_count = 0;
    while (*c != '\0') {
        if ((*c != '/' && !isalnum(*c) && *c != '.' && *c != '-') || (*c == '/' && slash_count > 1)) {
            HTTPObject *rsp = http_response(HTTP_STATUS_BAD_REQUEST, "BAD REQUEST");
            char *raw_rsp = http_raw(rsp);
            uv_client_send(client, raw_rsp, strlen(raw_rsp));
            http_object_free(rsp);
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }
        if (*c == '/') slash_count++;
        c++;
    }

    if (strcmp(method, HTTP_METHOD_GET) == 0) {
        if (strcmp(uri, "/favicon.ico") == 0) {
            HTTPObject *rsp = http_response("404", "NOT FOUND");
            char *raw_rsp = http_raw(rsp);
            uv_client_send(client, raw_rsp, strlen(raw_rsp));
            http_object_free(rsp);
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }

        if (http_get_content_range(client->parser->r, &client->range) != 0) {
            HTTPObject *rsp = http_response("404", "NOT FOUND");
            char *raw_rsp = http_raw(rsp);
            uv_client_send(client, raw_rsp, strlen(raw_rsp));
            http_object_free(rsp);
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }

        int pull_file_result;
        bool downloaded = false;

        if ((pull_file_result = fs_node_pull_storage_file(client->fs_node, uri, &downloaded)) != 0) {
            HTTPObject *rsp = NULL;
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
            char *raw_rsp = http_raw(rsp);
            uv_client_send(client, raw_rsp, strlen(raw_rsp));
            http_object_free(rsp);
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }

        if (downloaded) {
            uv_work_t *req = (uv_work_t *) malloc(sizeof(uv_work_t));
            req->data = client->fs_node;
            uv_queue_work(uv_default_loop(), req, task_prune_work, task_after_prune);
        }

        client->file_fullname = fs_node_full_path(client->fs_node, uri);
        if (client->file_fullname == NULL) {
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }

        uv_fs_t *file = (uv_fs_t *) malloc(sizeof(uv_fs_t));
        if (file == NULL) {
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }
        file->data = client;
        uv_fs_open(uv_default_loop(), file, client->file_fullname, O_RDONLY, 0, uv_on_file_opened);
        return;
    }

    if (strcmp(method, HTTP_METHOD_PUT) == 0) {
        if (client->file_fullname == NULL) {
            client->file_fullname = fs_node_full_path(client->fs_node, uri);
            if (client->file_fullname == NULL) {
                uv_close((uv_handle_t *) handle, uv_on_client_close);
                return;
            }

            client->upload_dst_open_req = (uv_fs_t *) malloc(sizeof(uv_fs_t));
            if (client->upload_dst_open_req == NULL) {
                free(client->file_fullname);
                uv_close((uv_handle_t *) handle, uv_on_client_close);
                return;
            }

            client->upload_dst = uv_fs_open(uv_default_loop(), client->upload_dst_open_req, client->file_fullname, O_WRONLY | O_CREAT | O_TRUNC, 0644, NULL);

            if (client->upload_dst < 0) {
                HTTPObject *rsp = http_response(HTTP_STATUS_INTERNAL, "INTERNAL SERVER ERROR");
                char *raw_rsp = http_raw(rsp);
                uv_client_send(client, raw_rsp, strlen(raw_rsp));
                http_object_free(rsp);
                uv_close((uv_handle_t *) handle, uv_on_client_close);
                return;
            }

        }

        uv_fs_t *write_req = (uv_fs_t *) malloc(sizeof(uv_fs_t));
        uv_buf_t wrbuf = uv_buf_init(buf->base + data_index, buf_size - data_index);
        uv_fs_write(uv_default_loop(), write_req, client->upload_dst, &wrbuf, 1, -1, uv_on_file_uploaded);
        client->uploaded_bytes_count += buf_size - data_index;

        if (buf_size == 0 || client->uploaded_bytes_count == client->parser->r->content_length) {
            uv_fs_close(uv_default_loop(), client->upload_dst_open_req, client->upload_dst_open_req->file, NULL);

            HTTPObject *rsp = http_response(HTTP_STATUS_OK, "OK");
            char *raw_rsp = http_raw(rsp);
            uv_client_send(client, raw_rsp, strlen(raw_rsp));
            http_object_free(rsp);
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }
        return;
    }

    if (strcmp(method, HTTP_METHOD_DELETE) == 0) {
        if (fs_node_delete_file(client->fs_node, uri) != 0) {
            HTTPObject *rsp = http_response("500", "INTERNAL SERVER ERROR");
            char *raw_rsp = http_raw(rsp);
            uv_client_send(client, raw_rsp, strlen(raw_rsp));
            http_object_free(rsp);
            uv_close((uv_handle_t *) handle, uv_on_client_close);
            return;
        }
        return;
    }

    uv_close((uv_handle_t *) handle, uv_on_client_close);
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
    if (suggested_size < TLS_RECORD_MAX_SIZE) {
        suggested_size = TLS_RECORD_MAX_SIZE;
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

    FSNode *fs_node = (FSNode *) server->data;

    Client *client = client_new();
    if (client == NULL || uv_tcp_init(server->loop, &client->handle) != 0) {
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        return;
    }

    if (uv_accept(server, (uv_stream_t *) &client->handle) == 0) {
        client->fs_node = fs_node;
        client->handle.data = client;
        client->tls = tls_session_new(fs_node->ssl_server_ctx);
        if(client->tls == NULL) {
            tls_session_free(client->tls);
            ERR_print_errors_fp(stderr);
            uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
            return;
        }
        uv_read_start((uv_stream_t *) &client->handle, uv_on_alloc_buffer, uv_on_client_data);
    } else {
        uv_close((uv_handle_t *) &client->handle, uv_on_client_close);
        client_free(client);
    }
}

/*
 * ###################
 * # SERVICE RUNNER
 * ###################
 */
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

    server->tcp.data = server->node;

    uv_tcp_bind(&server->tcp, (const struct sockaddr *) &sa, 0);
    int result = uv_listen((uv_stream_t *) &server->tcp, 1024, on_connection);
    if (result) {
        dzlog_error("Listen error %s", uv_strerror(result));
        return 1;
    }

    dzlog_info("%s server: port %d", server->name, server->port);
    return 0;
}

int main(void) {
    if (dzlog_init("zlog.conf", "fsnode")) {
        printf("zlog initialization failed\n");
        return -1;
    }

    zlog_category_t *log_c = zlog_get_category("fsnode");
    if (!log_c) {
        printf("zlog get category failed\n");
        zlog_fini();
        return -2;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    FSNode *node = fs_node_new();
    if (node == NULL) {
        return 1;
    }

    // Parsing .env handle
    if (env_load((void *) node, fs_node_set_env_var) != 0) {
        dzlog_error("failed to load env variable");
        return 1;
    }

    if (fs_node_init(node) != 0) {
        fs_node_free(node);
        return 1;
    }

    if (fs_node_get_signed_certificate(node) != 0) {
        fs_node_free(node);
        dzlog_error("could not get certificate");
        return 1;
    }

    if (fs_node_init_service_tls_context(node) != 0) {
        fs_node_free(node);
        dzlog_error("failed to initialize service tls context");
        return 1;
    }

    fs_node_get_disk_usage(node->disk->dir, &node->disk->usage);
    fs_node_publish_info(node);

    Server *http = malloc(sizeof(Server));
    http->node = node;
    http->port = node->info->port;
    http->name = "http";
    if (svc_serve(http, uv_on_new_client) != 0) {
        dzlog_info("failed to run HTTP service");
        fs_node_free(node);
        free(http);
        return 1;
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    fs_node_free(node);
    free(http);
    return 0;
}
