//
// Created by Jabar Karim on 25/08/2024.
//


#include "utils.h"

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

int parse_iso8601_date(const char *iso8601_str, struct tm *tm_info) {
    memset(tm_info, 0, sizeof(struct tm));

    // Define the ISO 8601 format that we're going to parse
    // Example format: "2023-08-25T14:30:00"
    const char *iso8601_format = "%Y%m%dT%H%M%SZ";

    // Use strptime to parse the string into the tm structure
    if (strptime(iso8601_str, iso8601_format, tm_info) == NULL) {
        return 1;
    }

    // Adjust the tm_info fields
    tm_info->tm_isdst = -1;  // Daylight Saving Time flag (-1 to let system determine)

    return 0;
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
    char *buffer = (char *) malloc(file_size + 1);  // +1 for the null terminator
    if (buffer == NULL) {
        fclose(file);
        return 1;
    }

    // Read file content into the buffer
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != (size_t) file_size) {
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
