//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_UTILS_H
#define FSNODE_UTILS_H

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>
#include <time.h>

#define KB 1024
#define MB (KB * 1024)
#define GB (MB * 1024)

#define unused(x) (void)(x)

char *toLower(const char *);

char *hex(const char *bytes, size_t length);

char *iso8601_date_from_time(struct tm *tm_info);

int parse_iso8601_date(const char *iso8601_str, struct tm *tm_info);

char *date_from_time(struct tm *tm_info);

char *trim(const char *str);

char *int_to_str(int value);

int str_to_size_t(const char *str, size_t *val);

int parse_size(const char *str_size, uint64_t *out_size);

int read_file(const char *name, char **out, size_t *out_len);

#endif //FSNODE_UTILS_H
