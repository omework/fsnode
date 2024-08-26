//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_ENV_H
#define FSNODE_ENV_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include "utils.h"

typedef struct {
    const char *name;
    const char *value;
} env_var_t;

typedef bool (*env_var_cb)(void *container, env_var_t);

int env_load(void *container, env_var_cb var_cb);

#endif //FSNODE_ENV_H
