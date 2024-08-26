//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_MAP_H
#define FSNODE_MAP_H

#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t cap;
    size_t len;
    char **names;
    char **values;
} Map;

Map *map_create();

int map_grow(Map *map, size_t count);

int map_set(Map *map, char *name, char *value);

const char *map_value(Map *map, char *name);

void map_free(Map *map);

#endif //FSNODE_MAP_H
