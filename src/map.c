//
// Created by Jabar Karim on 25/08/2024.
//

#include "map.h"

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