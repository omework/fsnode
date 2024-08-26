//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_LIST_H
#define FSNODE_LIST_H

#include <stdlib.h>

typedef struct {
    size_t cap;
    size_t len;
    void **items;
} List;

List *list_create();

void list_grow(List *list, size_t count);

void* list_get(List *list, size_t index);

void list_add(List *list, char *item);

void *list_pop(List *list);

void *list_pop_head(List *list);

void list_clear(List *list);

void list_free(List *list);

#endif //FSNODE_LIST_H
