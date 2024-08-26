//
// Created by Jabar Karim on 25/08/2024.
//
#include "list.h"

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

    void *item = list->items[0];
    list->items[0] = NULL;

    for (size_t i = 0; i < list->len - 1; i++) {
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