//
// Created by Jabar Karim on 25/08/2024.
//

#ifndef FSNODE_ECHO_H
#define FSNODE_ECHO_H

#include <uv.h>

#include "fsnode.h"
#include "server.h"
#include "http.h"

typedef struct {
    Client *client;
} EchoReceiver;

typedef struct {
    Client *client;
} EchoSender;

void echo_recv(any_t a, const char *data, size_t len);

any_t echo_create_recv_handler(any_t param);

void echo_destroy_recv_handler(any_t handler);

svc_handler_t *new_echo_svc_handler();

#endif //FSNODE_ECHO_H
