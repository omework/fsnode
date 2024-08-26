//
// Created by Jabar Karim on 25/08/2024.
//

#include "echo.h"


void echo_recv(const context_t ctx, const char *data, size_t len) {
    char * copy = (char *) malloc(len);
    memcpy(copy, data, len);
    printf("received: \n");
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\r') continue;
        // Print each byte as a character
        printf("%c", data[i]);
    }
    ctx_send_data(ctx, copy, len, NULL);
}

any_t echo_create_recv_handler(any_t param) {
    unused(param);
    EchoReceiver *echo = (EchoReceiver *) malloc(sizeof (EchoReceiver));
    return echo;
}

void echo_destroy_recv_handler(any_t handler) {
    EchoReceiver *echo = (EchoReceiver *) handler;
    if (echo != NULL) {
        free(echo);
    }
}

svc_handler_t * new_echo_svc_handler() {
    svc_handler_t* handler = (svc_handler_t *) malloc(sizeof(svc_handler_t));
    if (handler == NULL) {
        return NULL;
    }

    handler->create_param = NULL;
    handler->create_recv_handler = echo_create_recv_handler;
    handler->destroy_recv_handler = echo_destroy_recv_handler;
    handler->recv_handle = echo_recv;

    return handler;
}