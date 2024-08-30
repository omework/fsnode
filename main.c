#include "fsnode.h"
#include "env.h"
#include "server.h"
#include "echo.h"
#include "cdn.h"

int main(void) {
    if (dzlog_init("zlog.conf", "fsnode")) {
        printf("zlog initialization failed\n");
        return 1;
    }

    zlog_category_t *log_c = zlog_get_category("fsnode");
    if (!log_c) {
        printf("zlog get category failed\n");
        zlog_fini();
        return 1;
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

    if ((node->ssl_server_ctx = fs_node_init_service_tls_context(
            FS_NODE_SERVICE_CERT_FILENAME,
            FS_NODE_SERVICE_KEY_FILENAME,
            false)) == NULL) {
        fs_node_free(node);
        dzlog_error("failed to initialize service tls context");
        return 1;
    }

    fs_node_get_disk_usage(node->disk->dir, &node->disk->usage);
    fs_node_publish_info(node);

    Server *svc = malloc(sizeof(Server));
    svc->port = node->info->port;
    svc->name = "http";
    svc->ssl_ctx = node->ssl_server_ctx;
    svc->svc_handler = new_http_svc_handler(node);

    if (svc_serve(svc, uv_on_new_client) != 0) {
        dzlog_info("failed to run HTTP service");
        fs_node_free(node);
        free(svc);
        return 1;
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    fs_node_free(node);
    free(svc);
    return 0;
}
