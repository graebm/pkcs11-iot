#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/logging.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/io.h>
#include <aws/io/pkcs11.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <stdio.h>
#include <string.h>

/* things you might want to tweak */
#define LOG_LEVEL AWS_LL_INFO
#define TIMEOUT_SEC 1

/* misc */
#define TIMEOUT_MS (TIMEOUT_SEC * 1000)
#define TIMEOUT_NS (TIMEOUT_SEC * 1000000000ULL)

#define FAIL(MSG) do {printf(MSG); exit(-1);} while(0);

#define ASSERT_SUCCESS(EXPR) \
    do { \
        if ((EXPR) != AWS_OP_SUCCESS) { \
            printf("Failed at line %d: `" #EXPR "` last-error: %s\n", \
            __LINE__, \
            aws_error_name(aws_last_error())); \
            exit(-1); \
        } \
    } while (0)

#define ASSERT_NOT_NULL(EXPR) \
    do { \
        if ((EXPR) == NULL) { \
            printf("Failed at line %d: failed to create `" #EXPR "` last-error: %s\n", \
            __LINE__, \
            aws_error_name(aws_last_error())); \
            exit(-1); \
        } \
    } while (0)

struct aws_allocator *g_alloc;
struct aws_mutex g_mutex = AWS_MUTEX_INIT;
struct aws_condition_variable g_cvar = AWS_CONDITION_VARIABLE_INIT;
bool g_connection_complete;
int g_connection_error_code;

struct aws_string *envvar(const char *name) {
    struct aws_string *name_str = aws_string_new_from_c_str(g_alloc, name);
    struct aws_string *value = NULL;
    aws_get_environment_value(g_alloc, name_str, &value);
    aws_string_destroy(name_str);
    printf("%s: %s\n", name, value ? aws_string_c_str(value) : "");
    return value;
}

void on_connection_setup(struct aws_client_bootstrap *bootstrap,
                         int error_code,
                         struct aws_channel *channel,
                         void *user_data) {
    if (error_code == 0) {
        printf("Connection successfully established! Shutting down...\n");
        aws_channel_shutdown(channel, 0);
    } else {
        printf("Connection failed. error-code: %s\n", aws_error_name(error_code));

        /* wake main thread */
        aws_mutex_lock(&g_mutex);
        g_connection_complete = true;
        g_connection_error_code = error_code;
        aws_mutex_unlock(&g_mutex);
        aws_condition_variable_notify_all(&g_cvar);
    }
}

void on_connection_shutdown(struct aws_client_bootstrap *bootstrap,
                            int error_code,
                            struct aws_channel *channel,
                            void *user_data) {
    printf("Connection shutdown complete\n");

    /* wake main thread */
    aws_mutex_lock(&g_mutex);
    g_connection_complete = true;
    aws_mutex_unlock(&g_mutex);
    aws_condition_variable_notify_all(&g_cvar);
}

bool is_connection_complete(void *user_data) {
    return g_connection_complete;
}

int main(int argc, char **argv) {
    /*********** init ***********/
    g_alloc = aws_default_allocator();
    aws_io_library_init(g_alloc);

    /* logger */
    struct aws_logger_standard_options logger_opts = {
        .file = stdout,
        .level = LOG_LEVEL,
    };
    struct aws_logger logger;
    aws_logger_init_noalloc(&logger, g_alloc, &logger_opts);
    aws_logger_set(&logger);

    /* read env vars */
    struct aws_string *endpoint = envvar("ENDPOINT");
    struct aws_string *port = envvar("PORT");
    struct aws_string *pkcs11_lib_path = envvar("PKCS11_LIB_PATH");
    struct aws_string *pkcs11_user_pin = envvar("PKCS11_USER_PIN");
    struct aws_string *pkcs11_token_label = envvar("PKCS11_TOKEN_LABEL");
    struct aws_string *pkcs11_key_label = envvar("PKCS11_KEY_LABEL");
    struct aws_string *cert_file = envvar("CERT_FILE");
    struct aws_string *root_ca = envvar("ROOT_CA");

    if (!endpoint || !port) {
        FAIL("ENDPOINT and PORT env-vars must be defined");
    }

    /* PKCS#11 lib */
    struct aws_pkcs11_lib_options pkcs11_lib_opts = {0};
    if (pkcs11_lib_path) {
        pkcs11_lib_opts.filename = aws_byte_cursor_from_string(pkcs11_lib_path);
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(g_alloc, &pkcs11_lib_opts);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* PKCS#11 TLS options */
    struct aws_tls_ctx_pkcs11_options pkcs11_tls_opts = {
        .pkcs11_lib = pkcs11_lib,
    };

    if (pkcs11_user_pin) {
        pkcs11_tls_opts.user_pin = aws_byte_cursor_from_string(pkcs11_user_pin);
    }

    if (pkcs11_token_label) {
        pkcs11_tls_opts.token_label = aws_byte_cursor_from_string(pkcs11_token_label);
    }

    if (pkcs11_key_label) {
        pkcs11_tls_opts.private_key_object_label = aws_byte_cursor_from_string(pkcs11_key_label);
    }

    if (cert_file) {
        pkcs11_tls_opts.cert_file_path = aws_byte_cursor_from_string(cert_file);
    }

    /* TLS context */
    struct aws_tls_ctx_options tls_ctx_opts;
    ASSERT_SUCCESS(aws_tls_ctx_options_init_client_mtls_with_pkcs11(&tls_ctx_opts, g_alloc, &pkcs11_tls_opts));
    if (root_ca) {
        ASSERT_SUCCESS(aws_tls_ctx_options_override_default_trust_store_from_path(&tls_ctx_opts, NULL, aws_string_c_str(root_ca)));
    }
    struct aws_tls_ctx *tls_ctx = aws_tls_client_ctx_new(g_alloc, &tls_ctx_opts);
    ASSERT_NOT_NULL(tls_ctx);

    /* TLS connection options */
    struct aws_tls_connection_options tls_connection_opts;
    aws_tls_connection_options_init_from_ctx(&tls_connection_opts, tls_ctx);
    struct aws_byte_cursor server_name = aws_byte_cursor_from_string(endpoint);
    aws_tls_connection_options_set_server_name(&tls_connection_opts, g_alloc, &server_name);
    tls_connection_opts.timeout_ms = TIMEOUT_MS;

    /* socket options */
    struct aws_socket_options socket_opts = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = TIMEOUT_MS,
    };

    /* event loop group - aka network I/O thread pool */
    struct aws_event_loop_group *event_loop_group = aws_event_loop_group_new_default(g_alloc, 1/*threads*/, NULL/*callbacks*/);

    /* DNS host resolver */
    struct aws_host_resolver_default_options resolver_opts = {
        .el_group = event_loop_group,
    };
    struct aws_host_resolver *host_resolver = aws_host_resolver_new_default(g_alloc, &resolver_opts);

    /* client bootstrap - helps establish client network connections */
    struct aws_client_bootstrap_options bootstrap_opts = {
        .event_loop_group = event_loop_group,
        .host_resolver = host_resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(g_alloc, &bootstrap_opts);

    /* kick off network connection */
    struct aws_socket_channel_bootstrap_options channel_bootstrap_opts = {
        .bootstrap = client_bootstrap,
        .host_name = aws_string_c_str(endpoint),
        .port = atoi(aws_string_c_str(port)),
        .socket_options = &socket_opts,
        .tls_options = &tls_connection_opts,
        .setup_callback = on_connection_setup,
        .shutdown_callback = on_connection_shutdown,
    };
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_bootstrap_opts));

    /* wait for connection to finish setup & teardown */
    aws_mutex_lock(&g_mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(&g_cvar, &g_mutex, (int64_t)TIMEOUT_NS, is_connection_complete, NULL));
    aws_mutex_unlock(&g_mutex);

    /*********** clean up ***********/

    aws_client_bootstrap_release(client_bootstrap);
    aws_host_resolver_release(host_resolver);
    aws_event_loop_group_release(event_loop_group);
    aws_string_destroy(endpoint);
    aws_string_destroy(port);
    aws_string_destroy(pkcs11_lib_path);
    aws_string_destroy(pkcs11_user_pin);
    aws_string_destroy(pkcs11_token_label);
    aws_string_destroy(pkcs11_key_label);
    aws_string_destroy(cert_file);
    aws_string_destroy(root_ca);
    aws_tls_connection_options_clean_up(&tls_connection_opts);
    aws_tls_ctx_release(tls_ctx);
    aws_tls_ctx_options_clean_up(&tls_ctx_opts);
    aws_pkcs11_lib_release(pkcs11_lib);

    /* wait for background threads to join */
    aws_thread_set_managed_join_timeout_ns(TIMEOUT_NS);
    ASSERT_SUCCESS(aws_thread_join_all_managed());

    aws_logger_set(NULL);
    aws_logger_clean_up(&logger);

    aws_io_library_clean_up();

    printf("SAMPLE SUCCESS!\n");
    return 0;
}
