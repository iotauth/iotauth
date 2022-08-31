#include "c_api.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    printf("finished\n");
    // sleep(1);  // TODO: If erase this comment, MAC error happens at HS_3
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread, (void *)session_ctx);
    send_secure_message("Hello World", strlen("Hello World"), session_ctx);
    sleep(1);
    send_secure_message("Hello Dongha", strlen("Hello Dongha"), session_ctx);
    sleep(1);

    s_key_list = get_session_key(ctx, s_key_list);

    s_key_list = get_session_key(ctx, s_key_list);

    s_key_list = get_session_key(ctx, s_key_list);

    free_session_key_list_t(s_key_list);

    free_SST_ctx(ctx);

    sleep(60);
}
