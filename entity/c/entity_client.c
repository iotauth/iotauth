#include "c_api.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];

    ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx);
    int sock = secure_connect_to_server(&s_key_list->s_key[0], ctx);
    printf("finished\n");
    pthread_t thread;
    arg_struct_t args = {.sock = &sock, .s_key = &s_key_list->s_key[0]};
    pthread_create(&thread, NULL, &receive_thread, (void *)&args);
    sleep(1);
    send_secure_message("Hello World", strlen("Hello World"),
                        &s_key_list->s_key[0], sock);
    sleep(1);
    send_secure_message("Hello Dongha", strlen("Hello Dongha"),
                        &s_key_list->s_key[0], sock);
    sleep(1);

    sleep(60);
}
