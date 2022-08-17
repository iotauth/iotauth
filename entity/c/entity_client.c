#include "c_api.h"

int main() {
    char path[] = "c_client.config";
    config_t *config_info = load_config(path);

    session_key_list_t *s_key_list = get_session_key(config_info);
    int sock = secure_connect_to_server(&s_key_list->s_key[0], config_info);
    printf("finished\n");
    pthread_t thread;
    arg_struct_t args = {.sock = sock, .s_key = &s_key_list->s_key[0]};
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
