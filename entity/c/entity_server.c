#include "c_api.h"

extern int sent_seq_num;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        error_handling("Enter config path");
    }

    int serv_sock, clnt_sock, clnt_sock2;
    const char *PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        error_handling("socket() error");
    }
    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        printf("socket option set error\n");
        return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(PORT_NUM));

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        error_handling("bind() error");
    }

    if (listen(serv_sock, 5) == -1) {
        error_handling("listen() error");
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        error_handling("accept() error");
    }

    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    INIT_SESSION_KEY_LIST(s_key_list);
    session_key_t *s_key =
        server_secure_comm_setup(ctx, clnt_sock, &s_key_list);
        //TODO: return SST_session_ctx. - sock, s_key, r_seq_num, sent_seq_num

    pthread_t thread;
    arg_struct_t args = {.sock = &clnt_sock, .s_key = s_key};
    pthread_create(&thread, NULL, &receive_thread, (void *)&args);
    sleep(1);

    send_secure_message("Hello World", strlen("Hello World"), s_key, clnt_sock);
    sleep(1);
    send_secure_message("Hello Dongha", strlen("Hello Dongha"), s_key,
                        clnt_sock);
    sleep(1);
    close(clnt_sock);
    pthread_cancel(thread);
    printf("Finished first communication\n");

    // Second connection. session_key_list caches the session key.
    sent_seq_num = 0;  // TODO: temporarily resets sent_seq_num;
    clnt_sock2 =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock2 == -1) {
        error_handling("accept() error");
    }
    session_key_t *s_key2 =
        server_secure_comm_setup(ctx, clnt_sock2, &s_key_list);

    pthread_t thread2;
    arg_struct_t args2 = {.sock = &clnt_sock2, .s_key = s_key2};
    pthread_create(&thread2, NULL, &receive_thread, (void *)&args2);
    sleep(1);

    send_secure_message("Hello World", strlen("Hello World"), s_key2,
                        clnt_sock2);
    sleep(1);
    send_secure_message("Hello Dongha", strlen("Hello Dongha"), s_key2,
                        clnt_sock2);
    sleep(1);

    sleep(100);
    close(clnt_sock2);
    pthread_cancel(thread2);
    close(serv_sock);
}
