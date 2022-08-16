#include "c_api.h"

int main()
{

    int serv_sock, clnt_sock;
    const char *PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
    {
        error_handling("socket() error");
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(PORT_NUM));

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }

    if (listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1)
    {
        error_handling("accept() error");
    }
    char path[] = "c_server.config";
    config_t *config = load_config(path);
    session_key_t *s_key = server_secure_comm_setup(config, clnt_sock);

    printf("finished\n");
    pthread_t thread;
    arg_struct_t args = {
        .sock = clnt_sock,
        .s_key = s_key};
    pthread_create(&thread, NULL, &receive_thread, (void *)&args);
    sleep(1);

    send_secure_message("Hello World", strlen("Hello World"), s_key, clnt_sock);
    sleep(1);
    send_secure_message("Hello Dongha", strlen("Hello Dongha"), s_key, clnt_sock);
    sleep(1);
    // send_secure_message("Hello Yeongbin", strlen("Hello Yeongbin"),&session_key_list[0], sock);
    // sleep(10);
    // send_secure_message("Hello Yoonsang", strlen("Hello Yoonsang"),&session_key_list[0], sock);

    sleep(10);
    close(clnt_sock);
    close(serv_sock);
}
