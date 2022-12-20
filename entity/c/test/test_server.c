#include "../c_api.h"
#include <sys/time.h>

int main(int argc, char *argv[]) {
    struct timeval st, et, total_st, total_et, first_st;
    int elapsed;

    if (argc != 2) {
        error_handling("Enter config path");
    }

    int serv_sock, clnt_sock;
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
    gettimeofday(&first_st,NULL);
    // if (clnt_sock == -1) {
    //     error_handling("accept() error");
    // }

    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    INIT_SESSION_KEY_LIST(s_key_list);
    SST_session_ctx_t *session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, &s_key_list);
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length = 0;
    int num_runs = 100;
    // sleep(1);
    gettimeofday(&total_st,NULL);
    for (int i = 0; i < num_runs; i ++){
        gettimeofday(&st,NULL);
        received_buf_length =
            read(session_ctx->sock, received_buf, sizeof(received_buf));
        // if (received_buf_length == 0) {
        //     printf("Socket closed!\n");
        //     close(session_ctx->sock);
        //     return 0;
        // }
        // if (received_buf_length == -1) {
        //     printf("Connection error!\n");
        //     return 0;
        // }
        receive_message(received_buf, received_buf_length, session_ctx);
        send_secure_message("Hello client", strlen("Hello client"), session_ctx);
        gettimeofday(&et,NULL);
        elapsed = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        printf("Round %d time: %d micro seconds\n", i, elapsed);
    } 
    gettimeofday(&total_et,NULL);
    int num_runs_elapsed = (((total_et.tv_sec - total_st.tv_sec) * 1000000) + (total_et.tv_usec - total_st.tv_usec));
    int average_num_runs_elapsed = num_runs_elapsed / num_runs;
    printf("Average elapsed time of  %d rounds : %d micro seconds\n", num_runs, average_num_runs_elapsed);
    printf("Total elapsed time of  %d rounds : %d micro seconds\n", num_runs, num_runs_elapsed);
    int total_elapsed = (((total_et.tv_sec - first_st.tv_sec) * 1000000) + (total_et.tv_usec - first_st.tv_usec));
    printf("Total elapsed time of Auth connection + entity handshake + %d rounds : %d micro seconds\n", num_runs, total_elapsed);


    // send_secure_message("Hello client", strlen("Hello client"), session_ctx);

    // send_secure_message("Hello client - second message", strlen("Hello client - second message"), session_ctx);

}
