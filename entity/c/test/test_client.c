#include "../c_api.h"
#include <sys/time.h>
int main(int argc, char *argv[]) {
    struct timeval st, et, total_st, total_et, first_st;
    int elapsed;
    char *config_path = argv[1];
    gettimeofday(&first_st,NULL);
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    // printf("finished\n");
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length = 0;
    int num_runs = 100;
    gettimeofday(&total_st,NULL);
    for (int i = 0; i < num_runs; i ++){
        gettimeofday(&st,NULL);
        send_secure_message("Hello server", strlen("Hello server"), session_ctx);

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


}
