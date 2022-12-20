#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

int main(int argc, char const *argv[]) {
    struct timeval st, et, total_st, total_et, first_st;
    int elapsed;

    gettimeofday(&first_st,NULL);

    int serv_sock, clnt_sock;
    const char *PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);

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
        exit(0);
    }

    if (listen(serv_sock, 5) == -1) {
        exit(0);
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock =
        accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock < 0) {
        printf("server accept failed...\n");
        exit(0);
    } else
        printf("server accept the client...\n");
    unsigned char received_buf[1024];
    unsigned int received_buf_length = 0;
    int num_runs = 100;
     gettimeofday(&total_st,NULL);
    for (int i = 0; i < num_runs; i++) {
        gettimeofday(&st, NULL);
        received_buf_length =
            read(clnt_sock, received_buf, sizeof(received_buf));
        printf("%dth message: %s\n", i,received_buf);
        write(clnt_sock, "Hello client", sizeof("Hello client"));
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
    printf("Total elapsed time of setup + %d rounds : %d micro seconds\n", num_runs, total_elapsed);
}
