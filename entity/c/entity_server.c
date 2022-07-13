#include "c_api.h"

int main()
{
    // char path[] = "a.config";
    // config * config_info = load_config(path);

    // int serv_sock = init_server(config_info);

    int serv_sock, clnt_sock;
    const char * PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(serv_sock == -1){
        error_handling("socket() error");
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port=htons(atoi(PORT_NUM));

    if(bind(serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr))==-1){
        error_handling("bind() error");
    }

    if(listen(serv_sock, 5)==-1){
        error_handling("listen() error");
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if(clnt_sock==-1){
        error_handling("accept() error");
    }

    char path[] = "server.config";
    config_t * config = load_config(path);
    session_key_t * s_key = server_secure_comm_setup(config, clnt_sock);

    printf("finished\n");
    pthread_t thread;
    arg_struct_t args = {
        .sock = clnt_sock,
        .s_key = s_key
    };
    pthread_create(&thread, NULL, &receive_thread, (void *)&args);
    sleep(1);

    send_secure_message("Hello World", strlen("Hello World"), s_key, clnt_sock);
    sleep(1);
    send_secure_message("Hello Dongha", strlen("Hello Dongha"), s_key, clnt_sock);
    sleep(1);
    // send_secure_message("Hello Yeongbin", strlen("Hello Yeongbin"),&session_key_list[0], sock);
    // sleep(10);
    // send_secure_message("Hello Yoonsang", strlen("Hello Yoonsang"),&session_key_list[0], sock);

    sleep(60);
}










/*
//Multiplexing version.
main()
{
    config = load_config();
    init_server(&config);

    int serv_sock;
    int clnt_sock = accept(serv_sock);
    data_length = read();
    session_key_t s_key = server_secure_comm_setup(data, data_length, clnt_sock, )
    parse -> 

    pthread_create(&wait_thread, NULL, &wait_connection, (void *)&args);
    //this covers all connections and receiving messages.

    send_to_everyone(); 
}
*/

/*
2. wait_server 첫 server socket 세팅에서

    2-1 
            const char * PORT_NUM = "21100";
            struct sockaddr_in serv_addr;
            int serv_sock = socket(PF_INET, SOCK_STREAM, 0);
            if(serv_sock == -1)
                error_handling("socket() error");
            memset(&serv_addr, 0, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
            serv_addr.sin_port=htons(atoi(PORT_NUM));

            if(bind(serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr))==-1)
                error_handling("bind() error");
            if(listen(serv_sock, 5)==-1)
                error_handling("listen() error");
            return serv_sock;

    이런 것들을 user 가 직접 입력해야 하는건지 아니면,
    2-2
            int serv_sock = init_server(config *config_info); 
            이런식으로 config를 통해 가져와야하는건지?
 2-2로
        

3. 2번의 서버 세팅후 나온 serv_sock을 이용할건데,

    int client_sock;
    session_key_t s_key;
    accept()
    server_waits_client(serv_sock, client_sock, &s_key);
    // 이 부분은 accept에서 blocking 됨.
    print_recevied_message(client_sock, &s_key);
    이정도로만 만들면 되고 thread를 만들고 client관리 등은 user가 해야하는 것인가?

    accept까지는 user가. 


4. send 는 전체에게 버전 + 단일 client에게 버전으로 만들어야 하는가? 아니면 전체에게 버전은 user가 알아서 해야하는것인가?
    만약 전체 버전을 만들어야 한다면, client 관리를 api에서 해야하지 않나?

    단일 client에게 버전

5. server_state 도 변수로 넘겨야하는데 이걸 어떻게 해야하나?
    server_state란, 
    #define IDLE 0 //start state.
    #define HANDSHAKE_1_SENT 10
    #define HANDSHAKE_1_RECEIVED 21
    #define HANDSHAKE_2_SENT 22
    #define IN_COMM 30
   이 있는데, 마지막에 해당 client_sock이 IN_COMM state에 있는것을 확인해야하는데,
   api를 server_waits_client() 과 print_recevied_message() 로 나누면 server_state도 인풋으로 넘겨야 하는데, 어떻게 넘기는게 좋을까요?
    이 server_state는 client_sock 마다 관리 필요. 이 부분도 user가 해야할 일인가요?

소켓 관리 는 모두 사용자가. client, thread 관리도 다 사용자가.

.h파일에 comment 해주기.

high level은 .h에 

usage에서 각 인풋들이 어떻게쓰이는지 설명. ex) 이 버퍼 사이즈는 받을 데이터사이즈다~~이런거.

*/