#include "c_api.h"

typedef struct{
    unsigned char server_state;
    session_key * s_key; //TODO: think about this.
} server_args_t;

int check_session_key(unsigned char * key_id, server_args_t * server_args, int fd_max)
{
    bool ret;
    for(int i=0; i<fd_max+1; i++)
    {
        if(strncmp(server_args[i].s_key->key_id, key_id, SESSION_KEY_ID_SIZE) == 0)
        {
            return i;
        }
    }
    return -1;
}


int main()
{
    // char path[] = "a.config";
    // config * config_info = load_config(path);

    // int serv_sock = init_server(config_info);

    const char * PORT_NUM = "21100";

    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    struct timeval timeout;
    fd_set reads, cpy_reads;
    
    socklen_t adr_sz;
    int fd_max, fd_num, i;

    serv_sock=socket(PF_INET, SOCK_STREAM, 0);
    if(serv_sock == -1){
        error_handling("socket() error");
    }
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port=htons(atoi(PORT_NUM));
    
    if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr))==-1) {
        printf("bind() error");
    }
    if(listen(serv_sock, 5)==-1) {
        printf("listen() error");
    }
    
    FD_ZERO(&reads);		// fd_set 초기화
    FD_SET(serv_sock, &reads);	// 서버 소켓을 관리 대상으로 지정
    fd_max=serv_sock;           // 최대 파일 디스크립터 값

    while(1)
    {    
        server_args_t * server_args = (server_args_t *)malloc((fd_max)*sizeof(server_args_t));
        cpy_reads=reads;			// 원본 fd_set 복사
        timeout.tv_sec=5;
        timeout.tv_usec=5000;		// 타임아웃 설정
        
        if((fd_num=select(fd_max+1, &cpy_reads, 0, 0, &timeout))==-1) {
            break;
        } // 아직 서버 소켓만 있으므로 connect 연결 요청 시 서버소켓에 데이터가 들어오게 됨
        
        if(fd_num==0) {
            continue;
        } // 타임 아웃 시 continue
	for(i=0; i<fd_max+1; i++)
        {
            if(FD_ISSET(i, &cpy_reads))
            {
                if(i==serv_sock)     
                {
                    adr_sz=sizeof(clnt_adr);
                    clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz);
                    FD_SET(clnt_sock, &reads);
                    if(fd_max<clnt_sock){
                        fd_max=clnt_sock;
                    }
                    printf("connected client: %d \n", clnt_sock);
                    server_args = realloc(server_args, (fd_max)*sizeof(server_args_t)); //TODO: check if realloc here?
                    //TODO: check initialize?
                    server_args[clnt_sock].server_state = IDLE;
                } // 변화가 일어난 소켓이 서버 소켓이면 connect 요청인 경우
                else 
                {
                    unsigned char received_buf[1000];
                    unsigned int received_buf_length = read(i, received_buf, sizeof(received_buf));
                    unsigned char message_type;
                    unsigned int data_buf_length;
                    unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
                    if(message_type == SKEY_HANDSHAKE_1)
                    {
                        printf("received session key handshake1\n");
                        if(server_args[i].server_state != IDLE)
                        {
                            error_handling("Error during comm init - in wrong state, expected: IDLE, disconnecting...\n");
                        }
                        printf("switching to HANDSHAKE_1_RECEIVED state.\n");
                        //TODO: entity state.
                        server_args[i].server_state == HANDSHAKE_1_RECEIVED;
                        memcpy(server_args[i].s_key->key_id, data_buf, SESSION_KEY_ID_SIZE);
                        int session_key_found = check_session_key(server_args[i].s_key->key_id, &server_args, fd_max);
                        if(session_key_found > 0)
                        {
                            //TODO: implement when session_key_found
                        }
                        else if(session_key_found == -1)
                        {
                            get_session_key_server(); //TODO: tomorrow.
                            send_HS_2();
                            write();
                        }
                    
        // session_key_found = check_session_key(&first_received, callback_params.key_Id);
        // if(session_key_found){
        //     //TODO:
        // }
        // if(!session_key_found){
        //     send_session_key_request_check_protocol(helper_options, &callback_params);
        //     UCHAR ret[1024];
        //     UINT ret_length;
        //     handle_session_key_resp_server(ret, &ret_length, helper_options, &callback_params);
        //     write(helper_options->iot_secure_socket, ret,ret_length);
        // }       
        // return;

                    }
                    else if(message_type == SKEY_HANDSHAKE_3)
                    {
                        printf("received session key handshake3!\n");
                        if(server_args[i].server_state != HANDSHAKE_2_SENT)
                        {
                            error_handling("Error during comm init - in wrong state, expected: IDLE, disconnecting...\n");
                        }
                        unsigned int decrypted_length;
                        unsigned char * decrypted = symmetric_decrypt_authenticate(data_buf, data_buf_length, server_args[i].s_key->mac_key, MAC_KEY_SIZE, server_args[i].s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
                        HS_nonce hs;
                        parse_handshake(decrypted, &hs);
                        free(decrypted);

                        //compare my_nonce and received_nonce
                        if(strncmp(hs.reply_nonce, entity_nonce ,HS_NONCE_SIZE) != 0){
                            error_handling("Comm init failed: server NOT verified, nonce NOT matched, disconnecting...\n");
                        }
                        else{
                            printf("server authenticated/authorized by solving nonce!\n");
                        }
                        printf("switching to IN_COMM\n");
                        server_args[i].server_state = IN_COMM;
                    }
                    else if(message_type == SECURE_COMM_MSG)
                    {
                        printf("received secure communication!\n");
                    }args
                    // str_len=read(i, buf, BUF_SIZE);
                    // if(str_len==0)    // close request!
                    // {
                    //     FD_CLR(i, &reads);
                    //     close(i);
                    //     printf("closed client: %d \n", i);
                    // }
                    // else
                    // {
                    //     printf("Hi");
                    //     write(i, buf, str_len);    // echo!
                    //     printf("Hello");
                    // }
                } // 다른 소켓인 경우에는 데이터 read
            }
        }
        free(server_args);
    }
    close(serv_sock);
    return 0;
}

/*
//Multiplexing version.
main()
{
    pthread_create(&wait_thread, NULL, &wait_connection, (void *)&args);
    //this covers all connections and receiving messages.

    send_to_everyone(); 
}
*/

/*
1. read를 하라 하셨는데 buffer 선언도 user가 하는게 맞는건가?
        int main(){
        pthread_create(temp);
        }
        void temp(){
            unsigned char received_buf[1000];
            unsigned int received_buf_length = read(sock, received_buf, sizeof(received_buf));
            print_recevied_message(sock, session_key, received_buf, received_buf_length);  
        }
    이런식으로 가야하는 건가요? user가 이런식으로 직접짜야하는건지?



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
    session_key s_key;
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

struct 들 _t 해주기.

.h파일에 comment 해주기.

high level은 .h에 

usage에서 각 인풋들이 어떻게쓰이는지 설명. ex) 이 버퍼 사이즈는 받을 데이터사이즈다~~이런거.

*/