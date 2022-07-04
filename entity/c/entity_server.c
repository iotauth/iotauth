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
                    }
                    
                    
                    
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