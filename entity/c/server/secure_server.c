# include "secure_server.h"

pthread_t p_thread[12]; //scanf() + accept() + clients 10 = 12
client_list_t client_list;

void initialize_TCP_server(){
    int serv_sock;
    int clnt_sock;
    const char * PORT_NUM = "21100";

    helper_options_server helper_options[MAX_CLIENT_NUM];

    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
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

    //TODO: for(;;){}
    for(int i = 0; i < MAX_CLIENT_NUM; i ++){
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
        if(clnt_sock==-1){
            error_handling("accept() error");
        }


        helper_options[i].entity_state = IDLE;
        //TODO: 추후 thread 화? 여러개의 client 받아야함.
        // connect_to_client(&serv_sock, &clnt_sock, PORT_NUM);
        helper_options[i].iot_secure_socket = clnt_sock;
        pthread_create(&p_thread[i+1], NULL, &server_client_communication, (void *)&helper_options[i]);
        printf("test");
        sleep(1);
    }
}

void initialize_UDP_server(){}

void * server_client_communication(void * helper_options_t){
    received received;
    helper_options_server * helper_options = (helper_options_server *) helper_options_t;
    printf("\n------------Connected to client-------------\n");
    helper_options->seq_num = 0;

    while(1){
        //message에 저장
        //TODO: read 처리 부분.
        //file open 해서 buffer 를 file write해서 한다.
	    received.received_buf_length=read(helper_options->iot_secure_socket, received.received_buf, sizeof(received.received_buf)-1);
        check_read_error(received.received_buf_length);   
        parse_IoT_SP(&received);
        helper_options->msg_type = received.message_type;
        helper_options->payload = received.payload;
        helper_options->payload_length = received.payload_length.num;
        secure_server_helper(helper_options);
    }
}

//checks handshake type
void secure_server_helper(helper_options_server *helper_options){
    if(helper_options->msg_type == SKEY_HANDSHAKE_1){
        printf("received session key handshake1\n");
        if(helper_options->entity_state != IDLE){
            error_handling("Error during comm init - in wrong state, expected: IDLE, disconnecting...\n");
        }
        printf("switching to HANDSHAKE_1_RECEIVED state.\n");
        helper_options->entity_state = HANDSHAKE_1_RECEIVED;

        //SecureCommServer.js onClientRequest 202
        callback_params_server callback_params;
        callback_params.serverSocket = helper_options->iot_secure_socket;
        callback_params.handshake1_payload_length = helper_options->payload_length;
        memcpy(callback_params.handshake1_payload, helper_options->payload, callback_params.handshake1_payload_length);
        callback_params.key_Id = read_uint_BE(helper_options->payload, 0, SESSION_KEY_ID_SIZE);
        printf("session key id: %d\n", callback_params.key_Id);
        bool session_key_found = false;
        // TODO: SecureCommServer.js 213 for~ check
        // session_key_found = check_session_key(&first_received, callback_params.key_Id);
        // if(session_key_found){
        //     //TODO:
        // }
        if(!session_key_found){
            send_session_key_request_check_protocol(helper_options, &callback_params);
            UCHAR ret[1024];
            UINT ret_length;
            handle_session_key_resp_server(ret, &ret_length, helper_options, &callback_params);
            write(helper_options->iot_secure_socket, ret,ret_length);
        }       
        return;
    }
    else if(helper_options->msg_type == SKEY_HANDSHAKE_3){
        printf("received session key handshake3!\n");
        if(helper_options->entity_state != HANDSHAKE_2_SENT){
            error_handling("Error: wrong sequence of handshake, disconnecting...");
        }
        UCHAR buf[512];
        UINT buf_length;
        UCHAR temp_buf[512];
        UINT temp_buf_length;
        memcpy(temp_buf, helper_options->payload, helper_options->payload_length);
        temp_buf_length = helper_options->payload_length;
        symmetric_decrypt_authenticate(buf, &buf_length, temp_buf, temp_buf_length, &helper_options->entity_session_key_list[0].keys);
        parsed_handshake ret;
        parse_handshake(&ret, buf, buf_length);
        if(strncmp(helper_options->my_nonce, ret.reply_nonce, NONCE_SIZE) != 0){
            error_handling("Error: client NOT verified, nonce NOT matched, disconnecting...\n");
        }
        else{
            printf("client authenticated/authorized by solving nonce!\n");
        }
        //TODO: change
        printf("switching to IN_COMM\n");
        helper_options->entity_state = IN_COMM;
        client_list.client_list[client_list.client_list_length].socket = helper_options->iot_secure_socket;
        memcpy(&client_list.client_list[client_list.client_list_length].session_key, &helper_options->entity_session_key_list[0], sizeof(parsed_session_key));
        client_list.client_list[client_list.client_list_length].read_seq_num = 0;
        client_list.client_list[client_list.client_list_length].write_seq_num = 0;
        client_list.client_list_length ++;
        return;
    }
    else if(helper_options->msg_type == SECURE_COMM_MSG){
        printf("received secure communication!\n");
        UCHAR ret[512];
        UINT ret_length;
        receive_message(ret, &ret_length, &helper_options->seq_num, helper_options->payload, helper_options->payload_length, &helper_options->entity_session_key_list[0]);
        client_list.client_list[client_list.client_list_length - 1].read_seq_num = helper_options->seq_num;
        printf("%s\n", ret);
    }
    // else if(){}
}

//SecureCommServer.js handleSessionKeyResp
void handle_session_key_resp_server(UCHAR *ret, UINT * ret_length, helper_options_server *helper_options, callback_params_server *callback_params){
    
    // if(){} //TODO: migration
    // if(){} //TODO: check received_dist_key null;
    
    printf("received %d keys\n", helper_options->entity_session_key_list_length);
    
    // if(strncmp(callback_params.target_session_key_cache, "Clients", callback_params.target_session_key_cache_length) == 0){} //TODO: check. 
    
    if( strncmp(callback_params->target_session_key_cache, "none", callback_params->target_session_key_cache_length) == 0){
        // check received (keyId from auth == keyId from entity_client)
        if(helper_options->entity_session_key_list[0].key_Id == callback_params->key_Id){
            printf("Session key id is as expected\n");
            //SecureCommServer.js sendHandshake2Callback
            send_handshake2(ret, ret_length, callback_params->handshake1_payload, callback_params->handshake1_payload_length, &callback_params->serverSocket, helper_options->entity_session_key_list[0], helper_options);
        }
        else{
            error_handling("Session key id is NOT as expected\n");
        }
    }
}

void send_handshake2(UCHAR * return_buf, UINT * return_buf_length, UCHAR * handshake1_payload, UINT handshake1_payload_length, int * sock, parsed_session_key session_key, helper_options_server *helper_options){
    if(helper_options->entity_state != HANDSHAKE_1_RECEIVED){
        error_handling("Error during comm init - in wrong state, expected: HANDSHAKE_1_RECEIVED, disconnecting...");
    }
    UCHAR enc[512];
    UINT enc_length;
    memcpy(enc, handshake1_payload+SESSION_KEY_ID_SIZE, handshake1_payload_length - SESSION_KEY_ID_SIZE);
    enc_length = handshake1_payload_length - SESSION_KEY_ID_SIZE;
    // UCHAR buf[512];
    UINT buf_length;
        // symmetric_decrypt_authenticate(buf, &buf_length, enc, enc_length, &session_key.keys);
    unsigned char * buf = symmetric_decrypt_authenticate_t(enc, enc_length, &session_key.keys.mac_key_val, 32, &session_key.keys.cipher_key_val, 16, 16, &buf_length);
    parsed_handshake ret;
    parse_handshake(&ret, buf, buf_length);
    UCHAR received_nonce[HS_NONCE_SIZE];
    memcpy(received_nonce, ret.nonce, HS_NONCE_SIZE);
    printf("server ret: "); //client's nonce,, received nonce
    print_in_hex(received_nonce, HS_NONCE_SIZE);
    
    generate_nonce(helper_options->my_nonce, HS_NONCE_SIZE);
    printf("chosen nonce: ");
    print_in_hex(helper_options->my_nonce, HS_NONCE_SIZE);
    UCHAR buffer[512];
    UINT buffer_length;
    serialize_handshake(buffer, &buffer_length, helper_options->my_nonce, received_nonce);
    // UCHAR encrypted_tagged[512];
    UINT encrypted_tagged_length;
    // symmetric_encrypt_authenticate(encrypted_tagged, &encrypted_tagged_length, buffer, buffer_length ,&session_key.keys);
    unsigned char * encrypted_tagged = symmetric_encrypt_authenticate_t(buffer, buffer_length ,&session_key.keys.mac_key_val, 32, &session_key.keys.cipher_key_val, 16, 16, &encrypted_tagged_length);

    make_sender_buf(return_buf, return_buf_length, encrypted_tagged, encrypted_tagged_length, SKEY_HANDSHAKE_2);
    printf("switching to HANDSHAKE_2_SENT'\n");
    helper_options->entity_state = HANDSHAKE_2_SENT;
}
