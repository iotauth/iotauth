#include "c_api.h"

/*
gcc -g c_common.c c_crypto.c c_secure_comm.c load_config.c c_api.c entity_server.c -o entity_server -lcrypto -pthread
*/

extern int sent_seq_num;
extern unsigned char entity_client_state;
extern unsigned char entity_server_state;
extern long int st_time;

// get sessio key() is a function for getting secure session key from Auth 
// using OpenSSL which provides the cryptography, MAC, and Block cipher etc..

session_key_t * get_session_key(config_t * config_info)
{
    unsigned char option = 1;
    if(option == 1)
    {
        return send_session_key_req_via_TCP(config_info);
    }
    else if(option ==2)
    {
        return send_session_key_req_via_UDP();
    }
}
// secure connection() is a function for secure communication with other entity such as entity servers
// input is session key struct received by Auth 
int secure_connection(session_key_t * s_key)
{
    //load_config
    int sock;
    const char * IP_ADDRESS = "127.0.0.1";
    const char * PORT_NUM = "21100";

    connect_as_client(IP_ADDRESS, PORT_NUM, &sock);

    unsigned char entity_nonce[HS_NONCE_SIZE];
    

    unsigned int parsed_buf_length;
    unsigned char * parsed_buf = parse_handshake_1(s_key, entity_nonce, &parsed_buf_length);
    unsigned char sender[128]; //TODO: actually only needs 19 bytes.
    unsigned int sender_length;
    make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_1, sender, &sender_length);
    write(sock, sender, sender_length);
    free(parsed_buf);
    entity_client_state = HANDSHAKE_1_SENT;

    //received handshake 2
    unsigned char received_buf[1000];
    unsigned int received_buf_length = read(sock, received_buf, sizeof(received_buf));
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
    if(message_type == SKEY_HANDSHAKE_2)
    {
        if(entity_client_state != HANDSHAKE_1_SENT){
            printf("Comm init failed: wrong sequence of handshake, disconnecting...\n");
        }
        unsigned int parsed_buf_length;
        unsigned char * parsed_buf = check_handshake_2_send_handshake_3(data_buf, data_buf_length, entity_nonce, s_key, &parsed_buf_length);
        unsigned char sender[256]; 
        unsigned int sender_length;
        make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_3, sender, &sender_length);
        write(sock, sender, sender_length);
        free(parsed_buf);
        printf("switching to IN_COMM\n");
        entity_client_state = IN_COMM;
    }
    sent_seq_num = 0;
    st_time = 0;
    printf("wait\n");
    return sock;
}

/*
function:   Binds address and port to serv_sock.
usage:
    int serv_sock = init_server(config_info);
*/

session_key_t * server_secure_comm_setup(config_t * config, int clnt_sock)
{
    entity_server_state = IDLE;
    unsigned char server_nonce[HS_NONCE_SIZE];
    session_key_t * s_key;
    while(1)
    {
        unsigned char received_buf[1024];
        int received_buf_length = read(clnt_sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
        if(message_type == SKEY_HANDSHAKE_1)
        {
            printf("received session key handshake1\n");
            if(entity_server_state != IDLE)
            {
                error_handling("Error during comm init - in wrong state, expected: IDLE, disconnecting...\n");
            }
            printf("switching to HANDSHAKE_1_RECEIVED state.\n");
            //TODO: entity state.
            entity_server_state = HANDSHAKE_1_RECEIVED;
            unsigned char expected_key_id[SESSION_KEY_ID_SIZE];
            memcpy(expected_key_id, data_buf, SESSION_KEY_ID_SIZE);
            unsigned int expected_key_id_int = read_unsigned_int_BE(expected_key_id, SESSION_KEY_ID_SIZE);
            /*
            //TODO: Implement? need to think how.
            int session_key_found = check_session_key(server_args[i].s_key->key_id, &server_args, fd_max);
            */ 
            int session_key_found = -1;
            if(session_key_found > 0)
            {
                //TODO: implement when session_key_found
            }
            else if(session_key_found == -1)
            {
                // sprintf(config->purpose + 9, "%d", expected_key_id_int);
                unsigned char temp_buf [SESSION_KEY_ID_SIZE];
                sprintf(temp_buf, "%d", expected_key_id_int);
                memcpy(config->purpose + 9, temp_buf, SESSION_KEY_ID_SIZE);

                s_key = send_session_key_request_check_protocol(config, expected_key_id);

                if(entity_server_state != HANDSHAKE_1_RECEIVED){
                    error_handling("Error during comm init - in wrong state, expected: HANDSHAKE_1_RECEIVED, disconnecting...");
                }

                unsigned int parsed_buf_length;
                unsigned char * parsed_buf = check_handshake1_send_handshake2(data_buf, data_buf_length, server_nonce, s_key, &parsed_buf_length);
                
                unsigned char sender[256]; 
                unsigned int sender_length;
                make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_2, sender, &sender_length);
                write(clnt_sock, sender, sender_length);
                free(parsed_buf);
                printf("switching to HANDSHAKE_2_SENT'\n");
                entity_server_state = HANDSHAKE_2_SENT;
            }
        }  
        else if(message_type == SKEY_HANDSHAKE_3)
        {
            printf("received session key handshake3!\n");
            if(entity_server_state != HANDSHAKE_2_SENT)
            {
                error_handling("Error during comm init - in wrong state, expected: IDLE, disconnecting...\n");
            }
            unsigned int decrypted_length;
            unsigned char * decrypted = symmetric_decrypt_authenticate(data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
            HS_nonce_t hs;
            parse_handshake(decrypted, &hs);
            free(decrypted);
            //compare my_nonce and received_nonce
            if(strncmp(hs.reply_nonce, server_nonce, HS_NONCE_SIZE) != 0){
                error_handling("Comm init failed: server NOT verified, nonce NOT matched, disconnecting...\n");
            }
            else{
                printf("server authenticated/authorized by solving nonce!\n");
            }
            printf("switching to IN_COMM\n");
            entity_server_state = IN_COMM;
            return s_key;
        }
    }
}     
// //TODO: PORT_NUM needs to be in config_info. currently not implemented.
// int init_server(config_t *config_info)
// {
//     const char * PORT_NUM = "21100";

//     struct sockaddr_in serv_addr;
//     int serv_sock = socket(PF_INET, SOCK_STREAM, 0);
//     if(serv_sock == -1){
//         error_handling("socket() error");
//     }
//     memset(&serv_addr, 0, sizeof(serv_addr));
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     serv_addr.sin_port=htons(atoi(PORT_NUM));

//     if(bind(serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr))==-1){
//         error_handling("bind() error");
//     }

//     if(listen(serv_sock, 5)==-1){
//         error_handling("listen() error");
//     }
//     return serv_sock;
// }



/*
usage:
    pthread_t thread;
    arg_struct args = {
        .sock = sock,
        .s_key = &session_key_list[0]
    };
    pthread_create(&thread, NULL, &receive_thread, (void *)&args);
*/
void * receive_thread(void * arguments)
{
    while(1)
    {
        arg_struct_t * args = (arg_struct_t *) arguments;
        unsigned char received_buf[1000];
        unsigned int received_buf_length = read(args->sock, received_buf, sizeof(received_buf));
        receive_message(received_buf, received_buf_length, args->s_key);
    }
}

void receive_message(unsigned char * received_buf, unsigned int received_buf_length, session_key_t * s_key)
{
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
    if(message_type == SECURE_COMM_MSG)
    {
        print_recevied_message(data_buf, data_buf_length, s_key);
    }
}


/*
usage: 
send_secure_message("Hello World", strlen("Hello World"), &session_key_list[0], sock);
*/
void send_secure_message(char * msg, unsigned int msg_length, session_key_t * s_key, int sock)
{

    if(!check_validity(sent_seq_num, s_key->rel_validity, s_key->abs_validity, &st_time))
    {
        error_handling("Session key expired!\n");
    }
    unsigned char * buf = (unsigned char *)malloc(SEQ_NUM_SIZE + msg_length);
    memset(buf, 0, SEQ_NUM_SIZE + msg_length);
    write_in_n_bytes(sent_seq_num, SEQ_NUM_SIZE, buf);
    memcpy(buf+SEQ_NUM_SIZE, (unsigned char*) msg, msg_length);

    //encrypt
    unsigned int encrypted_length;
    unsigned char * encrypted = symmetric_encrypt_authenticate(buf, SEQ_NUM_SIZE + msg_length, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &encrypted_length);
    free(buf);
    sent_seq_num++;
    unsigned char sender_buf[1024]; //TODO: change later.
    unsigned int sender_buf_length;
    make_sender_buf(encrypted, encrypted_length, SECURE_COMM_MSG, sender_buf, &sender_buf_length);
    free(encrypted);
    write(sock, sender_buf, sender_buf_length);
}

