#include "c_api.h"

/*
gcc -g c_common.c c_crypto.c c_secure_comm.c load_config.c c_api.c test.c -o test -lcrypto -pthread
*/

extern int sent_seq_num;
extern unsigned char entity_client_state;
extern long int st_time;
extern int serv_sock;


session_key * get_session_key(config * config_info)
{

    int sock;
    const char * IP_ADDRESS = "127.0.0.1";
    const char * PORT_NUM = "21900";
    connect_as_client(IP_ADDRESS, PORT_NUM, &sock);

    //will be input from config.
    unsigned char sender[] = "net1.client";
    unsigned char purpose[] = "{\"group\":\"Servers\"}";
    unsigned char num_key = 3;
    const char * path_pub = "../auth_certs/Auth101EntityCert.pem";
    const char * path_priv = "../credentials/keys/net1/Net1.ClientKey.pem";    

    //TODO: startfrom here.


    session_key * session_key_list = malloc(sizeof(session_key) * num_key);
    unsigned char entity_nonce[NONCE_SIZE];
    while(1)
    {
        unsigned char received_buf[1000];
        unsigned int received_buf_length = read(sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
        if(message_type == AUTH_HELLO)
        {
            unsigned int auth_Id;
            unsigned char auth_nonce[NONCE_SIZE];
            auth_Id = read_unsigned_int_BE(data_buf,  AUTH_ID_LEN);
            memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE );
            RAND_bytes(entity_nonce, NONCE_SIZE);
            unsigned int ret_length;
            unsigned char * serialized = auth_hello_reply_message(entity_nonce, auth_nonce, num_key, sender, sizeof(sender), purpose, sizeof(purpose), &ret_length);
            
            //TODO: when distribution key exists.
            unsigned int enc_length;
            unsigned char enc[RSA_ENCRYPT_SIGN_SIZE];
            encrypt_and_sign(serialized, ret_length, path_pub, path_priv, enc, &enc_length);
            free(serialized);

            unsigned char message[1024];
            unsigned int message_length;
            make_sender_buf(enc, enc_length, SESSION_KEY_REQ_IN_PUB_ENC, message, &message_length);
            write(sock, message, message_length);
        }
        else if(message_type == SESSION_KEY_RESP_WITH_DIST_KEY)
        {
            signed_data_t signed_data;
            distribution_key dist_key;
            unsigned int key_size = RSA_KEY_SIZE; //TODO: ??

            //parse data
            unsigned int encrypted_session_key_length = data_buf_length - (key_size * 2);
            unsigned char * encrypted_session_key = (unsigned char *)malloc(encrypted_session_key_length);
            memcpy(signed_data.data, data_buf, key_size);
            memcpy(signed_data.sign, data_buf + key_size, key_size);
            memcpy(encrypted_session_key, data_buf + key_size*2, encrypted_session_key_length);

            //verify
            SHA256_verify(signed_data.data, key_size, signed_data.sign, key_size, path_pub);
            printf("auth signature verified\n");

            //decrypt encrypted_distribution_key
            unsigned char decrypted_distribution_key[key_size]; //TODO: may need to change size. Actual decrypted_length = 56 bytes.
            unsigned int decrypted_distribution_key_length = private_decrypt(signed_data.data, key_size, RSA_PKCS1_PADDING, path_priv, decrypted_distribution_key);

            //parse decrypted_distribution_key to mac_key & cipher_key
            parse_distribution_key(&dist_key, decrypted_distribution_key, decrypted_distribution_key_length);

            //decrypt session_key with decrypted_distribution_key
            unsigned int decrypted_session_key_response_length;
            unsigned char * decrypted_session_key_response = symmetric_decrypt_authenticate(encrypted_session_key, encrypted_session_key_length, dist_key.mac_key, dist_key.mac_key_size, dist_key.cipher_key, dist_key.cipher_key_size, IV_SIZE, &decrypted_session_key_response_length);
            free(encrypted_session_key);

            //parse decrypted_session_key_response for nonce comparison & session_key.
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(decrypted_session_key_response, decrypted_session_key_response_length, reply_nonce, session_key_list);

            printf("reply_nonce in sessionKeyResp: ");
            print_buf(reply_nonce, NONCE_SIZE);
            if(strncmp(reply_nonce, entity_nonce ,NONCE_SIZE) != 0)
            { //compare generated entity's nonce & received entity's nonce.
                error_handling("auth nonce NOT verified");
            }
            else
            {
                printf("auth nonce verified!\n");
            }
            return session_key_list;
        }

    }
}

int secure_connection(session_key * s_key)
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
function: waits for client to connect.

input: config, 
output: 

usage: 
    pthread_t wait_thread;
    arg_struct args = {
        .sock = sock,
        .s_key = &session_key_list[0]
    };
    pthread_create(&wait_thread, NULL, &receive_thread, (void *)&args);

*/

// void * wait_connection_message(void * arguments)
// {
//     arg_struct * args = (arg_struct *) arguments;
//     int clnt_sock;
//     const char * PORT_NUM = "21100";

//     helper_options_server helper_options[MAX_CLIENT_NUM];

//     struct sockaddr_in serv_addr;
//     struct sockaddr_in clnt_addr;
//     socklen_t clnt_addr_size;
//     serv_sock = socket(PF_INET, SOCK_STREAM, 0);
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

//     //TODO: for(;;){}
//     for(int i = 0; i < MAX_CLIENT_NUM; i ++){
//         clnt_addr_size = sizeof(clnt_addr);
//         clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
//         if(clnt_sock==-1){
//             error_handling("accept() error");
//         }


//         helper_options[i].entity_state = IDLE;
//         //TODO: 추후 thread 화? 여러개의 client 받아야함.
//         // connect_to_client(&serv_sock, &clnt_sock, PORT_NUM);
//         helper_options[i].iot_secure_socket = clnt_sock;
//         pthread_create(&p_thread[i+1], NULL, &server_client_communication, (void *)&helper_options[i]);
//         printf("test");
//         sleep(1);
//     }
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
        arg_struct * args = (arg_struct *) arguments;
        unsigned char received_buf[1000];
        unsigned int received_buf_length = read(args->sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
        if(message_type == SECURE_COMM_MSG)
        {
            receive_message(data_buf, data_buf_length, args->s_key);
        }
    }
}

/*
usage: 
send_secure_message("Hello World", strlen("Hello World"), &session_key_list[0], sock);
*/
void send_secure_message(char * msg, unsigned int msg_length, session_key * s_key, int sock)
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
