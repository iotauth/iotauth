#ifndef AUTH_H
#define AUTH_H

#include "common.h"



typedef struct callback_params_server{
    UCHAR target_session_key_cache[100];
    UINT target_session_key_cache_length;
    UINT key_Id;
    // int sendHandshake2Callback; //TODO: temp
    UCHAR handshake1_payload[1000];
    UINT handshake1_payload_length;
    int serverSocket;
    UCHAR dhparam;  
    UINT dhparam_length; 
} callback_params_server;

typedef struct auth_hello_message_received{
    UINT auth_Id;
    UCHAR auth_Nonce[NONCE_SIZE];
} auth_hello_message_received;

typedef struct numkeys{
    UCHAR numkeys;
    UCHAR buf[4];  //항상 4 고정!
} numkeys;

typedef struct parsed_distribution_key{
    UCHAR abs_validity; //TODO: 임시로 type 설정함.
    key_set keys;
} parsed_distribution_key;



typedef struct session_key_response{
    parsed_distribution_key parsed_distribution_key;
    UCHAR reply_nonce[8];
    UCHAR crypto_spec; //TODO: 임시 설정.
    parsed_session_key session_key_list[10]; //TODO:  check
    UINT session_key_list_length;
} session_key_response;



typedef struct helper_options_server{
    UCHAR msg_type;
    UCHAR * payload;
    UINT payload_length;
    UCHAR my_nonce[HS_NONCE_SIZE]; //used in handshake nonce compare
    UCHAR entity_state;
    parsed_session_key entity_session_key_list[10];
    UINT entity_session_key_list_length;
    parsed_distribution_key current_distribution_key;
    // serverECDH
    int iot_secure_socket; // the socket connected between server and client.
    // socketID
    UINT seq_num;
} helper_options_server;

void send_session_key_request_check_protocol(helper_options_server *helper_options, callback_params_server *callback_params);
void send_session_key_req_via_TCP(helper_options_server *helper_options, callback_params_server *callback_params);
void send_session_key_req_via_UDP();
void send_session_key_request(UCHAR * ret, UINT * ret_length, received * received, UCHAR * reply_nonce, callback_params_server *callback_params);
void parse_Auth_Hello(received * received, auth_hello_message_received *auth_hello_message_received);
void generate_reply_message_server(UCHAR * session_key_request_buf, UINT * session_key_request_buf_length, auth_hello_message_received *auth_hello_message_received, UCHAR * replyNonce,  callback_params_server *callback_params);
void encrypt_and_sign_and_concat(UCHAR *ret, UINT * ret_length, UCHAR *message_to_encrypt, UINT message_to_encrypt_length);
void parse_session_key_response_with_dist_key(session_key_response *session_key_response, received * response_received,UCHAR * reply_nonce);
void parse_data_SESSION_KEY_RESP_WITH_DIST_KEY(received *received, signed_data *distribution_key_buf, UCHAR * session_key_buf, UINT * session_key_buf_length,int key_size);
void parse_distribution_key(parsed_distribution_key *parsed_distribution_key, UCHAR *buf, UINT buf_length);
void parse_session_key_response(session_key_response *session_key_response, UCHAR *buf, UINT buf_length);
UINT parse_session_key(parsed_session_key *ret, UCHAR *buf, UINT buf_length);
bool check_session_key(received * received, UINT key_Id);


unsigned char * parse_received_message(unsigned char * received_buf, unsigned int received_buf_length, unsigned char * message_type, unsigned int * data_buf_length);


#endif // AUTH_H