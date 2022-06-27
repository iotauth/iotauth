#ifndef C_SECURE_COMM_H
#define C_SECURE_COMM_H

#include "c_crypto.h"

//This file includes functions that uses the struct "session_key"

#define HANDSHAKE_1_SENT 10
#define HANDSHAKE_1_RECEIVED 21
#define HANDSHAKE_2_SENT 22
#define IN_COMM 30

typedef struct
{
    unsigned char * message;
    unsigned int message_length;
    session_key * s_key;
}arg_struct;


unsigned char * auth_hello_reply_message(unsigned char * entity_nonce, unsigned char * auth_nonce, unsigned char num_key, unsigned char * sender, unsigned int sender_length, unsigned char* purpose, unsigned int purpose_length, unsigned int * ret_length);
void * encrypt_and_sign(unsigned char * buf, unsigned int buf_len, const char * path_pub, const char * path_priv, unsigned char * message, unsigned int * message_length);
void parse_distribution_key(distribution_key * parsed_distribution_key, unsigned char * buf, unsigned int buf_length);
unsigned char * parse_string_param(unsigned char * buf, unsigned int buf_length, int offset, unsigned int * return_to_length);
unsigned int parse_session_key(session_key * ret, unsigned char *buf, unsigned int buf_length);
void parse_session_key_response(unsigned char *buf, unsigned int buf_length, unsigned char * reply_nonce, session_key * session_key_list);
unsigned char * parse_handshake_1(session_key * s_key, unsigned char * entity_nonce, unsigned int * ret_length);
unsigned char * check_handshake_2_send_handshake_3(unsigned char * data_buf, unsigned int data_buf_length, unsigned char * entity_nonce, session_key * s_key, unsigned int *ret_length);

void * receive_message(void * args);



#endif