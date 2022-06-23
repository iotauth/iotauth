#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"

void load_config();
unsigned char * auth_hello_reply_message(unsigned char * entity_nonce, unsigned char * auth_nonce, unsigned char num_key, unsigned char * sender, unsigned int sender_length, unsigned char* purpose, unsigned int purpose_length, unsigned int * ret_length);
void * encrypt_and_sign(unsigned char * buf, unsigned int buf_len, const char * path_pub, const char * path_priv, unsigned char * message, unsigned int * message_length);
void get_session_key();


#endif