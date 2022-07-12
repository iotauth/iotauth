#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"

session_key_t * get_session_key(config_t * config_info);
int secure_connection(session_key_t * s_key);
session_key_t * server_secure_comm_setup(config_t * config, int clnt_sock);
void send_secure_message(char * msg, unsigned int msg_length, session_key_t * s_key, int sock);
void * receive_thread(void * arguments);
void receive_message(unsigned char * received_buf, unsigned int received_buf_length, session_key_t * s_key);




#endif //C_API_H