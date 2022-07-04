#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"
#include "load_config.h"

session_key * get_session_key();
int secure_connection(session_key * s_key);
void * receive_thread(void * arguments);
void send_secure_message(char * msg, unsigned int msg_length, session_key * s_key, int sock);
void * wait_connection_message(void * arguments);
#endif // C_API_H