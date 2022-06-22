#ifndef SECURE_SERVER_H
#define SECURE_SERVER_H

#include "common.h" 
#include "auth.h"

#define IDLE 0
#define WAITING_SESSION_KEY 20
#define HANDSHAKE_1_RECEIVED 21
#define HANDSHAKE_2_SENT 22
#define IN_COMM 30






void initialize_TCP_server();
void initialize_UDP_server();

void * server_client_communication(void * helper_options_t);
void secure_server_helper(helper_options_server *helper_options);

void handle_session_key_resp_server(UCHAR *ret, UINT * ret_length, helper_options_server *helper_options, callback_params_server *callback_params);

void send_handshake2(UCHAR * return_buf, UINT * return_buf_length, UCHAR * handshake1_payload, UINT handshake1_payload_length, int * sock, parsed_session_key session_key, helper_options_server *helper_options);




#endif // SECURE_SERVER_H