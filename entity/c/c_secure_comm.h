#ifndef C_SECURE_COMM_H
#define C_SECURE_COMM_H

#include "c_crypto.h"
#include "load_config.h"

// This file includes functions that uses the struct "session_key"

#define IDLE 0
#define HANDSHAKE_1_SENT 10
#define HANDSHAKE_1_RECEIVED 21
#define HANDSHAKE_2_SENT 22
#define IN_COMM 30
#define SESSION_KEY_EXPIRATION_TIME_SIZE 6

typedef struct
{
    int sock;
    session_key_t *s_key;
} arg_struct_t;

unsigned char *auth_hello_reply_message(unsigned char *entity_nonce, unsigned char *auth_nonce, unsigned char num_key, unsigned char *sender, unsigned int sender_length, unsigned char *purpose, unsigned int purpose_length, unsigned int *ret_length);
unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len, const char *path_pub, const char *path_priv, unsigned int *message_length);
void parse_distribution_key(distribution_key_t *parsed_distribution_key, unsigned char *buf, unsigned int buf_length);
unsigned char *parse_string_param(unsigned char *buf, unsigned int buf_length, int offset, unsigned int *return_to_length);
unsigned int parse_session_key(session_key_t *ret, unsigned char *buf, unsigned int buf_length);
void parse_session_key_response(unsigned char *buf, unsigned int buf_length, unsigned char *reply_nonce, session_key_t *session_key_list);
unsigned char *parse_handshake_1(session_key_t *s_key, unsigned char *entity_nonce, unsigned int *ret_length);
unsigned char *check_handshake_2_send_handshake_3(unsigned char *data_buf, unsigned int data_buf_length, unsigned char *entity_nonce, session_key_t *s_key, unsigned int *ret_length);

void print_recevied_message(unsigned char *data, unsigned int data_length, session_key_t *s_key);
int check_validity(int seq_n, unsigned char *rel_validity, unsigned char *abs_validity, long int *st_time);

session_key_t *send_session_key_request_check_protocol(config_t *config, unsigned char *target_key_id);
session_key_t *send_session_key_req_via_TCP(config_t *config);
session_key_t *send_session_key_req_via_UDP();
unsigned char *check_handshake1_send_handshake2(unsigned char *received_buf, unsigned int received_buf_length, unsigned char *server_nonce, session_key_t *s_key, unsigned int *ret_length);
#endif // C_SECURE_COMM_H