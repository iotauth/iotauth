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

// This struct is used in receive_thread()
typedef struct
{
    int sock;
    session_key_t *s_key;
} arg_struct_t;

// Parses the the reply message sending to Auth.
// Concat entity, auth nonce and information such as sender
// and purpose obtained from the config file.
// @param entity_nonce entity's nonce
// @param auth_nonce received auth's nonce
// @param num_key number of keys to receive from auth
// @param sender name of sender
// @param sender_length length of sender
// @param purpose purpose to get session key
// @param purpose_length length of purpose
// @param ret_length length of return buffer
// @return concated total buffer
unsigned char *auth_hello_reply_message(unsigned char *entity_nonce, unsigned char *auth_nonce, unsigned char num_key, unsigned char *sender, unsigned int sender_length, unsigned char *purpose, unsigned int purpose_length, unsigned int *ret_length);

// Encrypt the message and sign the encrypted message.
// @param buf input buffer
// @param buf_len length of buf
// @param path_pub public key path
// @param path_priv private key path
// @param message message with encrypted message and signature
// @param message_length length of message
unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len, const char *path_pub, const char *path_priv, unsigned int *message_length);

// Separate the message received from Auth and
// store the distribution key in the distribution key struct
// Must free distribution_key.mac_key, distribution_key.cipher_key
// @param parsed_distribution_key distribution key struct to save information
// @param buf input buffer with distribution key
// @param buf_length length of buf
void parse_distribution_key(distribution_key_t *parsed_distribution_key, unsigned char *buf, unsigned int buf_length);

// Used in parse_session_key_response() for index.
// @param buf input buffer with crypto spec
// @param buf_length length of buf
// @param offset buffer index
// @param return_to_length length of return buffer
// @return buffer with crypto spec
unsigned char *parse_string_param(unsigned char *buf, unsigned int buf_length, int offset, unsigned int *return_to_length);

// Store the session key in the session key struct
// Must free when session_key expired or usage finished.
// @param ret session key struct to save key info
// @param buf input buffer with session key
// @param buf_length length of buf
// @return index number for another session key
unsigned int parse_session_key(session_key_t *ret, unsigned char *buf, unsigned int buf_length);

// Separate the session key, nonce, and crypto spec from the message.
// @param buf input buffer with session key, nonce, and crypto spec
// @param buf_length length of buf
// @param reply_nonce nonce to compare with
// @param session_key_list session key list struct
void parse_session_key_response(unsigned char *buf, unsigned int buf_length, unsigned char *reply_nonce, session_key_t *session_key_list);

// Generate the nonce to send to entity server,
// encrypt the message with session key, and
// make the total message including the session key id and encrypted message.
// @param s_key session key struct to encrypt the message
// @param entity_nonce nonce to protect the reply attack
// @param ret_length length of return buffer
// @return total buffer with session key id and encrypted message
unsigned char *parse_handshake_1(session_key_t *s_key, unsigned char *entity_nonce, unsigned int *ret_length);

// Check the nonce obtained in decryption with own nonce and
// make the encrypted message with other entity's nonce.
// @param data_buf input data buffer
// @param data_buf_length length of data buffer
// @param entity_nonce own nonce
// @param s_key session key struct
// @param ret_length length of return buffer
// @return buffer with encrypted message
unsigned char *check_handshake_2_send_handshake_3(unsigned char *data_buf, unsigned int data_buf_length, unsigned char *entity_nonce, session_key_t *s_key, unsigned int *ret_length);

// Decrypts message, reads seq_num, checks validity, and prints message
// Print the received message and sequence number after check validity of session key.
// @param data input data buffer
// @param data_length length of data buffer
// @param s_key session key struct
void print_recevied_message(unsigned char *data, unsigned int data_length, session_key_t *s_key);

// Check the validity of session key by calculating relative time and absolute time.
// @param seq_n sequence number of received message
// @param rel_validity relative validity time of session key
// @param abs_validity absolute validity time of session key
// @param st_time time of first use of session key
// @return 1 or 0 depending on validity
int check_validity(int seq_n, unsigned char *rel_validity, unsigned char *abs_validity, long int *st_time);

// Check if entity has session key and if not, request the session key to Auth.
// @param config config struct for the entity information
// @param target_key_id id of session key
// @return session key struct according to key id
session_key_t *send_session_key_request_check_protocol(config_t *config, unsigned char *target_key_id);

// Request the session key to Auth according to session key id via TCP connection
// @param config_info config struct for the entity information
// @return session_key_t struct according to key id
session_key_t *send_session_key_req_via_TCP(config_t *config);

// Request the session key to Auth according to session key id via UDP connection.
// @param
// @return session key struct according to key id
session_key_t *send_session_key_req_via_UDP();

// Check the nonce obtained in decryption with own nonce and
// make the encrypted message with other entity's nonce.
// @param received_buf received buffer
// @param received_buf_length length of received buffer
// @param server_nonce own nonce
// @param s_key session key struct
// @param ret_length length of return buffer
// @return buffer with encrypted message
unsigned char *check_handshake1_send_handshake2(unsigned char *received_buf, unsigned int received_buf_length, unsigned char *server_nonce, session_key_t *s_key, unsigned int *ret_length);

#endif // C_SECURE_COMM_H