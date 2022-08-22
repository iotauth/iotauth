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

#define MAX_SESSION_KEY 10

// This struct is used in receive_thread()
typedef struct {
    int sock;
    session_key_t *s_key;
    int sent_seq_num;
    int received_seq_num;
} SST_session_ctx_t;

typedef struct {
    int num_key;
    session_key_t *s_key;
    int rear_idx;
} session_key_list_t;

// This struct contains distribution_key, loaded config, public and private
// keys.
typedef struct {
    distribution_key_t *dist_key;
    config_t *config;
    EVP_PKEY *pub_key;
    EVP_PKEY *priv_key;
} SST_ctx_t;

#define INIT_SESSION_KEY_LIST(X)          \
    session_key_list_t X = {.num_key = 0, \
                            .s_key = malloc(sizeof(session_key_t) * MAX_SESSION_KEY), \
                            .rear_idx = 0}

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
unsigned char *auth_hello_reply_message(
    unsigned char *entity_nonce, unsigned char *auth_nonce, int num_key,
    unsigned char *sender, unsigned int sender_length, unsigned char *purpose,
    unsigned int purpose_length, unsigned int *ret_length);

// Encrypt the message and sign the encrypted message.
// @param buf input buffer
// @param buf_len length of buf
// @param ctx ctx
// @param message message with encrypted message and signature
// @param message_length length of message
unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len,
                                SST_ctx_t *ctx, unsigned int *message_length);

// Separate the message received from Auth and
// store the distribution key in the distribution key struct
// Must free distribution_key.mac_key, distribution_key.cipher_key
// @param parsed_distribution_key distribution key struct to save information
// @param buf input buffer with distribution key
// @param buf_length length of buf
void parse_distribution_key(distribution_key_t *parsed_distribution_key,
                            unsigned char *buf, unsigned int buf_length);

// Used in parse_session_key_response() for index.
// @param buf input buffer with crypto spec
// @param buf_length length of buf
// @param offset buffer index
// @param return_to_length length of return buffer
// @return buffer with crypto spec
unsigned char *parse_string_param(unsigned char *buf, unsigned int buf_length,
                                  int offset, unsigned int *return_to_length);

// Store the session key in the session key struct
// Must free when session_key expired or usage finished.
// @param ret session key struct to save key info
// @param buf input buffer with session key
// @param buf_length length of buf
// @return index number for another session key
unsigned int parse_session_key(session_key_t *ret, unsigned char *buf,
                               unsigned int buf_length);

// Separate the session key, nonce, and crypto spec from the message.
// @param buf input buffer with session key, nonce, and crypto spec
// @param buf_length length of buf
// @param reply_nonce nonce to compare with
// @param session_key_list session key list struct
void parse_session_key_response(unsigned char *buf, unsigned int buf_length,
                                unsigned char *reply_nonce,
                                session_key_list_t *session_key_list);

// Parses the handshake1 buffer to send.
// First generates the entity client's nonce to send to entity server,
// encrypts the nonce with session key, and
// make the total message including the session key id and encrypted nonce.
// @param s_key session key struct to encrypt the message
// @param entity_nonce nonce to protect the reply attack
// @param ret_length length of return buffer
// @return total buffer with session key id and encrypted message
unsigned char *parse_handshake_1(session_key_t *s_key,
                                 unsigned char *entity_nonce,
                                 unsigned int *ret_length);

// Check the nonce obtained in decryption with own nonce and
// make the encrypted message with other entity's nonce.
// @param data_buf input data buffer
// @param data_buf_length length of data buffer
// @param entity_nonce own nonce
// @param s_key session key struct
// @param ret_length length of return buffer
// @return buffer with encrypted message
unsigned char *check_handshake_2_send_handshake_3(unsigned char *data_buf,
                                                  unsigned int data_buf_length,
                                                  unsigned char *entity_nonce,
                                                  session_key_t *s_key,
                                                  unsigned int *ret_length);

// Decrypts message, reads seq_num, checks validity, and prints message
// Print the received message and sequence number after check validity of
// session key.
// @param data input data buffer
// @param data_length length of data buffer
// @param SST_session_ctx_t session ctx struct
void print_recevied_message(unsigned char *data, unsigned int data_length,
                            SST_session_ctx_t *session_ctx);

// Check the validity of session key by calculating relative time and absolute
// time.
// @param seq_n sequence number of received message
// @param rel_validity relative validity time of session key
// @param abs_validity absolute validity time of session key
// @param st_time time of first use of session key
// @return 1 or 0 depending on validity
int check_validity(int seq_n, unsigned char *rel_validity,
                   unsigned char *abs_validity, long int *st_time);

// Check if entity has session key and if not, request the session key to Auth.
// @param ctx ctx struct
// @param target_key_id id of session key
// @return session key struct according to key id
session_key_list_t *send_session_key_request_check_protocol(
    SST_ctx_t *ctx, unsigned char *target_key_id);

// Request the session key to Auth according to session key id via TCP
// connection
// @param config_info config struct for the entity information
// @return session_key_t struct according to key id
session_key_list_t *send_session_key_req_via_TCP(SST_ctx_t *ctx);

// Request the session key to Auth according to session key id via UDP
// connection.
// @param
// @return session key struct according to key id
session_key_list_t *send_session_key_req_via_UDP(SST_ctx_t *ctx);

// Check the nonce obtained in decryption with own nonce and
// make the encrypted message with other entity's nonce.
// @param received_buf received buffer
// @param received_buf_length length of received buffer
// @param server_nonce own nonce
// @param s_key session key struct
// @param ret_length length of return buffer
// @return buffer with encrypted message
unsigned char *check_handshake1_send_handshake2(
    unsigned char *received_buf, unsigned int received_buf_length,
    unsigned char *server_nonce, session_key_t *s_key,
    unsigned int *ret_length);

// This function is used when checking if the server already has the session_key
// requested Checks if the s_key_list's idx'th session_key_id equals with the
// key_id
// @param key_id the target key id to obtain
// @param s_key_list the cached session_key_list
// @param idx current index
// @return index of the s_key_list
int check_session_key(unsigned int key_id, session_key_list_t *s_key_list,
                      int idx);

void add_session_key_to_list(session_key_t *s_key,
                             session_key_list_t *existing_s_key_list);

void append_session_key_list(session_key_list_t *dest, session_key_list_t *src);

void free_session_key_t(session_key_t *session_key);



void free_SST();

#endif  // C_SECURE_COMM_H
