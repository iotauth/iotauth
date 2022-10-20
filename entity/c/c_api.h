#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"

// Load config file from path and save the information in ctx struct.
// Also loads public and private key in EVP_PKEY struct.
// Stores the distribution_key.
// @param path config file path
// @return SST_ctx_t struct stores config, public and private keys, and
// distribution key.
SST_ctx_t *init_SST(char *config_path);

// Request and get session key from Auth according to secure connection
// by using OpenSSL which provides the cryptography, MAC, and Block cipher etc..
// @param config_info config struct obtained from load_config()
// @return secure session key
session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list);

// Connect with other entity such as entity servers using secure session key.
// @param s_key session key struct received by Auth
// @return secure socket number
SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx);

// Wait the entity client to get the session key and
// make a secure connection using session key.
// @param config config struct for information
// @param clnt_sock entity client socket number
// @return session key struct
SST_session_ctx_t *server_secure_comm_setup(
    SST_ctx_t *ctx, int clnt_sock, session_key_list_t *existing_s_key_list);

// Creates a thread to receive messages.
// Max buffer length is 1000 bytes currently.
// Use function receive_message() below for longer read buffer.
// @param arguments struct including session key and socket number
void *receive_thread(void *SST_session_ctx);

// Receive the message and print the message after decrypting with session key.
// @param received_buf received message buffer
// @param received_buf_length length of received_buf
// @param SST_session_ctx_t session ctx struct
void receive_message(unsigned char *received_buf,
                     unsigned int received_buf_length,
                     SST_session_ctx_t *session_ctx);

// Encrypt the message with session key and send the encrypted message to the
// socket.
// @param msg message to send
// @param msg_length length of message
// @param SST_session_ctx_t session ctx struct
void send_secure_message(char *msg, unsigned int msg_length,
                         SST_session_ctx_t *session_ctx);

// Frees memory used in session_key_list recursively.
// @param session_key_list_t session_key_list to free
void free_session_key_list_t(session_key_list_t *session_key_list);

// Free memory used in SST_ctx recursively.
// @param SST_ctx_t loaded SST_ctx_t to free
void free_SST_ctx(SST_ctx_t *ctx);

#endif  // C_API_H
