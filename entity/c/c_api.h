#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"

// Request and get session key from Auth according to secure connection
// by using OpenSSL which provides the cryptography, MAC, and Block cipher etc..
// @param config_info config struct obtained from load_config()
// @return secure session key
session_key_t *get_session_key(config_t *config_info);

// Connect with other entity such as entity servers using secure session key.
// @param s_key session key struct received by Auth
// @return secure socket number
int secure_connection(session_key_t *s_key);

// Wait the entity client to get the session key and
// make a secure connection using session key.
// See server_secure_comm_setup() for details.
// @param config config struct for information
// @param clnt_sock entity client socket number
// @return session key struct
session_key_t *server_secure_comm_setup(config_t *config, int clnt_sock);

// Creates a thread to receive messages.
// Max buffer length is 1000 bytes currently.
// Use function receive_message() below for longer read buffer.
// @param arguments struct including session key and socket number
void *receive_thread(void *arguments);

// Receive the message and print the message after decrypting with session key.
// @param received_buf received message buffer
// @param received_buf_length length of received_buf
// @param s_key session key struct
void receive_message(unsigned char *received_buf, unsigned int received_buf_length, session_key_t *s_key);

// Encrypt the message with session key and send the encrypted message to the socket.
// @param msg message to send
// @param msg_length length of message
// @param s_key session key struct
// @param sock socket number
void send_secure_message(char *msg, unsigned int msg_length, session_key_t *s_key, int sock);

#endif // C_API_H