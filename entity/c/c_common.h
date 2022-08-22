#ifndef C_COMMON_H
#define C_COMMON_H

#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

// Message Type //
#define AUTH_HELLO 0
#define ENTITY_HELLO 1
#define AUTH_SESSION_KEY_REQ 10
#define AUTH_SESSION_KEY_RESP 11
#define SESSION_KEY_REQ_IN_PUB_ENC 20
#define SESSION_KEY_RESP_WITH_DIST_KEY \
    21                       // Includes distribution message (session keys)
#define SESSION_KEY_REQ 22   // Distribution message
#define SESSION_KEY_RESP 23  // Distribution message
#define SKEY_HANDSHAKE_1 30
#define SKEY_HANDSHAKE_2 31
#define SKEY_HANDSHAKE_3 32
#define SECURE_COMM_MSG 33
#define FIN_SECURE_COMM 34
#define SECURE_PUB 40
#define MIGRATION_REQ_WITH_SIGN 50
#define MIGRATION_RESP_WITH_SIGN 51
#define MIGRATION_REQ_WITH_MAC 52
#define MIGRATION_RESP_WITH_MAC 53
#define AUTH_ALERT 100

// Size //
#define MESSAGE_TYPE_SIZE 1
#define MAX_PAYLOAD_BUF_SIZE 5
#define HS_NONCE_SIZE 8
#define HS_INDICATOR_SIZE 1 + HS_NONCE_SIZE * 2

#define SEQ_NUM_SIZE 8

// Auth Hello //
#define AUTH_ID_LEN 4
#define NUMKEY_SIZE 4
#define NONCE_SIZE 8

// Session key Resp //
#define MAC_SIZE 32
#define KEY_ID_SIZE 8

// Handshake struct including nonce, reply_nonce(received),
// and Diffie Helman parameter

typedef struct {
    unsigned char nonce[HS_NONCE_SIZE];
    unsigned char reply_nonce[HS_NONCE_SIZE];
    unsigned char dhParam[];  // TODO: The buffer size is temporarily defined
                              // none. Need to implement diffie_helman protocol.
} HS_nonce_t;

// Handle whether message has error or not.
// @param message input message
void error_handling(char *message);

// Print the buffer which you want
// @param buf input buffer to print
// @param size buffer size to print
void print_buf(unsigned char *buf, int n);

// Generate secure random nonce using OpenSSL.
// @param length length to generate the nonce
// @param buf buffer to save the generated nonce
void generate_nonce(int length, unsigned char *buf);

// Write number num in buffer size of n.
// @param num number to write in buffer
// @param n buffer size
// @param buf output buffer
void write_in_n_bytes(int num, int n, unsigned char *buf);

// Make the total int number in big endian buffer.
// @param buf input buffer
// @param byte_length buffer length to make the total number
// @return total number of input buffer
unsigned int read_unsigned_int_BE(unsigned char *buf, int byte_length);

// Splits received but to variable_length_buf + data_buf
// When
//     buf = (variable_length_buf) + (data_buf)
//     reads (variable_length_buf) to unsigned int (payload_length)
//     reads (variable_length_buf)'s buf_length to unsigned int
//     (payload_buf_length)
//  *@param buf input buffer
//  *@param buf_length length of input buffer
//  *@param payload_length length of information
//  *@param payload_buf_length length of payload buffer to use this length as
//  index
void var_length_int_to_num(unsigned char *buf, unsigned int buf_length,
                           unsigned int *payload_length,
                           unsigned int *payload_buf_length);

// Parses received message into 'message_type',
// and data after msg_type+payload_buf to 'data_buf'.
// Message type from received message and
// information which we needs from received message.
// @param received_buf input buffer
// @param received_buf_length length of input buffer
// @param message_type message type of received input buffer
// @param data_buf_length length of return information
// @return starting address of information from input buffer
unsigned char *parse_received_message(unsigned char *received_buf,
                                      unsigned int received_buf_length,
                                      unsigned char *message_type,
                                      unsigned int *data_buf_length);

// Makes sender_buf with 'payload' and 'MESSAGE_TYPE' to 'sender'.
// The four functions num_to_var_length_int(), make_buffer_header(),
// concat_buffer_header_and_payload(), make_sender_buf()
// parses a header to the the data to send.
// Actual usage only needs make_sender_buf()

// Make the data_length to a variable length.
// @param data_length input data length
// @param payload_buf payload buffer in terms of input data length
// @param payload_buf_length  length of payload buffer
void num_to_var_length_int(unsigned int data_length, unsigned char *payload_buf,
                           unsigned char *payload_buf_length);

// Make the header buffer including the message type and payload buffer.
// @param data_length input data buffer length
// @param MESSAGE_TYPE message type according to purpose
// @param header output header buffer including the message type and payload
// buffer
// @param header_length header buffer length
void make_buffer_header(unsigned int data_length, unsigned char MESSAGE_TYPE,
                        unsigned char *header, unsigned int *header_length);

// Concat the two buffers into a new return buffer
// @param header buffer to be copied the beginning of the return buffer
// @param header_length length of header buffer
// @param payload buffer to be copied to the back of the return buffer
// @param payload_length length of payload buffer
// @param ret header new return buffer
// @param ret_length length of return buffer
void concat_buffer_header_and_payload(
    unsigned char *header, unsigned int header_length, unsigned char *payload,
    unsigned int payload_length, unsigned char *ret, unsigned int *ret_length);

// Make the buffer sending to Auth by using make_buffer_header() and
// concat_buffer_header_and_payload().
// @param payload input data buffer
// @param payload_length length of input data buffer
// @param MESSAGE_TYPE message type according to purpose
// @param sender buffer to send to Auth
// @param sender_length length of sender buffer
void make_sender_buf(unsigned char *payload, unsigned int payload_length,
                     unsigned char MESSAGE_TYPE, unsigned char *sender,
                     unsigned int *sender_length);

// Connect to the server as client by using ip address, port number, and sock.
// May be the entity_client-Auth, entity_client - entity_server, entity_server -
// Auth.
// @param ip_addr IP address of server
// @param port_num port number to connect IP address
// @param sock socket number
void connect_as_client(const char *ip_addr, const char *port_num, int *sock);

// Serializes a buffer based on the nonce type such as nonce and reply nonce.
// @param nonce a nonce made by yourself
// @param reply_nonce nonce received from the other entity or Auth
// @param ret return_buffer:indicator_1byte + nonce_8byte + reply_nonce_8byte
void serialize_handshake(unsigned char *nonce, unsigned char *reply_nonce,
                         unsigned char *ret);

/**
 *Parses the received buffer to struct HS_nonce_t
 *See parse_handshake() for details.
 *@param buf input buffer incluing nonce.
 *@param ret return buffer
 */
void parse_handshake(unsigned char *buf, HS_nonce_t *ret);

int mod(int a, int b);

#endif  // C_COMMON_H
