#ifndef C_COMMON_H
#define C_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h> 
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <pthread.h>

// message type //
#define AUTH_HELLO 0
#define ENTITY_HELLO 1
#define AUTH_SESSION_KEY_REQ 10
#define AUTH_SESSION_KEY_RESP 11
#define SESSION_KEY_REQ_IN_PUB_ENC 20
#define SESSION_KEY_RESP_WITH_DIST_KEY 21  // Includes distribution message (session keys)
#define SESSION_KEY_REQ 22        // Distribution message
#define SESSION_KEY_RESP 23        // Distribution message
#define SKEY_HANDSHAKE_1 30   //client �� auth���� ������
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


#define MESSAGE_TYPE_SIZE 1
#define MAX_PAYLOAD_BUF_SIZE 5
#define HS_NONCE_SIZE 8
#define HS_INDICATOR_SIZE 1+HS_NONCE_SIZE*2

#define SEQ_NUM_SIZE 8

// Auth Hello //
#define AUTH_ID_LEN 4
#define NUMKEY_SIZE 4
#define NONCE_SIZE 8

// Session key Resp //
#define MAC_SIZE 32
#define KEY_ID_SIZE 8

// Nonce is the buffer to protect reply attack.
typedef struct
{
    unsigned char nonce[HS_NONCE_SIZE];
    unsigned char reply_nonce[HS_NONCE_SIZE];
    unsigned char dhParam[HS_NONCE_SIZE]; //TODO: check_size.
}HS_nonce_t;



void error_handling(char *message);
void print_buf(unsigned char * buf, int n);
void generate_nonce(int length, unsigned char * buf);
void write_in_n_bytes(int num, int n, unsigned char * buf);
unsigned int read_unsigned_int_BE(unsigned char * buf, int byte_length);



void var_length_int_to_num(unsigned char * buf, unsigned int buf_length, unsigned int * payload_length, unsigned int * payload_buf_length);
unsigned char * parse_received_message(unsigned char * received_buf, unsigned int received_buf_length, unsigned char * message_type, unsigned int * data_buf_length);
//making sender_buf
void num_to_var_length_int(unsigned int data_length, unsigned char * payload_buf, unsigned char * buf_len);
void make_buffer_header(unsigned char *data, unsigned int data_length, unsigned char MESSAGE_TYPE, unsigned char *header, unsigned int * header_length);
void concat_buffer_header_and_payload(unsigned char *header, unsigned int header_length, unsigned char *payload, unsigned int payload_length, unsigned char *ret, unsigned int * ret_length);
void make_sender_buf(unsigned char *payload, unsigned int payload_length, unsigned char MESSAGE_TYPE, unsigned char *sender, unsigned int * sender_length);

//connection
void connect_as_client(const char * ip_addr, const char * port_num, int * sock);

//Handshake
void serialize_handshake(unsigned char * nonce, unsigned char * reply_nonce, unsigned char * ret);
void parse_handshake(unsigned char *buf,  HS_nonce_t * ret);


#endif // C_COMMON_H