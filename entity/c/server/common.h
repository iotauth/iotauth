#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include<stdbool.h>  
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#define get_name(var)  #var
#define NONCE_SIZE 8
#define AUTH_ID_SIZE 4
#define MSG_TYPE_SIZE 1
#define NUM_KEYS_SIZE 4
#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define SESSION_KEY_EXPIRATION_TIME_SIZE 6
#define REL_VALIDITY_SIZE 6
#define KEY_SIZE 256

#define AUTH_HELLO 0
#define SESSION_KEY_REQ_IN_PUB_ENC 20
#define SESSION_KEY_RESP_WITH_DIST_KEY 21
#define SESSION_KEY_RESP 23
#define AUTH_ALERT 100

#define SKEY_HANDSHAKE_1 30
#define SKEY_HANDSHAKE_2 31
#define SKEY_HANDSHAKE_3 32
#define SECURE_COMM_MSG 33

#define HS_NONCE_SIZE 8
#define SEQ_NUM_SIZE 8
#define HS_INDICATOR_SIZE 1+HS_NONCE_SIZE*2

#define MAX_CLIENT_NUM 10
#define MAX_MSG_LENGTH 1000

typedef unsigned char UCHAR;
typedef unsigned int UINT;

// pthread_t p_thread[12]; //scanf() + accept() + clients 10 = 12


/*  num: number of payload in decimals
    buf_len: length of changed buffer. Max 4
    buf[4]: payload_lengh buffer */
typedef struct payload_length_t{
    UINT num;
    UCHAR buf_len;
    UCHAR buf[4];
} payload_length_t;

/*  received_buf: received message from socket
    payload: removed buffer header  */
typedef struct received{
    UCHAR received_buf[1000]; //TODO: 
    UINT received_buf_length;
    UCHAR message_type;
    payload_length_t payload_length;
    UCHAR payload[1000];
} received;

typedef struct key_set{
    //TODO: size 변경
    UCHAR cipher_key_val[500];
    UINT cipher_key_val_length;
    UCHAR mac_key_val[500];
    UINT mac_key_val_length;
} key_set;

typedef struct parsed_session_key{
    UINT key_Id;
    UCHAR abs_validity; //TODO: 임시 설정.
    UINT rel_validity; 
    key_set keys;
} parsed_session_key;

typedef struct signed_data{
    UCHAR data[500];
    UINT data_length;
    UCHAR sign[500];
    UINT sign_length;
} signed_data;

typedef struct parsed_handshake{
    UCHAR nonce[NONCE_SIZE];
    UCHAR reply_nonce[NONCE_SIZE];
    UCHAR dhparam;  
    UINT dhparam_length;   
} parsed_handshake;


typedef struct connected_client_info{
    int socket;
    parsed_session_key session_key;
    UINT write_seq_num;
    UINT read_seq_num;
} connected_client_info;

typedef struct client_list_t{
    connected_client_info client_list[10];
    UINT client_list_length;
} client_list_t;



void error_handling(char *message);
void print_in_hex(UCHAR * var, UINT length);
void check_read_error(UINT length);
void generate_nonce(UCHAR * generated, UINT size);
void write_in_4bytes(UCHAR  num, UCHAR * buf);
void write_in_8bytes(long int num, UCHAR * buf);
UINT read_uint_BE(UCHAR *buf, UINT offset, UINT byte_length);
UINT read_uint_32BE(UCHAR *buf);
void parse_IoT_SP( received * received);
void parse_string_param(UCHAR *return_to, UINT * return_to_length, UCHAR * buf, UINT buf_length,int offset);
void * scan_command();


//make header + payload

void num_to_var_length_int_t(payload_length_t *buf);
void num_to_var_length_int(unsigned int data_length, unsigned char * payload_buf, unsigned char * buf_len);
void var_length_int_to_num(UCHAR * buf, UINT buf_length, payload_length_t * payload_length, int offset);
void var_length_int_to_num_t(unsigned char * buf, unsigned int buf_length, unsigned int * payload_length, unsigned int * payload_buf_length);
void make_buffer_header_t(UCHAR *header, UINT * header_length, UCHAR *payload, UINT payload_length, UCHAR MESSAGE_TYPE);
void make_buffer_header(unsigned char *header, unsigned int * header_length, unsigned char *data, unsigned int data_length, unsigned char MESSAGE_TYPE);
void concat_buffer_header_and_payload(UCHAR *ret, UINT * ret_length, UCHAR *header, UINT header_length, UCHAR *payload, UINT payload_length);
void make_sender_buf(UCHAR *sender, UINT * sender_length, UCHAR *payload, UINT payload_length, UCHAR MESSAGE_TYPE);

//crypto part

void print_Last_error(char *msg);
int public_encrypt(UCHAR * data, int data_len, UCHAR *encrypted, int padding, char * path);
int private_decrypt(UCHAR * enc_data, int data_len, UCHAR *decrypted, int padding, char * path);
void sign(UCHAR *sigret, UINT * sigret_length, UCHAR *encrypted, UINT encrypted_length, char * path);
void verify(signed_data * distribution_key_buf, char * path);

void AES_CBC_128_encrypt(UCHAR * ret, UINT * ret_length, UCHAR * plaintext, UINT plaintext_length ,UCHAR * key, UINT key_length, UCHAR * iv, UINT iv_length);
void AES_CBC_128_decrypt(UCHAR * ret, UINT * ret_length, UCHAR * encrypted, UINT encrypted_length, UCHAR * key, UINT key_length, UCHAR  * iv, UINT iv_length);
void make_digest_msg(UCHAR *dig_enc, UCHAR *encrypted ,int encrypted_length);
void symmetric_encrypt_authenticate(UCHAR * ret, UINT * ret_length, UCHAR * buf, UINT buf_length, key_set* symmetric_key_set);
void symmetric_decrypt_authenticate(UCHAR * ret, UINT *ret_length, UCHAR * buf, UINT buf_len, key_set* symmetric_key_set);

// RSA * create_RSA(UCHAR * key, bool public);

// server connection
void connection(int * sock, const char * ip_addr, const char * port_num);
void connect_to_client(int * serv_sock, int * clnt_sock, const char * port_num);

//handshake
void parse_handshake( parsed_handshake *ret, UCHAR *buf, UINT buf_length);
void serialize_handshake(UCHAR * ret, UINT * ret_length, UCHAR * nonce, UCHAR * reply_nonce );


//secure communication
void receive_message (UCHAR * ret, UINT * ret_length, UINT * seq_num, UCHAR * payload, UINT payload_length, parsed_session_key *parsed_session_key);
void parse_session_message(UCHAR * ret, UINT * ret_length, UINT *seq_num, UCHAR * buf, UINT buf_length);
void send_message(char * msg, connected_client_info * client);


unsigned char * symmetric_decrypt_authenticate_t(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length);
unsigned char * symmetric_encrypt_authenticate_t(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length);
void serialize_handshake_t(unsigned char * nonce, unsigned char * reply_nonce, unsigned char * ret);



extern pthread_t p_thread[12]; //scanf() + accept() + clients 10 = 12
extern client_list_t client_list;

#endif // COMMON_H