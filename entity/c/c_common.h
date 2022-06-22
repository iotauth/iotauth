#ifndef C_COMMON_H
#define C_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
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

#define MESSAGE_TYPE_SIZE 1
#define MAX_PAYLOAD_BUF_SIZE 5


void print_buf(unsigned char * buf, int n);
void generate_nonce(int length, unsigned char * buf);
void write_in_n_bytes(int num, int n, unsigned char * buf);
unsigned int read_variable_unsigned_int(unsigned char * buf, int byte_length);



void var_length_int_to_num(unsigned char * buf, unsigned int buf_length, unsigned int * payload_length, unsigned int * payload_buf_length);

//making sender_buf
void num_to_var_length_int(unsigned int data_length, unsigned char * payload_buf, unsigned char * buf_len);
void make_buffer_header(unsigned char *data, unsigned int data_length, unsigned char MESSAGE_TYPE, unsigned char *header, unsigned int * header_length);
void concat_buffer_header_and_payload(unsigned char *header, unsigned int header_length, unsigned char *payload, unsigned int payload_length, unsigned char *ret, unsigned int * ret_length);
void make_sender_buf(unsigned char *payload, unsigned int payload_length, unsigned char MESSAGE_TYPE, unsigned char *sender, unsigned int * sender_length);

//connection
void connect_as_client(const char * ip_addr, const char * port_num, int * sock);

#endif