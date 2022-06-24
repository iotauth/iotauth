#ifndef C_CRYPTO_H
#define C_CRYPTO_H

#include "c_common.h"

#define AES_CBC_128_KEY_SIZE 128
#define AES_CBC_128_IV_SIZE 16

#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define REL_VALIDITY_SIZE 6

#define MAC_KEY_SIZE 32
#define CIPHER_KEY_SIZE 16
#define RSA_KEY_SIZE 256
#define RSA_ENCRYPT_SIGN_SIZE RSA_KEY_SIZE*2

#define IV_SIZE 16

#define SHA256_DIGEST_LENGTH 32


typedef struct
{
    unsigned char data[RSA_KEY_SIZE];
    unsigned char sign[RSA_KEY_SIZE];
}signed_data_t;

//must free mac & cipher key
typedef struct
{
    unsigned char * mac_key;
    unsigned int mac_key_size;
    unsigned char * cipher_key;
    unsigned int cipher_key_size;
    unsigned char absvalidity[DIST_KEY_EXPIRATION_TIME_SIZE];
    long int start_time;
}distribution_key;


//must free mac & cipher key
typedef struct
{
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    unsigned char abs_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char rel_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char * mac_key;
    unsigned int mac_key_size;
    unsigned char * cipher_key;
    unsigned int cipher_key_size;
}session_key; 

void print_last_error(char *msg);
int public_encrypt(unsigned char * data, int data_len,  int padding, const char * path, unsigned char *ret);
int private_decrypt(unsigned char * enc_data, int enc_data_len, int padding, const char * path, unsigned char *ret);
void SHA256_sign(unsigned char *encrypted, unsigned int encrypted_length, const char * path, unsigned char *sigret, unsigned int * sigret_length);
void SHA256_verify(unsigned char * data, unsigned int data_length, unsigned char * sign, unsigned int sign_length, const char * path);
void SHA256_make_digest_msg(unsigned char *encrypted ,int encrypted_length, unsigned char *dig_enc);
void AES_CBC_128_encrypt(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * key, unsigned int key_length, unsigned char * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length);
void AES_CBC_128_decrypt(unsigned char * encrypted, unsigned int encrypted_length, unsigned char * key, unsigned int key_length, unsigned char  * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length);

unsigned char * symmetric_encrypt_authenticate(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length);
unsigned char * symmetric_decrypt_authenticate(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length);

#endif