#ifndef CRYPTO
#define CRYPTO

#include "common.h"

// Crypto spec !

#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define KEY_EXPIRATION_TIME_SIZE 6
#define MAC_KEY_SIZE 32
#define CIPHER_KEY_SIZE 16
#define DIST_ENC_SIZE 512
#define IV_SIZE 16
#define KEY_BUF 4

typedef struct
{
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned char cipher_key[CIPHER_KEY_SIZE];
    unsigned char absvalidity[DIST_KEY_EXPIRATION_TIME_SIZE];
    long int start_time;
}distribution_key;

typedef struct
{
    unsigned char key_id[KEY_ID_SIZE];
    unsigned char abs_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char rel_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned char cipher_key[CIPHER_KEY_SIZE];
}sessionkey; 
// TODO: 
void print_last_error(char *msg);
int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted, char *key);
void make_digest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length);

int encrypt_sign(unsigned char *message, size_t size);
void sign_verify(unsigned char * dig, int dig_size, unsigned char *ret, int ret_size);
void dist_key_decrypt(unsigned char * buffer, int index, distribution_key *D);
void sess_key_decrypt(unsigned char *buf, int size, sessionkey S[], distribution_key *D);
void get_sessionkey(unsigned char *buf, int index, int key_num, sessionkey S[]);
int symm_enc_authenticate(sessionkey S, unsigned char * message, unsigned char * z, int data_len, int t); 
void symm_dec_authenticate(sessionkey S, unsigned char * message, int data_len); 


#endif