#ifndef C_CRYPTO_H
#define C_CRYPTO_H

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "c_common.h"

#define AES_CBC_128_KEY_SIZE 128
#define AES_CBC_128_IV_SIZE 16
#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define ABS_VALIDITY_SIZE 6
#define REL_VALIDITY_SIZE 6
#define MAC_KEY_SIZE 32  // FIXME: To be replaced by config.
#define MAX_MAC_KEY_SIZE 32
#define CIPHER_KEY_SIZE 16  // FIXME: To be replaced by config.
#define MAX_CIPHER_KEY_SIZE 32
#define RSA_KEY_SIZE 256
#define RSA_ENCRYPT_SIGN_SIZE RSA_KEY_SIZE * 2
#define IV_SIZE 16
#define SHA256_DIGEST_LENGTH 32

// Struct for digital signature
typedef struct {
    unsigned char data[RSA_KEY_SIZE];
    unsigned char sign[RSA_KEY_SIZE];
} signed_data_t;

// Must free mac key & cipher key
typedef struct {
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    unsigned char abs_validity[DIST_KEY_EXPIRATION_TIME_SIZE];
} distribution_key_t;

// Must free mac key & cipher key
typedef struct {
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    unsigned char abs_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char rel_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
} session_key_t;

// Print error message when the code has error.
// @param msg message to print the error
void print_last_error(char *msg);

// Loads auth's public key from path
// @param path path of auth's public key
EVP_PKEY *load_auth_public_key(const char *path);

// Loads entity's private key from path
// @param path path of entity's private key
EVP_PKEY *load_entity_private_key(const char *path);

// Encrypt the message with public key using public key encryption from OpenSSL.
// @param data message for public key encryption
// @param data_len length of message
// @param padding set of padding , 1 if padding is used, 0 if not used.
// padding prevents an attacker from knowing the exact length of the plaintext
// message.
// @param path protected key path
// @param ret_len length of encrypted message
// @return encrypted message from public key encryption
unsigned char *public_encrypt(unsigned char *data, size_t data_len, int padding,
                              EVP_PKEY *pub_key, size_t *ret_len);

// Decrypt message with private key using private key decryption from OpenSSL.
// @param enc_data encrypted message for private key decryption
// @param enc_data_len length of encrypted message
// @param padding set of padding , 1 if padding is used, 0 if not used.
// padding prevents an attacker from knowing the exact length of the plaintext
// message.
// @param path private key path
// @param ret_len length of decrypted message
// @return decrypted message from private key decryption
unsigned char *private_decrypt(unsigned char *enc_data, size_t enc_data_len,
                               int padding, EVP_PKEY *priv_key,
                               size_t *ret_len);

// After digest the encrypted message, sign digested message
// with private key using private key signature from OpenSSL.
// @param encrypted encrypted message to sign
// @param encrypted_length length of encrypted message
// @param path private key path for private key signature
// @param sig_length length of signed buffer
// @return sign sign of the encrypted message
unsigned char *SHA256_sign(unsigned char *encrypted,
                           unsigned int encrypted_length, EVP_PKEY *priv_key,
                           size_t *sig_length);

// Verification of encrypted data and signature
// using the RSA verification from OpenSSL.
// @param data encrypted data
// @param data_length length of encrypted data
// @param sign signature buffer
// @param sign_length length of signiture
// @param path public key path
void SHA256_verify(unsigned char *data, unsigned int data_length,
                   unsigned char *sig, size_t sig_length, EVP_PKEY *pub_key);

// Digest the encrypted message using the SHA256 digest function from OpenSSL.
// @param message encrypted data
// @param message_length length of encrypted data
// @param digest_len length of the digested message
// @return digested_message
unsigned char *digest_message_SHA_256(unsigned char *message,
                                      int message_length,
                                      unsigned int *digest_len);

// Encrypt the message with the cipher key of the session key obtained from Auth
// by using Cipher Block Chaining(CBC) encryption of OpenSSL.
// @param plaintext data to encrypt
// @param plaintext_length length of plaintext
// @param key cipher key of session key to be used in CBC encryption
// @param key_length length of cipher key
// @param iv initialize vector to be used in first encryption of CBC encryption
// @param iv_length length of iv buffer
// @param ret decrypted message received from CBC encryption
// @param ret_length length of ret
void AES_CBC_128_encrypt(unsigned char *plaintext,
                         unsigned int plaintext_length, unsigned char *key,
                         unsigned int key_length, unsigned char *iv,
                         unsigned int iv_length, unsigned char *ret,
                         unsigned int *ret_length);

// Decrypt the message with the cipher key of the session key obtained from Auth
// by using Cipher Block Chaining(CBC) decryption of OpenSSL.
// @param encrypted encrypted data
// @param encrypted_length length of encrypted data
// @param key cipher key of session key to be used in CBC decryption
// @param key_length length of cipher key
// @param iv initialize vector to be used in first decryption of CBC decryption
// @param iv_length length of iv buffer
// @param ret decrypted message received from CBC decryption
// @param ret_length length of ret
void AES_CBC_128_decrypt(unsigned char *encrypted,
                         unsigned int encrypted_length, unsigned char *key,
                         unsigned int key_length, unsigned char *iv,
                         unsigned int iv_length, unsigned char *ret,
                         unsigned int *ret_length);

// Encrypt the message with cipher key and
// make HMAC(Hashed Message Authenticate Code) with mac key from session key.
// @param buf input message
// @param buf_length length of buf
// @param mac_key mac key of session key to be used in HMAC
// @param mac_key_size size of mac key
// @param cipher_key cipher key of session key to be used in CBC encryption
// @param cipher_key_size size of cipher key
// @param iv_size size of iv(initialize vector)
// @param ret_length length of return buffer
unsigned char *symmetric_encrypt_authenticate(
    unsigned char *buf, unsigned int buf_length, unsigned char *mac_key,
    unsigned int mac_key_size, unsigned char *cipher_key,
    unsigned int cipher_key_size, unsigned int iv_size,
    unsigned int *ret_length);

// Decrypt the encrypted message with cipher key and
// make HMAC(Hashed Message Authenticate Code) with mac key from session key.
// @param buf input message
// @param buf_length length of buf
// @param mac_key mac key of session key to be used in HMAC
// @param mac_key_size size of mac key
// @param cipher_key cipher key of session key to be used in CBC decryption
// @param cipher_key_size size of cipher key
// @param iv_size size of iv(initialize vector)
// @param ret_length length of return buffer
unsigned char *symmetric_decrypt_authenticate(
    unsigned char *buf, unsigned int buf_length, unsigned char *mac_key,
    unsigned int mac_key_size, unsigned char *cipher_key,
    unsigned int cipher_key_size, unsigned int iv_size,
    unsigned int *ret_length);

#endif  // C_CRYPTO_H
