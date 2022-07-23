#include "c_crypto.h"
/*
    function:
    input:
    output:
*/
/*
    function: prints error message
    input: Error message to display
    output: input message & openssl error
*/
void print_last_error(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

//TODO: �������� ���� check input ���� ���߷��� input ���� �ٲ�. Ȯ�ν� �����a.

/*
    function: read X509cert.pem file & get pubkey from 'path'. RSA_public_encrypt 'data' to 'ret' with 'padding'
    input: 'ret': encrypted buf, 'data': data to encrypt
    output: length of encrypted data
*/


unsigned char * public_encrypt(unsigned char * data, int data_len, int padding, const char * path, unsigned int *ret_len) 
{
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_last_error("is not RSA Encryption file");
    }
    /*openssl 3.0 -> do not change to RSA. 
    directly use EVP_PKEY
    */
    EVP_PKEY_CTX *ctx;
    ENGINE *eng;
    unsigned char *out;

    ctx = EVP_PKEY_CTX_new(pkey, eng);
    if (!ctx)
    print_last_error("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    print_last_error("EVP_PKEY_encrypt_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
    print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");

    /* Determine buffer length */
    if (EVP_PKEY_encrypt(ctx, NULL, (size_t *) ret_len, data, data_len) <= 0)
    print_last_error("EVP_PKEY_encrypt failed");


    out = OPENSSL_malloc(*ret_len);

    if (!out)
    print_last_error("OPENSSL_malloc failed");

    if (EVP_PKEY_encrypt(ctx, out, (size_t *) ret_len, data, data_len) <= 0)
    print_last_error("EVP_PKEY_encrypt failed");

 /* Encrypted data is outlen bytes written to buffer out */
    return out;
}

//test

/*
    function: read PEM key from 'path'. RSA_Private_decrypt 'encrypted' and save in 'ret' with 'padding'
    input: 'ret': decrypted result buf, 'enc_data': data to decrypt
    output: return decrypted length
*/
int private_decrypt(unsigned char * enc_data, int enc_data_len, int padding, const char * path, unsigned char *ret)
{
    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                                        pem_password_cb *cb, void *u);
    int result = RSA_private_decrypt(enc_data_len, enc_data, ret, rsa, padding);
    if(result == -1){  // RSA_private_decrypt() returns -1 on error
        print_last_error("Private Decrypt failed!");
        exit(0);
    }
    else{
        printf("Private Decrypt Success!\n");
    }
    return result;
}

/*
    function: make sign to 'sigret' buf, with private key from 'path', and data 'encrypted' 
    input:'sigret': return signed buf, 'encrypted': data to sign
    output: 
*/
void SHA256_sign(unsigned char *encrypted, unsigned int encrypted_length, const char * path, unsigned char *sigret, unsigned int * sigret_length)
{
    FILE *keyfile = fopen(path, "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    unsigned char dig_enc[SHA256_DIGEST_LENGTH];
    SHA256_make_digest_msg(encrypted, encrypted_length, dig_enc);


    int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
            sigret, sigret_length, rsa);
    if(sign_result == 1)
        printf("Sign successed! \n");
    else
        print_last_error("Sign failed! \n");

    
    EVP_PKEY_CTX *ctx;
    /* md is a SHA-256 digest in this example. */
    unsigned char *md, *sig;
    size_t mdlen = 32, siglen;
    EVP_PKEY *signing_key;

    /*
    * NB: assumes signing_key and md are set up before the next
    * step. signing_key must be an RSA private key and md must
    * point to the SHA-256 digest to be signed.
    */
    ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
    if (!ctx)
        /* Error occurred */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        /* Error */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        /* Error */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        /* Error */

    /* Determine buffer length */
    if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0)
        /* Error */

    sig = OPENSSL_malloc(siglen);

    if (!sig)
        /* malloc failure */

    if (EVP_PKEY_sign(ctx, sig, &siglen, md, mdlen) <= 0)
        /* Error */
        print_last_error("H");

    /* Signature is siglen bytes written to buffer sig */
}

/*
    function: Checks if sign and data verified. needs to digest message.
    input:
    output: error when verify fails
*/

void SHA256_verify(unsigned char * data, unsigned int data_length, unsigned char * sign, unsigned int sign_length, const char * path)
{
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509( pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_last_error("is not RSA Encryption file");
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) {
        print_last_error("EVP_PKEY_get1_RSA fail");
    }
    // verify! 
    unsigned char digest_buf[SHA256_DIGEST_LENGTH];
    SHA256_make_digest_msg(data, data_length, digest_buf);
    // RSA * rsa2 = create_RSA(authPublicKey,true);   
    int verify_result = RSA_verify(NID_sha256, digest_buf,SHA256_DIGEST_LENGTH,
          sign, sign_length, rsa);

    if(verify_result ==1)
        printf("verify success\n\n");
    else{
        print_last_error("verify failed\n");
    }
}
/*
    function: make SHA256 digest message
    input:
    output:
*/
void SHA256_make_digest_msg(unsigned char *encrypted ,int encrypted_length, unsigned char *dig_enc)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);   
}

void AES_CBC_128_encrypt(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * key, unsigned int key_length, unsigned char * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length)
{ 
    unsigned char iv_temp[AES_CBC_128_IV_SIZE];
    memcpy(iv_temp, iv, AES_CBC_128_IV_SIZE);
    //TODO: check iv changing. if not needed, erase.
    AES_KEY enc_key_128;
    if(AES_set_encrypt_key(key, AES_CBC_128_KEY_SIZE, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(plaintext, ret, plaintext_length , &enc_key_128, iv_temp, AES_ENCRYPT);  //iv �� �ٲ��?.
    *ret_length = ((plaintext_length) +iv_length)/iv_length *iv_length;
}

void AES_CBC_128_decrypt(unsigned char * encrypted, unsigned int encrypted_length, unsigned char * key, unsigned int key_length, unsigned char  * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length)
{ 
    AES_KEY enc_key_128;
    if(AES_set_decrypt_key(key, AES_CBC_128_KEY_SIZE, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(encrypted, ret, encrypted_length, &enc_key_128, iv, AES_DECRYPT); //iv�� �ٲ��???po
    // *ret_length = ((encrypted_length) +iv_length)/iv_length *iv_length;
}

//encrypt buf to ret with mac_key, cipher_key
//iv16+encrypted_data+HMAC_tag32
/*
function: 

input:  buf: buf to encrypt
        mac_key: for hmac. Mostly will be session_key's mac_key.
        cipher_key: for encryption. Mostly will be session_key's cipher_key.
        mac_key_size, cipher_key_size, iv_size: put in from config.
        ret_length: the returning buffer's length.
return: unsigned char *. iv+encrypted_data+HMAC_tag ex)16 + n + 32

usage:
    unsigned int encrypted_length;
    unsigned char * encrypted = symmetric_encrypt_authenticate(buf_to_encrypt, buf_to_encrypt_length, mac_key, MAC_KEY_SIZE, cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &encrypted_length);
    ~~ use 'encrypted' ~~
    free(encrypted); //never forget!!
*/

unsigned char * symmetric_encrypt_authenticate(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length)
{
    unsigned char * iv = (unsigned char *) malloc(iv_size);
    generate_nonce(iv_size, iv);
    unsigned int encrypted_length = ((buf_length/iv_size)+1)*iv_size;
    unsigned char * encrypted = (unsigned char *) malloc(encrypted_length);
    AES_CBC_128_encrypt(buf, buf_length, cipher_key, cipher_key_size, iv, iv_size, encrypted, &encrypted_length);

    unsigned int temp_length = ((buf_length/iv_size)+1)*iv_size + iv_size;
    unsigned char * temp = (unsigned char *) malloc(temp_length);
    memcpy(temp, iv, iv_size);
    memcpy(temp+iv_size, encrypted, encrypted_length);
    temp_length = iv_size + encrypted_length;
    unsigned char * hmac_tag = (unsigned char *) malloc(mac_key_size);
    HMAC(EVP_sha256(), mac_key, mac_key_size, temp, temp_length, hmac_tag, &mac_key_size );
    
    *ret_length = temp_length + mac_key_size;
    unsigned char * ret = (unsigned char *) malloc(*ret_length);
    memcpy(ret, temp, temp_length);
    memcpy(ret + temp_length, hmac_tag, mac_key_size);
    free(encrypted);free(temp);free(iv);free(hmac_tag);
    return ret;
}

/*
Usage:
    unsigned int decrypted_length;
    unsigned char * decrypted = symmetric_decrypt_authenticate(buf_to_decrypt, buf_to_decrypt_length, mac_key, MAC_KEY_SIZE, cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
    ~~ use 'encrypted' ~~
    free(decrypted); //never forget!!
*/

unsigned char * symmetric_decrypt_authenticate(unsigned char * buf, unsigned int buf_length, unsigned char * mac_key, unsigned int mac_key_size, unsigned char * cipher_key, unsigned int cipher_key_size, unsigned int iv_size, unsigned int * ret_length)
{
    unsigned int encrypted_length = buf_length - mac_key_size;
    unsigned char * encrypted = (unsigned char *) malloc(encrypted_length);
    memcpy(encrypted, buf, encrypted_length);
    unsigned char * received_tag = (unsigned char *) malloc(mac_key_size);
    memcpy(received_tag, buf + encrypted_length, mac_key_size);
    unsigned char * hmac_tag = (unsigned char *) malloc(mac_key_size);
    HMAC(EVP_sha256(), mac_key, mac_key_size, encrypted, encrypted_length, hmac_tag, &mac_key_size );
    if(strncmp(received_tag, hmac_tag, mac_key_size) != 0){
        error_handling("Ivalid MAC error!");
    }
    else{
        printf("MAC verified!\n");
    }
    unsigned char * iv = (unsigned char *) malloc(iv_size);
    memcpy(iv, encrypted, iv_size);

    unsigned int temp_length = encrypted_length - iv_size;
    unsigned char * temp = (unsigned char *) malloc(temp_length);
    memcpy(temp, encrypted+iv_size, temp_length);  
    *ret_length = ((temp_length) +iv_size)/iv_size *iv_size;
    unsigned char * ret = (unsigned char *) malloc(*ret_length);
    memset(ret, 0, *ret_length);
    AES_CBC_128_decrypt(temp, temp_length, cipher_key, cipher_key_size, iv, iv_size, ret, ret_length);
    free(encrypted);free(received_tag);free(hmac_tag);free(iv);free(temp);
    return ret;
}