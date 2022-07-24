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
    unsigned char *out;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
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

/*
    function: read PEM key from 'path'. RSA_Private_decrypt 'encrypted' and save in 'ret' with 'padding'
    input: 'ret': decrypted result buf, 'enc_data': data to decrypt
    output: return decrypted length
*/
unsigned char * private_decrypt(unsigned char * enc_data, int enc_data_len, int padding, const char * path, unsigned int *ret_len)
{
    FILE *keyfile = fopen(path, "rb"); 
    EVP_PKEY *key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);

    EVP_PKEY_CTX *ctx;
    unsigned char *out;
    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
    print_last_error("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    print_last_error("EVP_PKEY_decrypt_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
    print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");

    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx, NULL, (size_t *) ret_len, enc_data, enc_data_len) <= 0)
    print_last_error("EVP_PKEY_decrypt failed");

    out = OPENSSL_malloc(*ret_len);

    if (!out)
    print_last_error("OPENSSL_malloc failed");

    if (EVP_PKEY_decrypt(ctx, out, (size_t *) ret_len, enc_data, enc_data_len) <= 0)
    print_last_error("EVP_PKEY_decrypt failed");

    return out;
}

/*
    function: make sign to 'sigret' buf, with private key from 'path', and data 'encrypted' 
    input:'sigret': return signed buf, 'encrypted': data to sign
    output: 
*/

//under construction
unsigned char * SHA256_sign(unsigned char *encrypted, unsigned int encrypted_length, const char * path, unsigned int * sig_length)
{
    FILE *keyfile = fopen(path, "rb"); 
    EVP_PKEY *signing_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    unsigned int md_length;
    unsigned char * md = digest_message_SHA_256(encrypted, encrypted_length, &md_length);  
    EVP_PKEY_CTX *ctx;
    unsigned char *sig;
    ctx = EVP_PKEY_CTX_new(signing_key, NULL);
    if (!ctx)
        print_last_error("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_sign_init(ctx) <= 0)
        print_last_error("EVP_PKEY_sign_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        print_last_error("EVP_PKEY_CTX_set_signature_md failed");

    /* Determine buffer length */
    if (EVP_PKEY_sign(ctx, NULL, (size_t *) sig_length, md, md_length) <= 0)
        print_last_error("EVP_PKEY_sign failed");

    sig = OPENSSL_malloc(*sig_length);
    if (!sig)
        print_last_error("OPENSSL_malloc failed");
    if (EVP_PKEY_sign(ctx, sig, (size_t *) sig_length, md, md_length) <= 0)
        print_last_error("EVP_PKEY_sign failed");
    free(md);
    return sig;
}

/*
    function: Checks if sign and data verified. needs to digest message.
    input:
    output: error when verify fails
*/

void SHA256_verify(unsigned char * data, unsigned int data_length, unsigned char * sig, unsigned int sig_length, const char * path)
{
    FILE *pemFile = fopen(path, "rb");
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL );
    EVP_PKEY *verify_key = X509_get_pubkey(cert);
    if (verify_key == NULL){
        print_last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(verify_key);
    if ( id != EVP_PKEY_RSA ) {
        print_last_error("is not RSA Encryption file");
    }
    EVP_PKEY_CTX *ctx;
    unsigned int md_length;
    unsigned char * md = digest_message_SHA_256(data, data_length, &md_length);  

    ctx = EVP_PKEY_CTX_new(verify_key, NULL);
    if (!ctx)
        print_last_error("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_verify_init(ctx) <= 0)
        print_last_error("EVP_PKEY_verify_init failed");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        print_last_error("EVP_PKEY_CTX_set_signature_md failed");
    /* Perform operation */
    if(EVP_PKEY_verify(ctx, sig, sig_length, md, md_length) != 1)
        print_last_error("EVP_PKEY_verify failed");
    free (md);
}
/*
    function: make SHA256 digest message
    input:
    output:
*/

unsigned char * digest_message_SHA_256(unsigned char *message, int message_length, unsigned int *digest_len)
{
    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
        print_last_error("EVP_MD_CTX_create() failed");
    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        print_last_error("EVP_DigestInit_ex failed");
    if(EVP_DigestUpdate(mdctx, message, message_length) != 1)
        print_last_error("EVP_DigestUpdate failed");
    unsigned char *digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if(EVP_DigestFinal_ex(mdctx, digest, digest_len) != 1)
        print_last_error("failed");
    EVP_MD_CTX_destroy(mdctx);
    return digest;
}

 int do_crypt(char *outfile)
 {
     unsigned char outbuf[1024];
     int outlen, tmplen;
     /*
      * Bogus key and IV: we'd normally set these from
      * another source.
      */
     unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
     unsigned char iv[] = {1,2,3,4,5,6,7,8};
     char intext[] = "Some Crypto Text";

     FILE *out;

     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     EVP_EncryptInit_ex2(ctx, EVP_idea_cbc(), key, iv, NULL);

     if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, intext, strlen(intext))) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     }
     /*
      * Buffer passed to EVP_EncryptFinal() must be after data just
      * encrypted to avoid overwriting it.
      */
     if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)) {
         /* Error */
         EVP_CIPHER_CTX_free(ctx);
         return 0;
     }
     outlen += tmplen;
     EVP_CIPHER_CTX_free(ctx);
     /*
      * Need binary mode for fopen because encrypted data is
      * binary data. Also cannot use strlen() on it because
      * it won't be NUL terminated and may contain embedded
      * NULs.
      */
     out = fopen(outfile, "wb");
     if (out == NULL) {
         /* Error */
         return 0;
     }
     fwrite(outbuf, 1, outlen, out);
     fclose(out);
     return 1;
 }

void AES_CBC_128_encrypt(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * key, unsigned int key_length, unsigned char * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length)
{ 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(ctx, EVP_aes_128_cbc(), key, iv, NULL);
    if (!EVP_EncryptUpdate(ctx, ret, ret_length, plaintext, plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptUpdate failed");
    }    
    unsigned int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ret + *ret_length, &temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptFinal_ex failed");
    }
    *ret_length += temp_len;
    EVP_CIPHER_CTX_free(ctx);
}

void AES_CBC_128_decrypt(unsigned char * encrypted, unsigned int encrypted_length, unsigned char * key, unsigned int key_length, unsigned char  * iv, unsigned int iv_length, unsigned char * ret, unsigned int * ret_length)
{ 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex2(ctx, EVP_aes_128_cbc(), key, iv, NULL);
    if (!EVP_DecryptUpdate(ctx, ret, ret_length, encrypted, encrypted_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_DecryptUpdate failed");
    }    
    unsigned int temp_len;
    if (!EVP_DecryptFinal_ex(ctx, ret + *ret_length, &temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_DecryptFinal_ex failed");
    }
    *ret_length += temp_len;
    EVP_CIPHER_CTX_free(ctx);
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