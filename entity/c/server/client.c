/*
.toString('hex').match(/../g).join(' ')
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
node client.js configs/net1/client.config
node client.js configs/net1/client_0.config

node server.js configs/net1/server.config
gcc -g client.c -o client -lcrypto -lm
./client 127.0.0.1 21900
Ubuntu terminator: Ctrl+Shift+w: close, Ctrl+Shift+e: , Ctrl+Shift+o: horizontally
Window terminal: Alt+Shift++, Alt+Shift+-, Alt+Shift+arrows: resize
*/

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

int padding = RSA_PKCS1_PADDING;

struct auth_hello_message_received{
    unsigned int auth_Id;
    unsigned char auth_Nonce[NONCE_SIZE];
};
struct strbuf{
    unsigned int length;
    unsigned char buf[1000];  //??©£?(?? ???? ???? ?? ????)
};
struct numkeys{
    unsigned char numkeys;
    unsigned char buf[4];  //??? 4 ????!
};
struct signed_data{
    struct strbuf data;
    struct strbuf sign;
};
/*  num: number of payload in decimals
    buf_len: length of changed buffer. Max 4
    buf[4]: payload_lengh buffer
*/
struct payload_length{
    unsigned int num;
    unsigned char buf_len;
    unsigned char buf[4];
};
/*  received_buf: received message from socket
    payload: removed buffer header  */

struct received{
    struct strbuf received_buf;
    unsigned char message_type;
    struct payload_length payload_length;
    unsigned char payload[1000];
};
struct parsed_distribution_key{
    unsigned char abs_validity; //TODO: ??¡À? type ??????.
    struct strbuf cipher_key_val;
    struct strbuf mac_key_val;
};
struct parsed_session_key{
    unsigned int key_Id;
    unsigned char abs_validity; //TODO: ??? ????.
    unsigned int rel_validity; 
    struct strbuf cipher_key_val;
    struct strbuf mac_key_val;
};
struct session_key_response{
    struct parsed_distribution_key parsed_distribution_key;
    struct strbuf reply_nonce;
    unsigned char crypto_spec; //TODO: ??? ????.
    struct parsed_session_key session_key_list[10]; //TODO:  check
    unsigned int session_key_list_length;
};
struct callback_params_server{
    struct strbuf targetSessionKeyCache;
    unsigned int key_Id;
    // int sendHandshake2Callback; //TODO: temp
    struct strbuf handshake1Payload;
    int serverSocket; //TODO: temp
};

void error_handling(char *message);
void generate_nonce(unsigned char * generated, unsigned long size);
void string_to_int();
RSA * create_RSA(unsigned char * key, bool public);
int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted);
char *loadfile(char *filename);
void print_Last_error(char *msg);
unsigned int length(unsigned char * a);
void print_in_hex(unsigned char * var);
void parse_Auth_Hello(struct received * received, struct auth_hello_message_received *auth_hello_message_received);
void generate_reply_message(struct auth_hello_message_received *auth_hello_message_received, unsigned char * replyNonce, struct strbuf * session_key_request_buf);
void write_in_4bytes(unsigned char  num, unsigned char * buf);
void make_digest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length);
void num_to_var_length_int(struct payload_length *buf);
void parse_IoT_SP( struct received * received);
void var_length_int_to_num(struct strbuf * buf, struct payload_length * payload_length, int offset);
void verify(struct signed_data * distribution_key_buf);
void sign(struct strbuf *sigret, struct strbuf *encrypted);
void encrypt_and_sign_and_concat(struct strbuf *finished, struct strbuf *message_to_encrypt);
void make_buffer_header(struct strbuf *header, struct strbuf *payload, unsigned char MESSAGE_TYPE);
void concat_buffer_header_and_payload(struct strbuf *ret, struct strbuf *header, struct strbuf *payload);
void check_read_error(unsigned int  length);
void parse_data_SESSION_KEY_RESP_WITH_DIST_KEY(struct received *received, struct signed_data *distribution_key_buf, struct strbuf * session_key_buf, int key_size);
void parse_distribution_key(struct parsed_distribution_key *parsed_distribution_key, struct strbuf *buf);
void symmetric_decrypt_authenticate(struct strbuf * ret, struct strbuf * buf, struct parsed_distribution_key* symmetric_key_set);
void AES_CBC_128_decrypt(struct strbuf * ret, struct strbuf * encrypted, struct strbuf * key, struct strbuf  * iv);

void parse_session_key_response(struct session_key_response *session_key_response, struct strbuf *buf);
void parse_string_param(struct strbuf *return_to, struct strbuf * buf, int offset);
unsigned int parse_session_key(struct parsed_session_key *ret, struct strbuf *buf);
unsigned int read_uint_32BE(unsigned char *buf);
unsigned int read_uint_BE(unsigned char *buf, unsigned int offset, unsigned int byte_length);
void handle_session_key_resp_client(struct parsed_session_key *session_key_list[], struct signed_data receivedDistKey, int callbackParams);

void connection(int * sock, const char * ip_addr, const char * port_num);
void send_session_key_request(struct strbuf * ret, struct received * received, unsigned char * reply_nonce, struct callback_params_server *callback_params);
void parse_session_key_response_with_dist_key(struct session_key_response *session_key_response, struct received * response_received,unsigned char * reply_nonce);

int main(int argc, char * argv[]){

    //Error when wrong args
    if(argc != 3){
        error_handling("number of input args wrong");
    }
    const char * IP_ADDRESS = argv[1];
    const char * PORT_NUM = argv[2];
    int sock;
    connection(&sock, IP_ADDRESS, PORT_NUM);
    struct received first_received;

    //message?? ????
	first_received.received_buf.length=read(sock, first_received.received_buf.buf, sizeof(first_received.received_buf.buf)-1);
    check_read_error(first_received.received_buf.length);
    parse_IoT_SP(&first_received);

    struct callback_params_server callback_params; //TODO: ???.

    if(first_received.message_type == AUTH_HELLO){
        struct strbuf sendbuffer;
        unsigned char reply_nonce[NONCE_SIZE];
        send_session_key_request(&sendbuffer, &first_received, reply_nonce, &callback_params);
        write(sock, sendbuffer.buf,sendbuffer.length);

        // read SESSION_KEY_RESP_WITH_DIST_KEY
        struct received response_received;
	    response_received.received_buf.length=read(sock, response_received.received_buf.buf, sizeof(response_received.received_buf.buf)-1);
        check_read_error(response_received.received_buf.length);       
        parse_IoT_SP(&response_received);

        if(response_received.message_type == SESSION_KEY_RESP_WITH_DIST_KEY){
            struct session_key_response session_key_response;
            parse_session_key_response_with_dist_key(&session_key_response, &response_received, reply_nonce);
            // handle_session_key_resp_client(session_key_response.session_key_list, receivedDistKey, callbackParams);

        }
        printf("\n");
    }
    close(sock);
    return 0;
}

void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void connection(int * sock, const char * ip_addr, const char * port_num){
    struct sockaddr_in serv_addr;
    struct received first_received;
    int str_len;

    //???? ????
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if(*sock == -1){
        error_handling("socket() error");
    }

    //??? ?? 0???? ????, memset(?????????, ??????, ????)
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; //??? ?¬Û¬Ú?, IPv4???

    //????????? ?????? ip ??? ????, (command line ???? ????)
    //inet_addr( )????? ????? ???¡¤? IP???? ??©ö?? 32??? ????(?????? ????? ????)?? ????
    serv_addr.sin_addr.s_addr = inet_addr(ip_addr);

    //??? ??? ???? 
    //atoi() -???? ??????? ?????? ???
    //htons() - ?????? ????? ?????? ??? 
    serv_addr.sin_port = htons(atoi(port_num));

    /*
    ???? ??? ??? connect()
    int connect(
            int sockfd ???? ???????, 
            const struct sockaddr *serv_addr ???? ??? ?????? ???? ?????? , 
            socklen_t addrlen ??????? ??????? ??????? ???)   
    return: -1==????  0==????
    */
    
    if(connect(*sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        error_handling("connect() error!");
    }
    printf("\n\n------------Connected-------------\n");
}


void string_to_int(){
    int test[25]={}, i=0, j;
    char a[25]="This is a test string.";
    while(a[i]!='\0') {
        test[i]=a[i];
        i++;
    }
    for(j=0;j<i-1;j++){
        printf("%d ",test[j]);
    }
}

RSA * create_RSA(unsigned char * key,bool public){
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1); // ?¬Ò? ???? ??? ????? BIO
    if (keybio==NULL){
        printf( "Failed to create key BIO");
        return 0;
    }
    /* PEM?????? ? ?????? ?¬à??? RSA ????? ???????? ??? */
    if(public){ // PEM public ??? RSA ????
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }else{ // PEM private ??? RSA ????
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    
    if(rsa == NULL){
        printf( "Failed to create RSA");
    }
    return rsa;
}

/* ??????? ???? */
int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted) {
    ///mnt/c/Users/user/project/iotauth/entity/auth_certs/Auth101EntityCert.pem
    FILE *pemFile = fopen("../../auth_certs/Auth101EntityCert.pem", "rb");
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_Last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_Last_error("is not RSA Encryption file");
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) {
        print_Last_error("EVP_PKEY_get1_RSA fail");
    }
    int padding = RSA_PKCS1_PADDING;
    // RSA * rsa = create_RSA(authPublicKey,true);
    int result = RSA_public_encrypt(data_len,data,encrypted, rsa,padding);
    if(result == -1){ // RSA_public_encrypt() returns -1 on error
        print_Last_error("Public Encrypt failed!\n");
        exit(0);
    }
    else{
        printf("Public Encryption Success!\n");
    }
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted){
    ///mnt/c/Users/user/project/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem
    //client?? ?????
    FILE *keyfile = fopen("../../credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    int padding = RSA_PKCS1_PADDING;
    // RSA * rsa = create_RSA(testPrivateKey,false);

    RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                                        pem_password_cb *cb, void *u);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    if(result == -1){  // RSA_private_decrypt() returns -1 on error
        print_Last_error("Private Decrypt failed!");
        exit(0);
    }
    else{
        printf("Private Decrypt Success!\n");
    }
    return result;
}

void print_Last_error(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

unsigned int length(unsigned char * a){
    // printf("sizeof(a) = %ld, sizeof(a[0]) = %ld\n", sizeof(a), sizeof(a[0]));
    return sizeof(a)/sizeof(a[0]);
}

//TODO: ???? ???
void print_in_hex(unsigned char * var){
    for (int i = 0; i < sizeof(var); i++){
        printf("%x ", var[i]);    
    }
    printf("\n");
}

void generate_nonce(unsigned char * generated, unsigned long size){
    int rc = RAND_bytes(generated, sizeof(generated));
    if(rc == -1){
        printf("Failed to create randomNonce.");
        exit(1);
    }
}
//replyNonce[8byte]+auth_Nonce[8byte]+numkeys[4byte]+senderbuf[size:1 + buf]+purposeBuf[size:1 +buf]
void generate_reply_message(struct auth_hello_message_received *auth_hello_message_received, unsigned char * replyNonce, struct strbuf * session_key_request_buf){
    //numkeys 4byte
    struct numkeys numkeys = {
        .numkeys = 3, //TODO: ???? ????
    };
    write_in_4bytes(numkeys.numkeys, numkeys.buf);

    //senderBuf ????
    struct strbuf senderBuf = {
        .length = (unsigned char) sizeof("net1.client")/sizeof(unsigned char) - 1, // \0??? ????? //TODO: -1 check??
        .buf = "net1.client" //TODO: ???? ????
    };

    //purposeBuf ????
    struct strbuf purposeBuf = {
        .length = (unsigned char) sizeof("{\"group\":\"Servers\"}")/sizeof(unsigned char) - 1, // \0??? ?????
        .buf = "{\"group\":\"Servers\"}" //TODO: ???? ????
    };

    unsigned char temp[] = {senderBuf.length};
    unsigned char temp2[] = {purposeBuf.length};

    memcpy(session_key_request_buf->buf, replyNonce, NONCE_SIZE);
    memcpy(session_key_request_buf->buf + NONCE_SIZE, auth_hello_message_received->auth_Nonce, NONCE_SIZE);
    memcpy(session_key_request_buf->buf + NONCE_SIZE*2, numkeys.buf, NUM_KEYS_SIZE);
    memcpy(session_key_request_buf->buf + NONCE_SIZE*2 + NUM_KEYS_SIZE, temp, 1);
    memcpy(session_key_request_buf->buf + NONCE_SIZE*2 + NUM_KEYS_SIZE + 1, senderBuf.buf, senderBuf.length);
    memcpy(session_key_request_buf->buf + NONCE_SIZE*2 + NUM_KEYS_SIZE + 1 + senderBuf.length, temp2, 1);
    memcpy(session_key_request_buf->buf + NONCE_SIZE*2 + NUM_KEYS_SIZE + 1 + senderBuf.length +1, purposeBuf.buf, purposeBuf.length);
    session_key_request_buf->length = NONCE_SIZE*2 + NUM_KEYS_SIZE + 1 + senderBuf.length +1 + purposeBuf.length;
}

void write_in_4bytes(unsigned char num, unsigned char * buf){
    buf[0] = (num >> 24) & 0xFF;
    buf[1] = (num >> 16) & 0xFF;
    buf[2] = (num >> 8) & 0xFF;
    buf[3] = num & 0xFF;
}

void make_digest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length){
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);   
}

//change num to variable length in int?
//return struct strbuf extra_buf 
void num_to_var_length_int(struct payload_length *buf){
    int num = buf->num;
    buf->buf_len = 1;
    while(num > 127)
    {
        buf->buf[buf->buf_len-1] = 128 | num & 127;
        buf->buf_len += 1;
        num >>=7;
    }
    buf->buf[buf->buf_len-1] = num;
}

//auth hello response???? ????.
int getPublicEncryptedAndSignedMessageSize(int key_size) {
    return key_size* 2;     // only for RSA
}

// parses received message into struct received (msg_type, payload_length, payload_buffer)
void parse_IoT_SP(struct received * received){
    received->message_type = received->received_buf.buf[0];
    var_length_int_to_num(&received->received_buf, &received->payload_length, 1);
    memcpy(received->payload , received->received_buf.buf + 1 + received->payload_length.buf_len , received->payload_length.num);
}

void var_length_int_to_num(struct strbuf * buf, struct payload_length * payload_length, int offset){
    unsigned int num = 0;
    for( int i = 0; i < buf->length && i < 5; i++) {
        num |= (buf->buf[offset + i] & 127) << (7 * i);
        if ((buf->buf[offset + i] & 128) == 0) {
            payload_length->num = num;
            payload_length->buf_len = i +1;
            break;
        }
    }
}
void verify(struct signed_data *distribution_key_buf){
    FILE *pemFile = fopen("./../../auth_certs/Auth101EntityCert.pem", "rb");
    X509 *cert = PEM_read_X509( pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_Last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_Last_error("is not RSA Encryption file");
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) {
        print_Last_error("EVP_PKEY_get1_RSA fail");
    }
    // verify! 
    unsigned char distribution_key_buf_dig[SHA256_DIGEST_LENGTH];
    make_digest_msg(distribution_key_buf_dig, distribution_key_buf->data.buf, distribution_key_buf->data.length);
    // RSA * rsa2 = create_RSA(authPublicKey,true);   
    int verify_result = RSA_verify(NID_sha256, distribution_key_buf_dig,SHA256_DIGEST_LENGTH,
          distribution_key_buf->sign.buf, distribution_key_buf->sign.length, rsa);

    if(verify_result ==1)
        printf("verify success\n\n");
    else{
        print_Last_error("verify failed\n");
    }
}

// auth_hello_message_received?? auth_ID, auth_NONCE ???
void parse_Auth_Hello(struct received * received, struct auth_hello_message_received *auth_hello_message_received){
    auth_hello_message_received->auth_Id = read_uint_BE(received->payload, 0, AUTH_ID_SIZE);
    memcpy(auth_hello_message_received->auth_Nonce, received->payload + AUTH_ID_SIZE, NONCE_SIZE );
}

void sign(struct strbuf *sigret, struct strbuf *encrypted){
    //TODO: input ????
    FILE *keyfile = fopen("../../credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    unsigned char dig_enc[SHA256_DIGEST_LENGTH];
    make_digest_msg(dig_enc, encrypted->buf, encrypted->length);
    int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
          sigret->buf, &sigret->length, rsa);
    if(sign_result == 1)
        printf("Sign successed! \n");
    else
        print_Last_error("Sign failed! \n");
}

// returns concat of encryption + sign
void encrypt_and_sign_and_concat(struct strbuf *ret, struct strbuf *message_to_encrypt){
    struct strbuf encrypted;
    encrypted.length= (unsigned int) public_encrypt(message_to_encrypt->buf, (int) message_to_encrypt->length, encrypted.buf);
    struct strbuf sigret;
    sign(&sigret, &encrypted);
    ret->length = encrypted.length + sigret.length;
    memcpy(ret->buf, encrypted.buf, encrypted.length);
    memcpy(ret->buf + encrypted.length, sigret.buf, sigret.length);
}

// returns header
void make_buffer_header(struct strbuf *header, struct strbuf *payload, unsigned char MESSAGE_TYPE){
        struct payload_length payload_length_buf;
        payload_length_buf.num = payload->length;
        num_to_var_length_int(&payload_length_buf);

        header->length = MSG_TYPE_SIZE + payload_length_buf.buf_len;
        header->buf[0] = MESSAGE_TYPE;
        memcpy(header->buf + MSG_TYPE_SIZE, payload_length_buf.buf, payload_length_buf.buf_len);
}

// returns buffer of header + payload
void concat_buffer_header_and_payload(struct strbuf *ret, struct strbuf *header, struct strbuf *payload){
    memcpy(ret->buf, header->buf, header->length);
    memcpy(ret->buf + header->length, payload->buf, payload->length);
    ret->length = header->length + payload->length;
}

void check_read_error(unsigned int length){
    if(length == -1){
        error_handling("read() error!");
    }
}

void parse_data_SESSION_KEY_RESP_WITH_DIST_KEY(struct received *received, struct signed_data *distribution_key_buf, struct strbuf * session_key_buf, int key_size){
            distribution_key_buf->sign.length= key_size, distribution_key_buf->data.length= key_size, session_key_buf->length= received->payload_length.num - key_size *2 ;

            /* distribution_key_buf.data(key_size) + distribution_key_buf.sign(key_size)+ session_key_buf.buf(length-2*key_size)
             */
            memcpy(distribution_key_buf->data.buf, received->payload, key_size);
            memcpy(distribution_key_buf->sign.buf, received->payload +key_size, key_size);
            memcpy(session_key_buf->buf, received->payload +key_size*2, session_key_buf->length);
}

void parse_distribution_key(struct parsed_distribution_key *parsed_distribution_key, struct strbuf *buf){
    unsigned int curIndex = DIST_KEY_EXPIRATION_TIME_SIZE;
    unsigned int cipherKeySize = buf->buf[curIndex];
    curIndex += 1;
    memcpy(parsed_distribution_key->cipher_key_val.buf, buf->buf + curIndex, cipherKeySize);
    parsed_distribution_key->cipher_key_val.length = cipherKeySize;
    curIndex += cipherKeySize;
    unsigned int macKeySize = buf->buf[curIndex];
    curIndex += 1;
    memcpy(parsed_distribution_key->mac_key_val.buf, buf->buf +curIndex, macKeySize);
    parsed_distribution_key->mac_key_val.length = macKeySize;
}
// decrypt buf with symmetric_key_set
void symmetric_decrypt_authenticate(struct strbuf * ret, struct strbuf * buf, struct parsed_distribution_key* symmetric_key_set){ //TODO: add options.distributionCryptoSpec, TODO: may need to change sturct
    int mac_size = 32; //TODO: need to implement get_Mac_Size
    struct strbuf enc;
    memcpy(enc.buf, buf->buf, buf->length - mac_size);
    enc.length = buf->length - mac_size;
    struct strbuf receivedTag;
    memcpy(receivedTag.buf, buf->buf + buf->length - mac_size, mac_size);
    receivedTag.length = mac_size;
    struct strbuf hmac;
    HMAC(EVP_sha256(), symmetric_key_set->mac_key_val.buf, symmetric_key_set->mac_key_val.length, enc.buf, enc.length, hmac.buf, &hmac.length );
    if(strncmp(receivedTag.buf, hmac.buf, mac_size) != 0){
        error_handling("Ivalid MAC error!");
    }
    else{
        printf("MAC verified!\n");
    }
    int iv_size = AES_BLOCK_SIZE; //16  TODO: implement getCipherIvSize
    struct strbuf iv;
    memcpy(iv.buf, enc.buf, iv_size);
    iv.length = iv_size;

    struct strbuf temp;
    memcpy(temp.buf, enc.buf+iv_size, enc.length - iv_size);
    temp.length = enc.length - iv_size;
    bzero(ret->buf, 1000);
    ret->length = 0;
    AES_CBC_128_decrypt(ret, &temp, &symmetric_key_set->cipher_key_val,&iv);
}

//TODO: ??????.
void AES_CBC_128_decrypt(struct strbuf * ret, struct strbuf * encrypted, struct strbuf * key, struct strbuf  * iv){ 
    AES_KEY enc_key_128;
    if(AES_set_decrypt_key(key->buf, 128, &enc_key_128) < 0){
        error_handling("AES key setting failed!") ;
    }; 
    AES_cbc_encrypt(encrypted->buf, ret->buf, encrypted->length, &enc_key_128, iv->buf, AES_DECRYPT); 
    ret->length = encrypted->length;
}

void parse_session_key_response(struct session_key_response *session_key_response, struct strbuf *buf){
    memcpy(session_key_response->reply_nonce.buf,buf->buf, NONCE_SIZE);
    session_key_response->reply_nonce.length = NONCE_SIZE;
    int buf_idx = NONCE_SIZE;
    struct strbuf ret;
    parse_string_param(&ret, buf, buf_idx );
    //TODO: cryptoSpec ???? ???. iotAuthService.js 260
    buf_idx += ret.length; //48
    session_key_response->session_key_list_length = read_uint_32BE(&buf->buf[buf_idx]); //TODO: check
    buf_idx += 4;
    for(int i = 0; i < session_key_response->session_key_list_length; i ++){
        struct strbuf temp;
        memcpy(temp.buf, &buf->buf[buf_idx], buf->length - buf_idx);
        temp.length = buf->length - buf_idx;
        buf_idx += parse_session_key(&session_key_response->session_key_list[i], &temp);
    }
}
void parse_string_param(struct strbuf *return_to, struct strbuf * buf, int offset){
    struct payload_length ret;
    var_length_int_to_num(buf, &ret ,offset);
    if(ret.buf_len == 0){
        return_to->length = 1;
        memset(return_to->buf, 0, return_to->length);
    }
    memcpy(return_to->buf, buf->buf + offset+ ret.buf_len, ret.num);
    return_to->length = ret.buf_len + ret.num ;
}

unsigned int parse_session_key(struct parsed_session_key *ret, struct strbuf *buf){
    ret->key_Id = read_uint_BE(buf->buf, 0, SESSION_KEY_ID_SIZE);
    unsigned int cur_idx = SESSION_KEY_ID_SIZE;
    //TODO: abs_validity. iotAuthService.js 203
    cur_idx += SESSION_KEY_EXPIRATION_TIME_SIZE;
    ret->rel_validity = read_uint_BE(buf->buf, cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;
    ret->cipher_key_val.length = buf->buf[cur_idx];
    cur_idx += 1;
    memcpy(ret->cipher_key_val.buf,buf->buf+cur_idx, ret->cipher_key_val.length);
    cur_idx += ret->cipher_key_val.length;
    ret->mac_key_val.length = buf->buf[cur_idx];
    cur_idx += 1;
    memcpy(ret->mac_key_val.buf, buf->buf+cur_idx, ret->mac_key_val.length);
    cur_idx += ret->mac_key_val.length;
    return cur_idx;
    
}
//reads first 4bytes to unsigned int in big endian ( 12 34 56 78 => 12345678 => decimal)
unsigned int read_uint_32BE(unsigned char *buf){
    unsigned int ret;
    ret = buf[0] * pow(16, 3) + buf[1] * pow(16,2) +buf[2] * 16 + buf[3];
    return ret;
}
//read 'byte_length' bytes of 'buf' with offset 'offset' to unsigned int.
unsigned int read_uint_BE(unsigned char *buf, unsigned int offset, unsigned int byte_length){
    unsigned int ret = 0;
    for (int i = 0; i < byte_length; i ++){
        ret += buf[offset + i] * pow(16, (byte_length -1 -i)*2);
    }
    return ret;
}

void send_session_key_request(struct strbuf * ret, struct received * received, unsigned char * reply_nonce, struct callback_params_server *callback_params){
    struct auth_hello_message_received auth_hello_message_received;
    parse_Auth_Hello(received, &auth_hello_message_received); //st
    //replyNonce ???? 
    generate_nonce(reply_nonce, sizeof(reply_nonce));
    struct strbuf session_key_request_buf;
    generate_reply_message(&auth_hello_message_received, reply_nonce, &session_key_request_buf);
    struct strbuf payload;
    encrypt_and_sign_and_concat(&payload, &session_key_request_buf);
    struct strbuf header;
    make_buffer_header(&header, &payload, SESSION_KEY_REQ_IN_PUB_ENC);
    concat_buffer_header_and_payload(ret, &header, &payload);
}

void parse_session_key_response_with_dist_key(struct session_key_response *session_key_response, struct received * response_received,unsigned char * reply_nonce){
    printf("received session key response with distribution key attached!\n");
    struct signed_data distribution_key_buf;
    struct strbuf session_key_buf;
    parse_data_SESSION_KEY_RESP_WITH_DIST_KEY(response_received, &distribution_key_buf, &session_key_buf, KEY_SIZE);
    verify(&distribution_key_buf);
    printf("auth signature verified\n");
    struct strbuf decrypted;
    decrypted.length = private_decrypt(distribution_key_buf.data.buf,distribution_key_buf.data.length, decrypted.buf);
    printf("\n");
    parse_distribution_key(&session_key_response->parsed_distribution_key, &decrypted);
    struct strbuf dec_buf;
    symmetric_decrypt_authenticate(&dec_buf, &session_key_buf, &session_key_response->parsed_distribution_key);
    parse_session_key_response(session_key_response, &dec_buf);
    printf("reply_nonce in sessionKeyResp: ");
    print_in_hex(session_key_response->reply_nonce.buf);
    if(strncmp(session_key_response->reply_nonce.buf, reply_nonce ,NONCE_SIZE) != 0){ //client??nonce ??
        error_handling("auth nonce NOT verified");
    }
    else{
        printf("auth nonce verified!");
    }
}
// void handle_session_key_resp_client(struct parsed_session_key session_key_list[], struct signed_data receivedDistKey, int callbackParams){ //TODO: callbackParams implement need

// }