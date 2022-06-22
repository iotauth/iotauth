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

#define type(x) _Generic((x),                                                     \
        _Bool: "_Bool",                  unsigned char: "unsigned char",          \
         char: "char",                     signed char: "signed char",            \
    short int: "short int",         unsigned short int: "unsigned short int",     \
          int: "int",                     unsigned int: "unsigned int",           \
     long int: "long int",           unsigned long int: "unsigned long int",      \
long long int: "long long int", unsigned long long int: "unsigned long long int", \
        float: "float",                         double: "double",                 \
  long double: "long double",                   char *: "char *",                 \
       void *: "void *",                         int *: "int *",                  \
      default: "unknown")

#define AUTH_ID_LEN 4
#define NUMKEY 4
#define NONCE_SIZE 8
#define SESSION_KEY_REQ_IN_PUB_ENC 20
#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define SESSION_KEY_EXPIRATION_TIME_SIZE 6
#define SKEY_HANDSHAKE_1 30   
#define SKEY_HANDSHAKE_2 31
#define SKEY_HANDSHAKE_3 32
#define SECURE_COMM_MSG 33
#define BUF_LEN 128
int padding = RSA_PKCS1_PADDING;

pthread_t thread[10];

struct topic
{
    char  group[10];
    char  pubTopic[10];
    char  subTopic[10];
};

struct sessionKeyReq
{
    unsigned char Entity_nonce[NONCE_SIZE] ;
    unsigned char Auth_nonce[NONCE_SIZE] ;
    unsigned char NumKeys[4] ;
    char Sender [20] ;
    char Sender_len [1] ;
    char Purpose [20] ;
    char Purpose_len [1] ;
};
typedef struct
{
    unsigned char receive_message[100];
    unsigned char send_message[100];
    int sock;
    unsigned char mac_key[32];
    unsigned char cipher_key[16];
}message_arg;

typedef struct
{
  unsigned char receive_message[200];
  unsigned char send_message[200];
  unsigned int receive_seq_num;
  unsigned int send_seq_num;
}save_message;

typedef struct
{
long int st_time;

}start_time;


struct sessionkey_info
{
    unsigned char key_id[8];
    unsigned char abs_validity[6];
    unsigned char rel_validity[6];
    unsigned char mac_key[32];
    unsigned char cipher_key[16];
    unsigned char nonce[8];
}; 

struct received_nonce{
    unsigned char client_nonce[NONCE_SIZE];
    unsigned char server_nonce[NONCE_SIZE];
    unsigned char dhParam[NONCE_SIZE];
};

save_message save_msg[100];
struct sessionkey_info sessionkeyinfo[10];
struct topic Topic;  // Topic declaration;
struct sessionKeyReq SessionKeyReq; // SessionkeyReq declaration;
start_time validity_time;
unsigned char message[15];
unsigned char auth_id[AUTH_ID_LEN];
char sender_req[] = "net1.client";
char purpose_req[] = "{\"group\":\"Servers\"}";

void nonce_generator(unsigned char * nonce_buf, int size_n) ;
void symmetricdecryptAuthenticate(struct sessionkey_info S[], unsigned char *in_buf, int p, unsigned char *out_buf, int q);


void slice(unsigned char * des_buf, unsigned char * buf, int a, int b )
{
    for(int i=0;i<b-a;i++)
    {
        des_buf[i] = buf[a+i];
    }
}

int read_variable_UInt(unsigned char * read_buf,int offset, int byteLength)
{
    int num =0;
    unsigned long int sum =1LU;
    for(int i =0; i<byteLength;i++)
    {
        num |= read_buf[offset+i]<< 8*(byteLength-1-i);
    }
    return num; 
}
int payload_buf_length(int b)
{   
    int n = 1;
    while(b > 127)
    {
        n += 1;
        b >>=7;
    }
    return n;
}

int payload_length(unsigned char * message, int b)
{
    int num = 0;
    for (int i =0; i<b&& i<5; i++)
    {
        num |= (message[1+i]& 127) <<(7 * i);
        if((message[1+i]&128) == 0 )
        {
            i+= 1;
            printf("payload_length = %d, payload_buf = %d \n", num,i);
            break;
        }
    }
    return num;
}

void make_time(unsigned char * time_buf, int index, int byte_length)
{
    unsigned long int num_valid =1LU;
    for(int i =0; i<byte_length;i++)
        {
        unsigned long int num =1LU << 8*(byte_length-1-i); 
        num_valid |= num*time_buf[index+i];
    }
    printf("abs_valid : %ld\n", num_valid);
    num_valid = num_valid/1000; 

    struct tm *it; 
    it =localtime(&num_valid); 

    printf("%04d-%02d-%02d %02d:%02d:%02d\n",it->tm_year +1900 , it->tm_mon + 1, it->tm_mday , it->tm_hour, it->tm_min, it->tm_sec
    );
}

void print_buf(unsigned char * print_buffer, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", print_buffer[i]);
    printf("\n");
}

int print_seq_num(unsigned char *buf)
{
    int seq=0;
    for(int i =0 ; i<sizeof(buf);i++)
    {
        seq |= buf[i] <<(8 * (sizeof(buf)-i-1));
    }
    printf("Sequence number : %d\n",seq);
    return seq;
}
void *receive_message(void *multiple_arg)  /* read thread */
{
    message_arg *my_multiple_arg = (message_arg *)multiple_arg;
    unsigned char buf_msg[BUF_LEN];
    int n= 0;
    int my_sock = my_multiple_arg->sock;
    // mackey , cipher key decryption
    while(1)
    {
        if(n == 0 && validity_time.st_time == 0)
        {       
            validity_time.st_time = time(NULL);
        }

        // memset(my_multiple_arg->receive_message, 0, sizeof(my_multiple_arg->receive_message));
        memset(buf_msg, 0, sizeof(buf_msg));
        int str_len = read(my_sock, buf_msg, BUF_LEN);

        printf("seq num: %d\n",n);
        unsigned long int num_valid =1LU;
        for(int i =0; i<SESSION_KEY_EXPIRATION_TIME_SIZE;i++)
        {
            unsigned long int num =1LU << 8*(SESSION_KEY_EXPIRATION_TIME_SIZE-1-i); 
            num_valid |= num*sessionkeyinfo[0].abs_validity[i];
        }
        printf("abs_valid : %ld\n", num_valid);
        num_valid = num_valid/1000;
        long int relvalidity = read_variable_UInt(sessionkeyinfo[0].rel_validity, 0, 6)/1000;
        
        if(time(NULL) > num_valid || time(NULL) - validity_time.st_time >relvalidity)
        {
            printf("session key is expired");
            break;
        }
        else
        {
        printf("msg length: %d \n", str_len);
        printf("msg : ");
        print_buf(buf_msg,str_len);
        unsigned char dec[100];
        symmetricdecryptAuthenticate(sessionkeyinfo,buf_msg,str_len,dec,sizeof(dec));
        
        memset(save_msg[n].receive_message,0,sizeof(save_msg[n].receive_message));
        int seq_num = print_seq_num(dec);
        
        save_msg[n].receive_seq_num = seq_num ; 
        
        slice(save_msg[n].receive_message,dec,8,sizeof(save_msg[n].receive_message));
        print_buf(save_msg[n].receive_message,10);
        printf("message : %s\n", save_msg[n].receive_message);
        // if(n == 0 && ) // time number? if abs time is empty, start!
        // {

        // }
        n +=1;
        }
    }
}
void *thread_main(void * my_fd)  /* read thread */
{
    char buf[BUF_LEN];
    while(1)
    {
        memset(buf, 0, sizeof(buf));
        read(*(int *)my_fd, buf, BUF_LEN);
        print_buf(buf,32);
    }
}



void print_Last_error(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}
void sender()
{
    strcpy(SessionKeyReq.Sender,sender_req);
    memset(SessionKeyReq.Sender_len, strlen(SessionKeyReq.Sender),1);
}

void purpose()
{
    strcpy(SessionKeyReq.Purpose , purpose_req);
    memset(SessionKeyReq.Purpose_len,strlen(SessionKeyReq.Purpose),1);
}

void numkey()
{
    memset(SessionKeyReq.NumKeys,0,sizeof(SessionKeyReq.NumKeys));
    SessionKeyReq.NumKeys[3] = 3;
}

void AuthID()
{ 
    for(int i =0 ; i<AUTH_ID_LEN; i++)
    {
        auth_id[i] = message[i+2]; 
    }
}
void AuthNonce()
{
    for(int j = 0; j<sizeof(message)-(AUTH_ID_LEN+2)-1;j++)
    {
        SessionKeyReq.Auth_nonce[j] = message[AUTH_ID_LEN+2+j];
    }
}
void nonce_generator(unsigned char * nonce_buf, int size_n)  // nonce generator;
{
    int x = RAND_bytes(nonce_buf,size_n);
    if(x == -1)
    {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}    

unsigned char buf [NONCE_SIZE*2 + NUMKEY + 1 + 12 + 1 + 20]; //buf[20+]
// unsigned char buf [8196]; //buf[20+]

void serializeSessionkeyReq() 
{
    // unsigned char buf [NONCE_SIZE*2 + NUMKEY + 10 + 20]; //buf[20+]
    if(SessionKeyReq.Entity_nonce == NULL || SessionKeyReq.Auth_nonce == NULL || 
    SessionKeyReq.Sender == NULL || SessionKeyReq.Purpose == NULL ||  SessionKeyReq.NumKeys == NULL)
    {
        printf("Error: SessionKeyReq nonce or replyNonce or purpose or numKeys is missing.");                       
    }

    else
    {                                                      
        memcpy(buf,SessionKeyReq.Entity_nonce, NONCE_SIZE); //Entity_nonce
        memcpy(buf+NONCE_SIZE,SessionKeyReq.Auth_nonce,NONCE_SIZE); //Auth_nonce
        memcpy(buf+NONCE_SIZE*2,SessionKeyReq.NumKeys,NUMKEY); 
        memcpy(buf+NONCE_SIZE*2+NUMKEY,SessionKeyReq.Sender_len,1); 
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1,SessionKeyReq.Sender,strlen(SessionKeyReq.Sender)); 
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+strlen(SessionKeyReq.Sender),SessionKeyReq.Purpose_len,1); 
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+strlen(SessionKeyReq.Sender)+1,SessionKeyReq.Purpose,strlen(SessionKeyReq.Purpose)); 
        
    printf("-- Serialize -- \n");
    print_buf(buf,sizeof(buf));
    }
}


void parseHandshake(unsigned char * buff, struct received_nonce A[]) {

    if ((buff[0] & 1) != 0) {
        // nonce exists
        slice(A[0].server_nonce,buff,1, 1 + NONCE_SIZE);
    }
    if ((buff[0] & 2) != 0) {
        // replayNonce exists
        slice(A[0].client_nonce,buff,1+NONCE_SIZE,1+NONCE_SIZE*2);
    }
    if ((buff[0] & 4) != 0) {
        slice(A[0].dhParam,buff,1+NONCE_SIZE*2,1+NONCE_SIZE*3);
    }
    
};

void symmetricEncryptAuthenticate(struct sessionkey_info S[], unsigned char * p, unsigned char * z, int b, int a) // a?? key id?? ?????? or ???? ??????!!
{
        int iv_size =16;
        unsigned char iv[iv_size];
        // printf("iv: \n");
        RAND_bytes(iv,iv_size);
        // nonce_generator(iv, iv_size);
        // print_buf(iv,iv_size);

        unsigned char enc_mac[48]; 
        AES_KEY enc_key_128;
        unsigned char enc[32];
        memcpy(enc_mac,iv,iv_size);
        if(AES_set_encrypt_key(S[0].cipher_key, 16*8, &enc_key_128) < 0)
        {
            printf("error!!!");
        }; 
        AES_cbc_encrypt( z, enc,b, &enc_key_128, iv, 1); // why IV is changed?
        // printf("enc data: \n");
        // print_buf(enc, sizeof(enc));
        // iv 16 + enc 32

        // print_buf(iv,iv_size);
        // memcpy(enc_mac,iv,iv_size);
        memcpy(enc_mac+iv_size,enc,sizeof(enc));
        // printf("enc mac data: \n");
        // print_buf(enc_mac, sizeof(enc));

        // Hmac
        unsigned char hmac[32];
        unsigned int hmac_size = 32;
        HMAC(EVP_sha256(),S[0].mac_key , sizeof(S[0].mac_key),
         enc_mac, sizeof(enc_mac), hmac, &hmac_size);
        // printf("hmac : \n");
        // print_buf(hmac,sizeof(hmac));
        // enc + tag
        if(a ==1){ // handshake1 need a key id 
            memcpy(p,S[0].key_id,sizeof(S[0].key_id)); //8
            memcpy(p+sizeof(S[0].key_id),enc_mac,sizeof(enc_mac)); //48
            memcpy(p+sizeof(S[0].key_id)+sizeof(enc_mac), hmac, sizeof(hmac)); //32
            // printf(" : \n");

            // print_buf(p,88);
        }
        else{ // handshake3 don't need key id
            memcpy(p,enc_mac,sizeof(enc_mac)); //48
            memcpy(p+sizeof(enc_mac), hmac, sizeof(hmac)); //32
            // printf(" : \n");

            // print_buf(p,80);          
        }
}

void symmetricdecryptAuthenticate(struct sessionkey_info S[], unsigned char *in_buf, int p, unsigned char *out_buf, int q)
{
        int payload_buf_num, buf_num; 
        payload_buf_num = payload_length(in_buf,p);
        buf_num = payload_buf_length(payload_buf_num);
        int mac_size = 32;
        unsigned char received_tag[mac_size];
        unsigned char enc[payload_buf_num-mac_size];
        unsigned char  result[32];
        unsigned int result_len = 32;
        printf("payload buf num : %d \n",payload_buf_num );

        slice(enc,in_buf,buf_num+1,buf_num+1+payload_buf_num-mac_size);
        slice(received_tag,in_buf,buf_num+1+payload_buf_num-mac_size, payload_buf_num+buf_num+1);
        print_buf(enc,sizeof(enc));
        print_buf(received_tag,sizeof(received_tag));
        HMAC(EVP_sha256(),S[0].mac_key , 32, enc, sizeof(enc), result, &result_len);
        
        if(strncmp((char *)result, (char *) received_tag, sizeof(result)) == 0 )
        {
            printf("Hmac success!!! \n");
        }    
        int iv_size =16;
        AES_KEY enc_key_128;
        unsigned char iv[iv_size]; //16
        unsigned char enc_symmetric_cipher[sizeof(enc)-iv_size];
        
        memset(out_buf,0,q);
        slice(iv,enc,0,iv_size);
        slice(enc_symmetric_cipher,enc,iv_size,sizeof(enc));
        if(AES_set_decrypt_key(S[0].cipher_key, sizeof(S[0].cipher_key)*8, &enc_key_128) < 0){
            printf("error");
        }; 
        AES_cbc_encrypt(enc_symmetric_cipher, out_buf,sizeof(enc_symmetric_cipher), &enc_key_128, iv, 0);
        printf("decrypted value: \n");
        print_buf(out_buf,32);
}
// void TcpCommunication(int argc, char* argv[]) // TCP Connection(client)
// {
//     int my_sock;
//     struct sockaddr_in serv_addr;
//     int str_len;
//     if(argc != 3)
//     {
//         printf("%s <IP> <PORT>\n", argv[0]);
//         exit(1);
//     }
//     my_sock = socket(PF_INET,SOCK_STREAM,0); //1??
//     if(my_sock == -1)
//         printf("socket error \n");
//     memset(&serv_addr,0,sizeof(serv_addr));
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
//     serv_addr.sin_port=htons(atoi(argv[2]));

//     if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2??
//         printf("connect error\n");
//     memset(message,0x00,sizeof(message));
//     str_len = read(my_sock,message,sizeof(message)-1); //3??
//     if(str_len==-1)
//         printf("read error\n");
//     if(message[0] == 0)
//         printf("Received AUTH_HELLO Message!!! \n");
//         printf("Receiving message from Auth : ");
//     for(int i=0; i<str_len ; i++)
//     {
//         printf("%x ",message[i]);
//     }
//     close(my_sock); //4
// }

RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1); //
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public) // 
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else // 
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted) 
{
    FILE *pemFile = fopen("../SST-/sst/iotauth/entity/auth_certs/Auth101EntityCert.pem", "rb");
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
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted, char *key)
{

    FILE *keyfile = fopen("../SST-/sst/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}


void make_degest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);     
}


int main(int argc, char* argv[])
{

        int my_sock;
        struct sockaddr_in serv_addr;
        int str_len;
        if(argc != 3)
        {
            printf("%s <IP> <PORT>\n", argv[0]);
            exit(1);
        }
        my_sock = socket(PF_INET,SOCK_STREAM,0); 
        if(my_sock == -1)
            printf("socket error \n");
        memset(&serv_addr,0,sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
        serv_addr.sin_port=htons(atoi(argv[2]));

        if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2??
            printf("connect error\n");
        memset(message,0x00,sizeof(message));
        str_len = read(my_sock,message,sizeof(message)-1); // message
        if(str_len==-1)
            printf("read error\n");
        if(message[0] == 0)
        {
            printf("Received AUTH_HELLO Message!!! \n");
            printf("Receiving message from Auth : ");
            print_buf(message, str_len);

            AuthID();
            AuthNonce();
            numkey();
            sender();
            printf("-- Entity Nonce --\n");
            nonce_generator(SessionKeyReq.Entity_nonce, NONCE_SIZE);
            purpose();

            //Auth_Hello 
            serializeSessionkeyReq();
            
            unsigned char encrypted[2048] = {};
            unsigned char decrypted[2048] = {};
            unsigned char sigret [1000] = {};
            unsigned int  sigret_Length ;
            unsigned char dig_enc[SHA256_DIGEST_LENGTH];
            // Based on this comment you can encrypt at most 214 bytes using 256 byte RSA key.
            
            // Encryption
            int encrypted_length= public_encrypt(buf,sizeof(buf),encrypted);
            printf("encrypted length: %d\n", encrypted_length);
            printf(" -- encrypted value -- \n");
            print_buf(encrypted, encrypted_length);
            
            // Decryption?? ???? Encryption?? ?????? ???!!
            // int decrypted_length = private_decrypt(encrypted,encrypted_length,decrypted,privatekey);
            // printf("decrypted length: %d\n", decrypted_length);
            // printf(" -- decrypted value -- \n");
            // print_buf(decrypted, decrypted_length); 

            //////////////////sign part////////////////////////
            // make digest message

            make_degest_msg(dig_enc, encrypted, encrypted_length);

            FILE *keyfile = fopen("../SST-/sst/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
            RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);

            //// sign!
            int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
                sigret, &sigret_Length, rsa);
            if(sign_result ==1)
            {
                printf("Sign length: %d\n", sigret_Length);
                printf("Sign success \n");
            }

            //// verify!   
            int verify_result = RSA_verify(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
                sigret, sigret_Length, rsa);
            if(verify_result ==1)
                printf("verify success\n");

            /// enc+sign length ????? buffer?? ????
            unsigned char extra_buf[5];
            unsigned int num = encrypted_length + sigret_Length;
            int n = 1;
            while(num > 127)
            {
                extra_buf[n-1] = 128 | num & 127;
                n += 1;
                num >>=7;
            }
            extra_buf[n-1] = num;


            // Total message buffer ??????? msg_type???? ???!
            // msg type(1) + data length512(2) + data(512){encrypt 256+ sign 256} 
            unsigned char buffer [1 + n + encrypted_length + sigret_Length ];
            buffer[0] = SESSION_KEY_REQ_IN_PUB_ENC;
            memcpy(buffer+1, extra_buf, n);
            memcpy(buffer+1+n,encrypted, encrypted_length);
            memcpy(buffer + 1 + n + encrypted_length,sigret, sigret_Length);

            printf("sizeof buffer: %ld = msg type(1) + data length buf(2) + data(encrypt 256 + sign 256) \n", sizeof(buffer));
        
            write(my_sock, buffer,sizeof(buffer));
    
        }
        ///// Auth???? ?? message?? ????!!
        unsigned char message[2000];
        
        memset(message,0x00,sizeof(message));
        str_len = read(my_sock,message,sizeof(message)-1); //3
        if(str_len==-1)
            printf("read error\n");
        //////// msg type 21!
        if(message[0] == 21)
        {   
            printf("\nreceived session key response with distribution key attached! \n");
            printf("Receiving message length from Auth : %d \n", str_len);
            int num =0;
            int message_length;
            printf("\n");

            for (int i =0; i<sizeof(message)&& i<5; i++)
            {
                num |= (message[1+i]& 127) <<(7 * i);
                if((message[1+i]&128) == 0 )
                {
                    i+= 1;
                    message_length = i;
                    printf("num = %d, payload_len = %d \n", num,i);
                    break;
                }
            }
            
            unsigned char payload[num];
            for(int i = 0; i<num; i++)
            {
                payload[i] = message[i+1+message_length];
            }
            
            // slice(payload,message, 1+message_length, )
            //distributionkeybuf 512??
            unsigned char distribution_key[512];
            memcpy(distribution_key, payload,sizeof(distribution_key));
            //sessionkeyBuf 320??
            int session_key_len = num-sizeof(distribution_key); 
            unsigned char session_key[session_key_len];

            // ?? ????? sessionkeyreq???? key?? ?????????? ??? ex) 1?? -176, 3?? - 320
            printf("sessionkey_buf ???? : %ld\n", sizeof(session_key)); 
            slice(session_key, payload,sizeof(distribution_key),num);
            
            // distribution - ret_data, ret_signiture;
            unsigned char ret_data[256];
            unsigned char ret_signiture[256];
            memcpy(ret_data,distribution_key,256);
            slice(ret_signiture,distribution_key, 256, sizeof(distribution_key) );
            ////// Message digest
            unsigned char dig_enc[SHA256_DIGEST_LENGTH];
            make_degest_msg(dig_enc , ret_data,sizeof(ret_data) );
            ////// Verify
            FILE *pemFile = fopen("../SST-/sst/iotauth/entity/auth_certs/Auth101EntityCert.pem", "rb");
            X509 *cert = PEM_read_X509( pemFile, NULL, NULL, NULL );
            EVP_PKEY *pkey = X509_get_pubkey(cert);
            if (pkey == NULL){
                print_Last_error("public key getting fail");
            }
            int id = EVP_PKEY_id(pkey);
            if ( id != EVP_PKEY_RSA ) {
                print_Last_error("is not RSA Encryption file");
            }
            RSA *rsa1 = EVP_PKEY_get1_RSA(pkey);
            if ( rsa1 == NULL ) {
                print_Last_error("EVP_PKEY_get1_RSA fail");
            } 

            int verify_result = RSA_verify(NID_sha256, dig_enc ,sizeof(dig_enc),
              ret_signiture, sizeof(ret_signiture), rsa1);
            if(verify_result ==1)
                printf("auth signature verified \n\n");


            FILE *keyfile = fopen("../SST-/sst/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
            RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);

            unsigned char dec_buf[100];
            
            int  dec_length = RSA_private_decrypt(sizeof(ret_data),ret_data,dec_buf,rsa,padding);
            // int dec_length = RSA_private_decrypt(ret_data,sizeof(ret_data),dec_buf,signkey);
            printf("decrypted length: %d\n", dec_length);
            printf(" -- decrypted value -- \n");
            print_buf(dec_buf, dec_length);
            // parseDistributionKey !!
            // absValidity, cipher_key_value, mac_key_value for Received Distribution key!
            int cipher_key_size,mac_key_size, cur_index;
            unsigned char absValidity[DIST_KEY_EXPIRATION_TIME_SIZE];
            cur_index = DIST_KEY_EXPIRATION_TIME_SIZE; // 6!!

            memcpy(absValidity, dec_buf,cur_index);
            
            // unsigned to int         
            cipher_key_size =(int)dec_buf[cur_index]; //

            printf("size of cipher_key: %d\n", cipher_key_size);  //   16????
            unsigned char cipher_key_value[cipher_key_size];
            cur_index +=1;
            slice(cipher_key_value,dec_buf,cur_index,cipher_key_size+cur_index);
            cur_index += cipher_key_size;
            mac_key_size =(int)dec_buf[cur_index];
            printf("size of mac_key : %d\n", mac_key_size); //  32????
            unsigned char mac_key_value[mac_key_size];
            cur_index +=1;
            slice(mac_key_value,dec_buf,cur_index,cur_index+mac_key_size);
            print_buf(mac_key_value,mac_key_size);

            // session_key, absValidity, cipher_key_value, mac_key_value;

            //symmetricDecryptAuthenticate 
            int mac_size = 32; // sha256?? ??, 32 , SHA1 ?? ??, 20
            unsigned char symmetric_data[session_key_len -mac_size];
            unsigned char received_tag[mac_size];
            printf("size of symm_data: %ld , size of receiv_tag: %ld \n", sizeof(symmetric_data),sizeof(received_tag));
            slice(symmetric_data,session_key,0,session_key_len - mac_size);
            slice(received_tag,session_key,session_key_len - mac_size,session_key_len);

            // Hmac authentication method.
            
            //mac_key_value
            unsigned char  result[32];
            unsigned int result_len = 32;
            unsigned char hmac[32];
            HMAC(EVP_sha256(),mac_key_value , sizeof(mac_key_value), symmetric_data, sizeof(symmetric_data), result, &result_len);

            printf("size of result : %ld\n", sizeof(result));
            printf("size of received tag : %ld\n", sizeof(received_tag));
            
            slice(hmac,result,0,sizeof(hmac));
            if(strncmp((char *)hmac, (char *) received_tag, sizeof(hmac)) == 0 )
            {
                printf("Hmac success!!! \n");
            }
            //////////// session key 320 ????? mac size 32, 
            ////////////  IV(Initialize Vector)?? 16, ?????? encryption data 272

            // CBC mode (IV size 16, encryption data 272)
            int iv_size =16;
            AES_KEY enc_key_128;
            unsigned char iv[iv_size]; //16
            unsigned char enc_symmetric_cipher[sizeof(symmetric_data)-iv_size];
            printf("size of encrypted message : %ld\n", sizeof(enc_symmetric_cipher));

            unsigned char dec[1000];
            slice(iv,symmetric_data,0,iv_size);
            slice(enc_symmetric_cipher,symmetric_data,iv_size,sizeof(symmetric_data));

            if(AES_set_decrypt_key(cipher_key_value, sizeof(cipher_key_value)*8, &enc_key_128) < 0){
            printf("AES Decrypt Error!");  
            }; 
            AES_cbc_encrypt( enc_symmetric_cipher, dec,sizeof(enc_symmetric_cipher), &enc_key_128, iv, 0);
            

            //parseSessionKeyResp(buf) == dec_data

            unsigned char dec_data[256];
            slice(dec_data, dec, 0, sizeof(dec_data));
            ///Entitynonce!!!!
            unsigned char resp_reply_nonce[NONCE_SIZE];
            slice(resp_reply_nonce, dec_data,0,NONCE_SIZE);
            int resp_num =0;
            int resp_message_length;
            printf("\n");
            printf("-- Decrypted data -- \n");
            print_buf(dec_data,sizeof(dec_data));
            for (int i =0; i<sizeof(dec_data)&& i<5; i++)
            {
                resp_num |= (dec_data[NONCE_SIZE +i]& 127) <<(7 * i);
                if((dec_data[NONCE_SIZE+i]&128) == 0 )
                {
                    i+= 1;
                    resp_message_length = i;
                    printf("num = %d, payload_len = %d \n", resp_num,resp_message_length);
                    break;
                }
            }
            //dec_data?? entity_nonce 8?? , ?? ?? ???? 39???? ??????? ???? 1??, crypto spec 39?? 0 0 0 3 => 3??
            //NONCE_SIZE + resp_message_length(9)???? NONCE_SIZE + resp_message_length+strLen ????

            // cryptoSpec ??????? ?¥ê?!!!!
            int strLen = resp_num; // 39
            unsigned char resp_str[strLen];
            printf("crypto spec : ");
            for (int i; i<strLen;i++)
            {
                printf("%c", (dec_data[9+i]));
                resp_str[i] = dec_data[9+i];
            }
            printf("\n");

            int resp_session_length = 0;
            for(int i=0; i<4; i++)
            {
                resp_session_length |= dec[NONCE_SIZE + resp_message_length+ strLen+i] <<8*(3-i);
            }
            printf("key length: %d\n\n" ,resp_session_length); // 3??
            // parseSessionkey(buf) ???? parse_sessionkey ?? buf?? ???
            unsigned char parse_sessionkey[sizeof(dec_data) - 52]; // 256 - 52
            slice(parse_sessionkey,dec_data, 52, sizeof(dec_data));
            // int cur_index_par =0;
            int offset = 8;
            int relval_length =6;
            int cur_index_par =0;
            /// 70???? 3??!
            struct sessionkey_info session_key_info;

            for(int i = 0; i<resp_session_length;i++)
            {
                printf("%d ¹øÂ°! \n", i+1);
                printf("key id size: %d\n", offset);
                slice(session_key_info.key_id,parse_sessionkey,cur_index_par,cur_index_par+offset);
                long int key_id = read_variable_UInt(parse_sessionkey,cur_index_par , offset);
                printf("key id : %ld\n", key_id);
                cur_index_par += offset;

                printf("time size: %d \n", SESSION_KEY_EXPIRATION_TIME_SIZE);
                make_time(parse_sessionkey, cur_index_par,SESSION_KEY_EXPIRATION_TIME_SIZE);
                slice(session_key_info.abs_validity,parse_sessionkey,cur_index_par,cur_index_par+SESSION_KEY_EXPIRATION_TIME_SIZE);
                cur_index_par += SESSION_KEY_EXPIRATION_TIME_SIZE;

                long int relvalidity = read_variable_UInt(parse_sessionkey, cur_index_par, relval_length);
                slice(session_key_info.rel_validity,parse_sessionkey,cur_index_par,cur_index_par+relval_length);
                printf("Relvalidity size: %d \n", relval_length);
                printf("Relvalidity : %ld \n", relvalidity);
                cur_index_par += relval_length; // 8 + 6 + 6;
                int cipher_keysize = parse_sessionkey[cur_index_par];
                printf("cipher_keysize : %d \n", cipher_keysize);
                cur_index_par += 1; // 8 + 6 + 6 + 1;
                
                unsigned char cipher_key_value_par[cipher_keysize];
                slice(cipher_key_value_par, parse_sessionkey, cur_index_par, cur_index_par+ cipher_keysize);
                memcpy(session_key_info.cipher_key,cipher_key_value_par,cipher_keysize);

                cur_index_par += cipher_keysize;
                int mac_keysize = parse_sessionkey[cur_index_par];
                printf("mac_keysize : %d\n", mac_keysize );
                cur_index_par += 1;
                unsigned char mac_key_value_par[mac_keysize];
                slice(mac_key_value_par,parse_sessionkey, cur_index_par, cur_index_par+mac_keysize);
                memcpy(session_key_info.mac_key,mac_key_value_par,mac_keysize);
                cur_index_par += mac_keysize;
                printf("cur_index_par : %d \n", cur_index_par);
                printf("\n");

                sessionkeyinfo[i] = session_key_info;

            }
            
            //resp_reply_nonce?? SessionKeyReq.Entity_nonce?? ?????????
            // resp_reply_nonce SessionKeyReq.Entity_nonce
            printf("-- replyNonce in sessionKeyResp -- \n");
            print_buf(resp_reply_nonce,NONCE_SIZE);
            if(strncmp((char *)resp_reply_nonce, (char *) SessionKeyReq.Entity_nonce, NONCE_SIZE) == 0 )
            {
                printf("Nonce is consistent. \n");
            }
            else
                printf("auth nonce NOT verified\n");
            
            printf("auth nonce verified\n\n");


            printf("updating distribution key: \n");

            // absValidity, cipher_key_value, mac_key_value for Received Distribution key!
            printf("cipher_key_value ");
            print_buf(cipher_key_value, sizeof(cipher_key_value));
            printf("mac_key_value ");
            print_buf(mac_key_value, sizeof(mac_key_value));
            print_buf(absValidity, SESSION_KEY_EXPIRATION_TIME_SIZE);
            make_time(absValidity,0,SESSION_KEY_EXPIRATION_TIME_SIZE);
            printf("\nDistribution update success!!\n\n");

            printf("received %d keys! \n", resp_session_length);
        }


//////////////////////////////////handshake!!!!!!////////////////////////////////
        if(argc != 3)
        {
            printf("%s <IP> <PORT>\n", argv[0]);
            exit(1);
        }
        my_sock = socket(PF_INET,SOCK_STREAM,0); //1??
        if(my_sock == -1)
            printf("socket error \n");
        
        serv_addr.sin_port=htons(atoi("21100")); //21100

        if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2??
            printf("connect error\n");
        
        printf("key id: \n");
        print_buf(sessionkeyinfo[0].key_id,8);
        printf("cipher key: \n");
        print_buf(sessionkeyinfo[0].cipher_key,16);
        printf("mac key: \n");
        print_buf(sessionkeyinfo[0].mac_key,32);

        unsigned char hand_buf[88];

        printf("-- Client nonce --\n");
        nonce_generator(sessionkeyinfo[0].nonce, NONCE_SIZE);

        unsigned char hand_buf_data[1+ NONCE_SIZE*2];
        memset(hand_buf_data,0,1+ NONCE_SIZE*2);
        print_buf(hand_buf_data,17);
        hand_buf_data[0] = 1;
        memcpy(hand_buf_data+1,sessionkeyinfo[0].nonce, 8);
        printf("serialize handshake : \n");
        print_buf(hand_buf_data,17);

        symmetricEncryptAuthenticate(sessionkeyinfo,hand_buf,hand_buf_data,17,1);
        // printf(hand_buf,10);
        printf("key id: \n");
        print_buf(sessionkeyinfo[0].key_id,8);
        printf("hand buf: \n");
        print_buf(hand_buf,72);

        unsigned char extra_buf[5];
        unsigned int num = sizeof(hand_buf);
        int n = 1;
        while(num > 127)
        {
            extra_buf[n-1] = 128 | num & 127;
            n += 1;
            num >>=7;
        }
        extra_buf[n-1] = num;
        printf("num ? extra buf %d %d\n",n ,num);

        unsigned char handshake_buf[1+sizeof(hand_buf)+n];
        handshake_buf[0] = SKEY_HANDSHAKE_1;
        memcpy(handshake_buf+1,extra_buf,n);            
        memcpy(handshake_buf+1+n,hand_buf,sizeof(hand_buf));
        print_buf(handshake_buf,sizeof(handshake_buf));
        write(my_sock, handshake_buf,sizeof(handshake_buf));

        printf("switching to HANDSHAKE_1_SENT\n");
        


        //// handshake 2!!!!!!!!!!!!!!!!!!
        memset(message,0x00,sizeof(message));
        str_len = read(my_sock,message,sizeof(message)-1); 

        printf("Received handshake2 !! \n");
        print_buf(message,str_len);
        printf("Message size : %d\n", str_len);

        printf("Message type: %d\n", message[0]);
        unsigned char dec[100];

        symmetricdecryptAuthenticate(sessionkeyinfo,message,str_len,dec,sizeof(dec));

        struct received_nonce nonce[2];

        
        parseHandshake(dec,nonce);
        printf("Client Nonce: \n");
        print_buf(nonce[0].client_nonce,NONCE_SIZE);
        printf("Server Nonce: \n");
        print_buf(nonce->server_nonce,NONCE_SIZE);
        if(strncmp((char *)nonce[0].client_nonce, (char *) sessionkeyinfo[0].nonce, NONCE_SIZE) == 0 )
        {
            printf("Nonce?? ?????????. \n");
        }
        else
            printf("auth nonce NOT verified\n");
        printf("-- Server nonce --\n");
        unsigned char hand_buf2_data[1+ NONCE_SIZE*2];
        memset(hand_buf2_data,0,1+ NONCE_SIZE*2);
        print_buf(hand_buf2_data,17);
        hand_buf2_data[0] = 2;
        memcpy(hand_buf2_data+1+NONCE_SIZE,nonce[0].server_nonce, 8);
        printf("serialize handshake : \n");
        print_buf(hand_buf2_data,17);

        unsigned char hand_buf2[80];

        symmetricEncryptAuthenticate(sessionkeyinfo,hand_buf2, hand_buf2_data, 17, 0);


        unsigned char extra_buf2[5];
        unsigned int num2 = sizeof(hand_buf2);
        int n2 = 1;
        while(num2 > 127)
        {
            extra_buf2[n2-1] = 128 | num2 & 127;
            n2 += 1;
            num2 >>=7;
        }
        extra_buf2[n-1] = num2;
        printf("num ? extra buf %d %d\n",n2 ,num2);

        unsigned char handshake_buf2[1+sizeof(hand_buf2)+n2];
        handshake_buf2[0] = SKEY_HANDSHAKE_3;
        memcpy(handshake_buf2+1,extra_buf2,n2);            
        memcpy(handshake_buf2+1+n2,hand_buf2,sizeof(hand_buf2));
        print_buf(handshake_buf2,sizeof(handshake_buf2));
        write(my_sock, handshake_buf2,sizeof(handshake_buf2));


////////////////// Secure communication ///////////////////
        printf("--Secure Communication-- \n");

        unsigned int seq_num = 0;
        validity_time.st_time = 0;

        message_arg *multiple_arg;
        multiple_arg = (message_arg *)malloc(sizeof(message_arg));

        multiple_arg->sock = my_sock;
        memcpy(multiple_arg->cipher_key,sessionkeyinfo[0].cipher_key,16);
        memcpy(multiple_arg->mac_key,sessionkeyinfo[0].mac_key,32);
        
        pthread_create(thread, NULL, &receive_message, (void *)multiple_arg);
        while(1)
        {
            unsigned char command[10];
            scanf("%s", command);



            if(strncmp((char *) command, (char *) "send", 4) == 0)
            {
                if(seq_num == 0 && validity_time.st_time == 0)
                {       
                    validity_time.st_time = time(NULL);
                }

                unsigned long int num_valid =1LU;
                for(int i =0; i<SESSION_KEY_EXPIRATION_TIME_SIZE;i++)
                {
                    unsigned long int num =1LU << 8*(SESSION_KEY_EXPIRATION_TIME_SIZE-1-i); 
                    num_valid |= num*sessionkeyinfo[0].abs_validity[i];
                }
                // printf("abs_valid : %ld\n", num_valid);
                num_valid = num_valid/1000;
                long int relvalidity = read_variable_UInt(sessionkeyinfo[0].rel_validity, 0, 6)/1000;
                
                if(time(NULL) > num_valid || time(NULL) - validity_time.st_time >relvalidity)
                {
                    printf("session key is expired");
                    break;
                }
                else
                {
                unsigned char message[32]; 
                memset(message,0,32);
                scanf("%s", message);


                unsigned char msg_buf[80];
                unsigned char msg_data[32];
                int msg_data_len = sizeof(msg_data);    
                
                memset(msg_data,0,msg_data_len);
                msg_data[7] += seq_num;
                
                memcpy(msg_data+8,message,strlen(message));

                symmetricEncryptAuthenticate(sessionkeyinfo,msg_buf,msg_data,msg_data_len,0);
                
                unsigned char extra_buf3[5];
                unsigned int num3 = sizeof(msg_buf);
                int n3 = 1;
                while(num3 > 127)
                {   
                    extra_buf3[n3-1] = 128 | num3 & 127;
                    n3 += 1;
                    num3 >>=7;
                }
                extra_buf2[n3-1] = num3;
                // printf("num , extra buf %d %d\n",n3 ,num3);

                unsigned char message_buf[1+sizeof(msg_buf)+n3];
                message_buf[0] = SECURE_COMM_MSG;
                memcpy(message_buf+1,extra_buf2,n3);            
                memcpy(message_buf+1+n3,msg_buf,sizeof(msg_buf));
                write(my_sock, message_buf,sizeof(message_buf));

                memcpy(save_msg[seq_num].receive_message,message,sizeof(message));
                // print_buf(save_msg[seq_num].receive_message, sizeof(message));
                printf("send the message: %s\n",message );
                save_msg[n].send_seq_num = seq_num;
                printf("seq_num : %d \n", seq_num);
                seq_num += 1;
                
                }
            }
                else if(strncmp((char *) command, (char *) "finComm", 7) == 0 )
            {
                free(multiple_arg);
                printf("Exit !!\n");
                break;
            }
            
        }
}