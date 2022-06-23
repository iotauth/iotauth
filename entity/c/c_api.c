#include "c_api.h"

void load_config()
{

}


//client�� �̿���.
//config�� �ʿ��Ѱ�: IP_ADDRESS PORT_NUM sender purpose num_key


/*replyNonce[8byte]+auth_Nonce[8byte]+numkeys[4byte]+senderbuf[size:1 + buf]+purposeBuf[size:1 +buf]
//usage:    unsigned int ret_length;
            unsigned char * serialized = auth_hello_reply_message();
*/
unsigned char * auth_hello_reply_message(unsigned char * entity_nonce, unsigned char * auth_nonce, unsigned char num_key, unsigned char * sender, unsigned int sender_length, unsigned char* purpose, unsigned int purpose_length, unsigned int * ret_length)
{
    unsigned char * ret = (unsigned char *)malloc(NONCE_SIZE*2 + NUMKEY_SIZE + sender_length + purpose_length);
    unsigned char * num_key_buf[NUMKEY_SIZE];
    write_in_n_bytes((int)num_key, NUMKEY_SIZE, num_key_buf);
    unsigned char temp[] = {sender_length};
    unsigned char temp2[] = {purpose_length};
    memcpy(ret, entity_nonce, NONCE_SIZE);
    memcpy(ret + NONCE_SIZE, auth_nonce, NONCE_SIZE);
    memcpy(ret + NONCE_SIZE*2, num_key_buf, NUMKEY_SIZE);
    memcpy(ret + NONCE_SIZE*2 + NUMKEY_SIZE, temp, 1);
    memcpy(ret + NONCE_SIZE*2 + NUMKEY_SIZE + 1, sender, sender_length-1);
    memcpy(ret + NONCE_SIZE*2 + NUMKEY_SIZE + sender_length, temp2, 1);
    memcpy(ret + NONCE_SIZE*2 + NUMKEY_SIZE + sender_length + 1, purpose, purpose_length-1);
    *ret_length = NONCE_SIZE*2 + NUMKEY_SIZE + sender_length + purpose_length;

    return ret;
}

unsigned char * encrypt_and_sign(unsigned char * buf, unsigned int buf_len, char * path_pub, char * path_priv, unsigned int * message_length)
{
    unsigned char encrypted[2048]; // embedded system에서는 문제가 될 수 있음 
    int encrypted_length= public_encrypt(buf, buf_len, 1, path_pub, encrypted);

    unsigned char sigret [1024];
    unsigned int  sigret_length;

    SHA256_sign(encrypted, encrypted_length, path_priv, sigret, sigret_length);
    *message_length = sigret_length + encrypted_length;
    memcpy(encrypted+encrypted_length,sigret,sigret_length);

    return encrypted;
}

void get_session_key()
{
    int sock;
    const char * IP_ADDRESS = "127.0.0.1";
    const char * PORT_NUM = "21900";
    connect_as_client(IP_ADDRESS, PORT_NUM, sock);
    while(1)
    {
        unsigned char received_buf[1000];
        unsigned int received_buf_length = read(socket, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char * data_buf = parse_received_message(received_buf, received_buf_length, &message_type, &data_buf_length);
        if(message_type == AUTH_HELLO)
        {

            unsigned char sender[] = "net1.client";
            unsigned char purpose[] = "{\"group\":\"Servers\"}";
            unsigned char num_key = 3;

            unsigned int auth_Id;
            unsigned char auth_nonce[NONCE_SIZE];
            auth_Id = read_unsigned_int_BE(data_buf,  AUTH_ID_LEN);
            memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE );
            unsigned char entity_nonce[NONCE_SIZE];
            RAND_bytes(entity_nonce, NONCE_SIZE);
            unsigned int ret_length;
            unsigned char * serialized = auth_hello_reply_message(entity_nonce, auth_nonce, num_key, sender, sizeof(sender), purpose, sizeof(purpose), &ret_length);
            
            const char * path_pub = "../auth_certs/Auth101EntityCert.pem";
            const char * path_priv = "../credentials/keys/net1/Net1.ClientKey.pem";
            unsigned int enc_length;
            unsigned char * enc = encrypt_and_sign(serialized, ret_length, path_pub, path_priv, &message_length);
            free(serialized);

            unsigned char message;
            unsigned int message_length;
            
            make_sender_buf(enc, enc_length, SESSION_KEY_REQ_IN_PUB_ENC, message, &message_length);
            write(sock, message, message_length);
        }
        else if(message_type == SESSION_KEY_RESP_WITH_DIST_KEY)
        {

        }

    }








}

void secure_connection(){}

void send_secure_message(){}

void wait_connection_message(){}

