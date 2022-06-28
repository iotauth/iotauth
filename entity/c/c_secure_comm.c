#include "c_secure_comm.h"

int received_seq_num;
int sent_seq_num;

/*
function:   prints the seq_num & message.
            This decrypts the received 'payload', with the 'session_key', and calculates the seq_num.
input: seq_num(the seq_num must be saved), payload(data to decrypt), session_key
*/

unsigned char * auth_hello_reply_message(unsigned char * entity_nonce, unsigned char * auth_nonce, unsigned char num_key, unsigned char * sender, unsigned int sender_length, unsigned char* purpose, unsigned int purpose_length, unsigned int * ret_length)
{
    unsigned char * ret = (unsigned char *)malloc(NONCE_SIZE*2 + NUMKEY_SIZE + sender_length + purpose_length);
    // unsigned char ret[100];
    unsigned char num_key_buf[NUMKEY_SIZE];
    memset(num_key_buf, 0, NUMKEY_SIZE);
    write_in_n_bytes((int)num_key, NUMKEY_SIZE, num_key_buf);
    unsigned char temp[] = {sender_length-1};
    unsigned char temp2[] = {purpose_length-1};
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

void * encrypt_and_sign(unsigned char * buf, unsigned int buf_len, const char * path_pub, const char * path_priv, unsigned char * message, unsigned int * message_length)
{
    unsigned char encrypted[256]; 
    int encrypted_length= public_encrypt(buf, buf_len, RSA_PKCS1_PADDING, path_pub, message); //TODO: need padding as input?

    unsigned char sigret [256];
    unsigned int  sigret_length;

    SHA256_sign(message, encrypted_length, path_priv, sigret, &sigret_length);
    *message_length = sigret_length + encrypted_length;
    memcpy(message+encrypted_length,sigret,sigret_length);
}


//must free distribution_key.mac_key, distribution_key.cipher_key
void parse_distribution_key(distribution_key * parsed_distribution_key, unsigned char * buf, unsigned int buf_length)
{
    unsigned int cur_index = DIST_KEY_EXPIRATION_TIME_SIZE;
    unsigned int cipher_key_size = buf[cur_index];
    parsed_distribution_key->cipher_key_size = cipher_key_size;
    parsed_distribution_key->cipher_key = (unsigned char *)malloc(cipher_key_size);
    cur_index += 1;
    memcpy(parsed_distribution_key->cipher_key, buf + cur_index, cipher_key_size);
    cur_index += cipher_key_size;
    unsigned int mac_key_size = buf[cur_index];
    parsed_distribution_key->mac_key_size = mac_key_size;
    parsed_distribution_key->mac_key = (unsigned char *)malloc(mac_key_size);
    cur_index += 1;
    memcpy(parsed_distribution_key->mac_key, buf +cur_index, mac_key_size);
}

// must free ()
unsigned char * parse_string_param(unsigned char * buf, unsigned int buf_length, int offset, unsigned int * return_to_length)
{
    unsigned int num; 
    unsigned int payload_buf_length; 
    var_length_int_to_num(buf + offset, buf_length, &num, &payload_buf_length);
    if(payload_buf_length == 0){
        *return_to_length = 1;
        unsigned char * return_to = (unsigned char *)malloc(*return_to_length);
        memset(return_to, 0, *return_to_length);
        return return_to;
    }
    *return_to_length = num + payload_buf_length;
    unsigned char * return_to = (unsigned char *)malloc(*return_to_length);
    memcpy(return_to, buf + offset + payload_buf_length, num);
    return return_to;
}
//must free when session_key expired or usage finished.
unsigned int parse_session_key(session_key * ret, unsigned char *buf, unsigned int buf_length)
{
    memcpy(ret->key_id, buf, SESSION_KEY_ID_SIZE);
    unsigned int cur_idx = SESSION_KEY_ID_SIZE;
    //TODO: abs_validity. iotAuthService.js 203
    cur_idx += KEY_EXPIRATION_TIME_SIZE;
    memcpy(ret->rel_validity, buf+cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;

    //copy cipher_key
    ret->cipher_key_size = buf[cur_idx];
    ret->cipher_key = (unsigned char *)malloc(ret->cipher_key_size);
    cur_idx += 1;
    memcpy(ret->cipher_key, buf+cur_idx, ret->cipher_key_size);
    cur_idx += ret->cipher_key_size;

    //copy mac_key
    ret->mac_key_size = buf[cur_idx];
    ret->mac_key = (unsigned char *)malloc(ret->mac_key_size);
    cur_idx += 1;
    memcpy(ret->mac_key, buf+cur_idx, ret->mac_key_size);
    cur_idx += ret->mac_key_size;

    return cur_idx; 
}

void parse_session_key_response(unsigned char *buf, unsigned int buf_length, unsigned char * reply_nonce, session_key * session_key_list)
{
    memcpy(reply_nonce, buf, NONCE_SIZE);
    unsigned int buf_idx = NONCE_SIZE;
    unsigned int ret_length;
    unsigned char * ret = parse_string_param(buf, buf_length, buf_idx, &ret_length);
    //TODO: cryptoSpec ���� �ʿ�. iotAuthService.js 260
    //~~use ret~~
    free(ret);
    buf_idx += ret_length; //48
    unsigned int session_key_list_length = read_unsigned_int_BE(&buf[buf_idx], 4); //TODO: may need a struct session_key_list including list_length;
    buf_idx += 4;
    for(int i = 0; i < session_key_list_length; i ++){
        buf = buf + buf_idx;
        buf_idx = parse_session_key(&session_key_list[i], buf, buf_length);
        // unsigned char temp[1024];
        // unsigned int temp_length;
        // memcpy(temp, buf+buf_idx, buf_length - buf_idx);
        // temp_length = buf_length - buf_idx;
        // buf_idx += parse_session_key(&session_key_response->session_key_list[i], temp, temp_length);
    }
}

unsigned char * parse_handshake_1(session_key * s_key, unsigned char * entity_nonce, unsigned int * ret_length)
{
    //keyId8 + iv16 +data32 + hmac32

    RAND_bytes(entity_nonce, HS_NONCE_SIZE);
    unsigned char indicator_entity_nonce[1+HS_NONCE_SIZE];
    memcpy(indicator_entity_nonce+1, entity_nonce, HS_NONCE_SIZE);
    indicator_entity_nonce[0] = 1;

    unsigned int encrypted_length;
    unsigned char * encrypted = symmetric_encrypt_authenticate(indicator_entity_nonce, 1 + HS_NONCE_SIZE, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &encrypted_length);
    
    *ret_length = encrypted_length + KEY_ID_SIZE;
    unsigned char * ret = (unsigned char *)malloc(*ret_length);
    memcpy(ret, s_key->key_id, KEY_ID_SIZE);
    memcpy(ret + KEY_ID_SIZE, encrypted, encrypted_length);
    free(encrypted);
    return ret;
};

unsigned char * check_handshake_2_send_handshake_3(unsigned char * data_buf, unsigned int data_buf_length, unsigned char * entity_nonce, session_key * s_key, unsigned int *ret_length)
{
    printf("received session key handshake2!\n");
    unsigned int decrypted_length;
    unsigned char * decrypted = symmetric_decrypt_authenticate(data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
    HS_nonce hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);

    //compare my_nonce and received_nonce
    if(strncmp(hs.reply_nonce, entity_nonce ,HS_NONCE_SIZE) != 0){
        error_handling("Comm init failed: server NOT verified, nonce NOT matched, disconnecting...\n");
    }
    else{
        printf("server authenticated/authorized by solving nonce!\n");
    }

    //send handshake_3
    unsigned int buf_length = HS_INDICATOR_SIZE;
    unsigned char buf[HS_INDICATOR_SIZE];
    memset(buf, 0, HS_INDICATOR_SIZE);
    serialize_handshake(entity_nonce, hs.nonce, buf);

    unsigned char * ret = symmetric_encrypt_authenticate(buf, HS_INDICATOR_SIZE, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, ret_length);
    unsigned int test_length;
    unsigned char * test = symmetric_decrypt_authenticate(ret, *ret_length, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &test_length);
    
    return ret;
}

//TODO: debugging �ʿ��Ҽ��� ����.
void receive_message(unsigned char * data, unsigned int data_length, session_key * s_key)
{
    //TODO: check validity
    // ���������� ���� ������ָ� ������? �Լ��� �ϳ� ����?

    unsigned int decrypted_length;
    unsigned char * decrypted = symmetric_decrypt_authenticate(data, data_length, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
    received_seq_num = read_unsigned_int_BE(decrypted, SEQ_NUM_SIZE);
    printf("Received seq_num: %d\n", received_seq_num);
    printf("%s\n", decrypted+SEQ_NUM_SIZE);
}



//TODO: ���������� �ϸ� ������.

int check_validity(long int st_time, int seq_n, unsigned char *rel_validity, unsigned char *abs_validity )
{
    if( seq_n == 0 && st_time == 0)
    {       
        st_time = time(NULL);
    }
    unsigned long int num_valid =1LU;
    for(int i =0; i<SESSION_KEY_EXPIRATION_TIME_SIZE;i++)
    {
        unsigned long int num =1LU << 8*(SESSION_KEY_EXPIRATION_TIME_SIZE-1-i); 
        num_valid |= num*abs_validity[i];
    }
    printf("abs_valid : %ld\n", num_valid);
    num_valid = num_valid/1000;
    long int relvalidity = read_unsigned_int_BE(rel_validity,SESSION_KEY_EXPIRATION_TIME_SIZE)/1000;
    if(time(NULL) > num_valid || time(NULL) - st_time >relvalidity)
    {
        printf("session key is expired");
        return 0;
    }
    else
    {
        return 1;
    }
}
