#include "auth.h"



void send_session_key_request_check_protocol(helper_options_server *helper_options, callback_params_server *callback_params){
    int option;
    option = 1; //TODO: temp
    // option = get_entity_config(); //TODO: 구현 SecureCommServer.js 128줄
    callback_params->target_session_key_cache_length = (UCHAR) sizeof("none")/sizeof(UCHAR) - 1;
    memcpy(callback_params->target_session_key_cache, "none", callback_params->target_session_key_cache_length);

    if (option == 1){ //TCP
        //TODO: need to read from config?

        send_session_key_req_via_TCP(helper_options, callback_params);
        return;
    }
    if(option == 2){ //UDP
        send_session_key_req_via_UDP();
    }
}

unsigned char * parse_received_message(unsigned char * received_buf, unsigned int received_buf_length, unsigned char * message_type, unsigned int * data_buf_length){
    *message_type = received_buf[0];
    unsigned int payload_buf_length; 
    var_length_int_to_num_t(received_buf + 1, received_buf_length, data_buf_length, &payload_buf_length);
    return received_buf + 1 + payload_buf_length; //msgtype+payload_buf_length;
}

void send_session_key_req_via_TCP(helper_options_server *helper_options, callback_params_server *callback_params){
    
    const char * IP_ADDRESS = "127.0.0.1";
    const char * PORT_NUM = "21900";
    int sock;
    connection(&sock, IP_ADDRESS, PORT_NUM);
    received auth_received;
    UCHAR reply_nonce[NONCE_SIZE]; //Entity's nonce

    while(1){
        //message에 저장
	    auth_received.received_buf_length=read(sock, auth_received.received_buf, sizeof(auth_received.received_buf)-1);
        // check_read_error(auth_received.received_buf_length);
        // unsigned char message_type;
        // unsigned int data_buf_length;
        // unsigned char * data_buf = parse_received_message(auth_received.received_buf, auth_received.received_buf_length, &message_type, &data_buf_length);
        // print_in_hex(data_buf, data_buf_length);
        parse_IoT_SP(&auth_received);
    
        if (auth_received.message_type == AUTH_HELLO){
            UCHAR sendbuffer[1000];
            UINT sendbuffer_length;            
            send_session_key_request(sendbuffer, &sendbuffer_length, &auth_received, reply_nonce, callback_params);
            write(sock, sendbuffer, sendbuffer_length);
            continue;
        }
        else if(auth_received.message_type == SESSION_KEY_RESP_WITH_DIST_KEY){
            session_key_response session_key_response;
            parse_session_key_response_with_dist_key(&session_key_response, &auth_received, reply_nonce);
            //copy session key list to helper_options
            for(int i = 0; i < session_key_response.session_key_list_length; i++){
                memcpy(&helper_options->entity_session_key_list[i], &session_key_response.session_key_list[i], sizeof(parsed_session_key));
            }
            //copt distribution key to helper_options
            memcpy(&helper_options->current_distribution_key, &session_key_response.parsed_distribution_key, sizeof(parsed_distribution_key));
            close(sock);
            break;
        }
        else if(auth_received.message_type == SESSION_KEY_RESP){}
        else if(auth_received.message_type == AUTH_ALERT){}
        else{}
        return;
    }
    

    
} 

void send_session_key_req_via_UDP(){} //TODO:

//TODO: 주의 client 와 다름.
void send_session_key_request(UCHAR * ret, UINT * ret_length, received * received, UCHAR * reply_nonce, callback_params_server *callback_params){
    auth_hello_message_received auth_hello_message_received;
    parse_Auth_Hello(received, &auth_hello_message_received); //st
    //replyNonce 생성 
    generate_nonce(reply_nonce, sizeof(reply_nonce));
    UCHAR session_key_request_buf[1000];
    UINT session_key_request_buf_length;
    //여기다름
    generate_reply_message_server(session_key_request_buf, &session_key_request_buf_length, &auth_hello_message_received, reply_nonce, callback_params);
    UCHAR payload[1000];
    UINT payload_length;
    encrypt_and_sign_and_concat(payload, &payload_length, session_key_request_buf, session_key_request_buf_length);
    make_sender_buf(ret, ret_length, payload, payload_length, SESSION_KEY_REQ_IN_PUB_ENC);
}

// auth_hello_message_received에 auth_ID, auth_NONCE 넣기
void parse_Auth_Hello(received * received, auth_hello_message_received *auth_hello_message_received){
    auth_hello_message_received->auth_Id = read_uint_BE(received->payload, 0, AUTH_ID_SIZE);
    memcpy(auth_hello_message_received->auth_Nonce, received->payload + AUTH_ID_SIZE, NONCE_SIZE );
}

//replyNonce[8byte]+auth_Nonce[8byte]+numkeys[4byte]+senderbuf[size:1 + buf]+purposeBuf[size:1 +buf]
void generate_reply_message_server(UCHAR * session_key_request_buf, UINT * session_key_request_buf_length, auth_hello_message_received *auth_hello_message_received, UCHAR * replyNonce,  callback_params_server *callback_params){
    //numkeys 4byte
    numkeys numkeys = {
        .numkeys = 1, //TODO: 추후 변경
    };
    write_in_4bytes(numkeys.numkeys, numkeys.buf);

    //purposeBuf 생성
    UCHAR purpose_buf[] = "{\"keyId\":00000000}";
    UINT purpose_buf_length = sizeof(purpose_buf) - 1;

    // strbuf purposeBuf = {
    //     _length = (UCHAR) sizeof("{\"keyId\":00000000}")/sizeof(UCHAR) - 1, // \0하나 빼주기
    //      = "{\"keyId\":00000000}" //TODO: 추후 변경
    // };

    UCHAR temp_buf [SESSION_KEY_ID_SIZE];
    sprintf(temp_buf, "%d", callback_params->key_Id);
    memcpy(purpose_buf+ 9,temp_buf, 8);

    //senderBuf 생성
    UCHAR sender_buf[] = "net1.server";
    UINT sender_buf_length = sizeof(sender_buf) - 1;
    // strbuf senderBuf = {
    //     _length = (UCHAR) sizeof("net1.server")/sizeof(UCHAR) - 1, // \0하나 빼주기
    //      = "net1.server" //TODO: 추후 변경
    // };

    UCHAR temp[] = {sender_buf_length};
    UCHAR temp2[] = {purpose_buf_length};

    memcpy(session_key_request_buf, replyNonce, NONCE_SIZE);
    memcpy(session_key_request_buf + NONCE_SIZE, auth_hello_message_received->auth_Nonce, NONCE_SIZE);
    memcpy(session_key_request_buf + NONCE_SIZE*2, numkeys.buf, NUM_KEYS_SIZE);
    memcpy(session_key_request_buf + NONCE_SIZE*2 + NUM_KEYS_SIZE, temp, 1);
    memcpy(session_key_request_buf + NONCE_SIZE*2 + NUM_KEYS_SIZE + 1, sender_buf, sender_buf_length);
    memcpy(session_key_request_buf + NONCE_SIZE*2 + NUM_KEYS_SIZE + 1 + sender_buf_length, temp2, 1);
    memcpy(session_key_request_buf + NONCE_SIZE*2 + NUM_KEYS_SIZE + 1 + sender_buf_length +1, purpose_buf, purpose_buf_length);
    *session_key_request_buf_length = NONCE_SIZE*2 + NUM_KEYS_SIZE + 1 + sender_buf_length +1 + purpose_buf_length;
}

// returns concat of encryption + sign
void encrypt_and_sign_and_concat(UCHAR *ret, UINT * ret_length, UCHAR *message_to_encrypt, UINT message_to_encrypt_length){
    UCHAR encrypted[1000];
    UINT encrypted_length;
    encrypted_length= (UINT) public_encrypt(message_to_encrypt, (int) message_to_encrypt_length, encrypted, RSA_PKCS1_PADDING, "../../entity/auth_certs/Auth101EntityCert.pem");
    UCHAR sigret[512];
    UINT sigret_length;
    sign(sigret, &sigret_length, encrypted,encrypted_length, "../../entity/credentials/keys/net1/Net1.ServerKey.pem");
    *ret_length = encrypted_length + sigret_length;
    memcpy(ret, encrypted, encrypted_length);
    memcpy(ret + encrypted_length, sigret, sigret_length);
}

void parse_session_key_response_with_dist_key(session_key_response *session_key_response, received * response_received, UCHAR * reply_nonce){
    printf("received session key response with distribution key attached!\n");
    signed_data distribution_key_buf;

    UCHAR session_key_buf[256];
    UINT session_key_buf_length;
    parse_data_SESSION_KEY_RESP_WITH_DIST_KEY(response_received, &distribution_key_buf, session_key_buf, &session_key_buf_length, KEY_SIZE);
    verify(&distribution_key_buf, "./../../entity/auth_certs/Auth101EntityCert.pem");
    printf("auth signature verified\n");
    UCHAR decrypted[256];
    UINT decrypted_length;
    decrypted_length = private_decrypt(distribution_key_buf.data, distribution_key_buf.data_length, decrypted, RSA_PKCS1_PADDING, "../../entity/credentials/keys/net1/Net1.ServerKey.pem");
    printf("\n");
    parse_distribution_key(&session_key_response->parsed_distribution_key, decrypted, decrypted_length);
    UCHAR dec_buf[256];
    UINT dec_buf_length;
    symmetric_decrypt_authenticate(dec_buf, &dec_buf_length , session_key_buf, session_key_buf_length, &session_key_response->parsed_distribution_key.keys);
    parse_session_key_response(session_key_response, dec_buf, dec_buf_length);
    printf("reply_nonce in sessionKeyResp: ");
    print_in_hex(session_key_response->reply_nonce, NONCE_SIZE);
    if(strncmp(session_key_response->reply_nonce, reply_nonce ,NONCE_SIZE) != 0){ //client의nonce 비교
        error_handling("auth nonce NOT verified");
    }
    else{
        printf("auth nonce verified!\n");
    }
}

void parse_data_SESSION_KEY_RESP_WITH_DIST_KEY(received *received, signed_data *distribution_key_buf, UCHAR * session_key_buf, UINT * session_key_buf_length,int key_size){
            distribution_key_buf->sign_length= key_size, distribution_key_buf->data_length= key_size, *session_key_buf_length= received->payload_length.num - key_size *2 ;

            // distribution_key_buf.data(key_size) + distribution_key_buf.sign(key_size)+ session_key_buf(length-2*key_size)            
            memcpy(distribution_key_buf->data, received->payload, key_size);
            memcpy(distribution_key_buf->sign, received->payload +key_size, key_size);
            memcpy(session_key_buf, received->payload +key_size*2, *session_key_buf_length);
}

void parse_distribution_key(parsed_distribution_key *parsed_distribution_key, UCHAR *buf, UINT buf_length){
    UINT curIndex = DIST_KEY_EXPIRATION_TIME_SIZE;
    UINT cipherKeySize = buf[curIndex];
    curIndex += 1;
    memcpy(parsed_distribution_key->keys.cipher_key_val, buf + curIndex, cipherKeySize);
    parsed_distribution_key->keys.cipher_key_val_length = cipherKeySize;
    curIndex += cipherKeySize;
    UINT macKeySize = buf[curIndex];
    curIndex += 1;
    memcpy(parsed_distribution_key->keys.mac_key_val, buf +curIndex, macKeySize);
    parsed_distribution_key->keys.mac_key_val_length = macKeySize;
}

void parse_session_key_response(session_key_response *session_key_response, UCHAR *buf, UINT buf_length){
    memcpy(session_key_response->reply_nonce,buf, NONCE_SIZE);
    int buf_idx = NONCE_SIZE;
    UCHAR ret[512];
    UINT ret_length;
    parse_string_param(ret, &ret_length, buf, buf_length, buf_idx );
    //TODO: cryptoSpec 구현 필요. iotAuthService.js 260
    buf_idx += ret_length; //48
    session_key_response->session_key_list_length = read_uint_32BE(&buf[buf_idx]); //TODO: check
    buf_idx += 4;
    for(int i = 0; i < session_key_response->session_key_list_length; i ++){
        UCHAR temp[1024];
        UINT temp_length;
        memcpy(temp, buf+buf_idx, buf_length - buf_idx);
        temp_length = buf_length - buf_idx;
        buf_idx += parse_session_key(&session_key_response->session_key_list[i], temp, temp_length);
    }
}

UINT parse_session_key(parsed_session_key *ret, UCHAR *buf, UINT buf_length){
    ret->key_Id = read_uint_BE(buf, 0, SESSION_KEY_ID_SIZE);
    UINT cur_idx = SESSION_KEY_ID_SIZE;
    //TODO: abs_validity. iotAuthService.js 203
    cur_idx += SESSION_KEY_EXPIRATION_TIME_SIZE;
    ret->rel_validity = read_uint_BE(buf, cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;
    ret->keys.cipher_key_val_length = buf[cur_idx];
    cur_idx += 1;
    memcpy(ret->keys.cipher_key_val,buf+cur_idx, ret->keys.cipher_key_val_length);
    cur_idx += ret->keys.cipher_key_val_length;
    ret->keys.mac_key_val_length = buf[cur_idx];
    cur_idx += 1;
    memcpy(ret->keys.mac_key_val, buf+cur_idx, ret->keys.mac_key_val_length);
    cur_idx += ret->keys.mac_key_val_length;
    return cur_idx; 
}


bool check_session_key(received * received, UINT key_Id){
    bool session_key_found = false;
    // if (){
    //     return true;
    // } //TODO: 구현 필요

    return session_key_found;
}
