#include "c_secure_comm.h"

int sent_seq_num;
unsigned char entity_client_state;
unsigned char entity_server_state;
long int st_time;

unsigned char *auth_hello_reply_message(
    unsigned char *entity_nonce, unsigned char *auth_nonce,
    int num_key, unsigned char *sender, unsigned int sender_length,
    unsigned char *purpose, unsigned int purpose_length,
    unsigned int *ret_length) {
    unsigned char *ret = (unsigned char *)malloc(
        NONCE_SIZE * 2 + NUMKEY_SIZE + sender_length + purpose_length);
    unsigned char num_key_buf[NUMKEY_SIZE];
    memset(num_key_buf, 0, NUMKEY_SIZE);
    write_in_n_bytes(num_key, NUMKEY_SIZE, num_key_buf);
    unsigned char temp[] = {sender_length - 1};
    unsigned char temp2[] = {purpose_length - 1};
    memcpy(ret, entity_nonce, NONCE_SIZE);
    memcpy(ret + NONCE_SIZE, auth_nonce, NONCE_SIZE);
    memcpy(ret + NONCE_SIZE * 2, num_key_buf, NUMKEY_SIZE);
    memcpy(ret + NONCE_SIZE * 2 + NUMKEY_SIZE, temp, 1);
    memcpy(ret + NONCE_SIZE * 2 + NUMKEY_SIZE + 1, sender, sender_length - 1);
    memcpy(ret + NONCE_SIZE * 2 + NUMKEY_SIZE + sender_length, temp2, 1);
    memcpy(ret + NONCE_SIZE * 2 + NUMKEY_SIZE + sender_length + 1, purpose,
           purpose_length - 1);
    *ret_length = NONCE_SIZE * 2 + NUMKEY_SIZE + sender_length + purpose_length;

    return ret;
}

unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len,
                                const char *path_pub, const char *path_priv,
                                unsigned int *message_length) {
    size_t encrypted_length;
    unsigned char *encrypted = public_encrypt(buf, buf_len, RSA_PKCS1_PADDING,
                                              path_pub, &encrypted_length);
    size_t sigret_length;
    unsigned char *sigret =
        SHA256_sign(encrypted, encrypted_length, path_priv, &sigret_length);
    *message_length = sigret_length + encrypted_length;
    unsigned char *message = (unsigned char *)malloc(*message_length);
    memcpy(message, encrypted, encrypted_length);
    memcpy(message + encrypted_length, sigret, sigret_length);
    free(encrypted);
    free(sigret);
    return message;
}

void parse_distribution_key(distribution_key_t *parsed_distribution_key,
                            unsigned char *buf, unsigned int buf_length) {
    unsigned int cur_index = DIST_KEY_EXPIRATION_TIME_SIZE;
    unsigned int cipher_key_size = buf[cur_index];
    parsed_distribution_key->cipher_key_size = cipher_key_size;
    parsed_distribution_key->cipher_key =
        (unsigned char *)malloc(cipher_key_size);
    cur_index += 1;
    memcpy(parsed_distribution_key->cipher_key, buf + cur_index,
           cipher_key_size);
    cur_index += cipher_key_size;
    unsigned int mac_key_size = buf[cur_index];
    parsed_distribution_key->mac_key_size = mac_key_size;
    parsed_distribution_key->mac_key = (unsigned char *)malloc(mac_key_size);
    cur_index += 1;
    memcpy(parsed_distribution_key->mac_key, buf + cur_index, mac_key_size);
}

unsigned char *parse_string_param(unsigned char *buf, unsigned int buf_length,
                                  int offset, unsigned int *return_to_length) {
    unsigned int num;
    unsigned int payload_buf_length;
    var_length_int_to_num(buf + offset, buf_length, &num, &payload_buf_length);
    if (payload_buf_length == 0) {
        *return_to_length = 1;
        unsigned char *return_to = (unsigned char *)malloc(*return_to_length);
        memset(return_to, 0, *return_to_length);
        return return_to;
    }
    *return_to_length = num + payload_buf_length;
    unsigned char *return_to = (unsigned char *)malloc(*return_to_length);
    memcpy(return_to, buf + offset + payload_buf_length, num);
    return return_to;
}

unsigned int parse_session_key(session_key_t *ret, unsigned char *buf,
                               unsigned int buf_length) {
    memcpy(ret->key_id, buf, SESSION_KEY_ID_SIZE);
    unsigned int cur_idx = SESSION_KEY_ID_SIZE;
    // TODO: abs_validity. iotAuthService.js 203
    memcpy(ret->abs_validity, buf + cur_idx, ABS_VALIDITY_SIZE);
    cur_idx += ABS_VALIDITY_SIZE;
    memcpy(ret->rel_validity, buf + cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;

    // copy cipher_key
    ret->cipher_key_size = buf[cur_idx];
    ret->cipher_key = (unsigned char *)malloc(ret->cipher_key_size);
    cur_idx += 1;
    memcpy(ret->cipher_key, buf + cur_idx, ret->cipher_key_size);
    cur_idx += ret->cipher_key_size;

    // copy mac_key
    ret->mac_key_size = buf[cur_idx];
    ret->mac_key = (unsigned char *)malloc(ret->mac_key_size);
    cur_idx += 1;
    memcpy(ret->mac_key, buf + cur_idx, ret->mac_key_size);
    cur_idx += ret->mac_key_size;

    return cur_idx;
}

void parse_session_key_response(unsigned char *buf, unsigned int buf_length,
                                unsigned char *reply_nonce,
                                session_key_t *session_key_list) {
    memcpy(reply_nonce, buf, NONCE_SIZE);
    unsigned int buf_idx = NONCE_SIZE;
    unsigned int ret_length;
    unsigned char *ret =
        parse_string_param(buf, buf_length, buf_idx, &ret_length);
    // TODO: need to apply cryptoSpec?
    //~~use ret~~
    free(ret);
    buf_idx += ret_length;  // 48
    unsigned int session_key_list_length =
        read_unsigned_int_BE(&buf[buf_idx], 4);
    buf_idx += 4;
    for (int i = 0; i < session_key_list_length; i++) {
        buf = buf + buf_idx;
        buf_idx = parse_session_key(&session_key_list[i], buf, buf_length);
    }
}

unsigned char *parse_handshake_1(session_key_t *s_key,
                                 unsigned char *entity_nonce,
                                 unsigned int *ret_length) {
    // keyId8 + iv16 +data32 + hmac32

    RAND_bytes(entity_nonce, HS_NONCE_SIZE);
    unsigned char indicator_entity_nonce[1 + HS_NONCE_SIZE];
    memcpy(indicator_entity_nonce + 1, entity_nonce, HS_NONCE_SIZE);
    indicator_entity_nonce[0] = 1;

    unsigned int encrypted_length;
    unsigned char *encrypted = symmetric_encrypt_authenticate(
        indicator_entity_nonce, 1 + HS_NONCE_SIZE, s_key->mac_key, MAC_KEY_SIZE,
        s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
        &encrypted_length);

    *ret_length = encrypted_length + KEY_ID_SIZE;
    unsigned char *ret = (unsigned char *)malloc(*ret_length);
    memcpy(ret, s_key->key_id, KEY_ID_SIZE);
    memcpy(ret + KEY_ID_SIZE, encrypted, encrypted_length);
    free(encrypted);
    return ret;
};

unsigned char *check_handshake_2_send_handshake_3(unsigned char *data_buf,
                                                  unsigned int data_buf_length,
                                                  unsigned char *entity_nonce,
                                                  session_key_t *s_key,
                                                  unsigned int *ret_length) {
    printf("received session key handshake2!\n");
    unsigned int decrypted_length;
    unsigned char *decrypted = symmetric_decrypt_authenticate(
        data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE,
        s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
        &decrypted_length);
    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);

    // compare my_nonce and received_nonce
    if (strncmp((const char *)hs.reply_nonce, (const char *)entity_nonce,
                HS_NONCE_SIZE) != 0) {
        error_handling(
            "Comm init failed: server NOT verified, nonce NOT matched, "
            "disconnecting...\n");
    } else {
        printf("server authenticated/authorized by solving nonce!\n");
    }

    // send handshake_3
    unsigned int buf_length = HS_INDICATOR_SIZE;
    unsigned char buf[HS_INDICATOR_SIZE];
    memset(buf, 0, HS_INDICATOR_SIZE);
    serialize_handshake(entity_nonce, hs.nonce, buf);

    unsigned char *ret = symmetric_encrypt_authenticate(
        buf, HS_INDICATOR_SIZE, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key,
        CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, ret_length);
    return ret;
}

void print_recevied_message(unsigned char *data, unsigned int data_length,
                            session_key_t *s_key) {
    unsigned int decrypted_length;
    unsigned char *decrypted = symmetric_decrypt_authenticate(
        data, data_length, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key,
        CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
    unsigned int received_seq_num =
        read_unsigned_int_BE(decrypted, SEQ_NUM_SIZE);
    if (!check_validity(received_seq_num, s_key->rel_validity,
                        s_key->abs_validity, &st_time)) {
        error_handling("Session key expired!\n");
    }

    printf("Received seq_num: %d\n", received_seq_num);
    printf("%s\n", decrypted + SEQ_NUM_SIZE);
}

int check_validity(int seq_n, unsigned char *rel_validity,
                   unsigned char *abs_validity, long int *st_time) {
    if (seq_n == 0 && *st_time == 0) {
        *st_time = time(NULL);
    }
    unsigned long int num_valid = 1LU;
    for (int i = 0; i < SESSION_KEY_EXPIRATION_TIME_SIZE; i++) {
        unsigned long int num =
            1LU << 8 * (SESSION_KEY_EXPIRATION_TIME_SIZE - 1 - i);
        num_valid |= num * abs_validity[i];
    }
    // printf("abs_valid : %ld\n", num_valid);
    num_valid = num_valid / 1000;
    long int relvalidity =
        read_unsigned_int_BE(rel_validity, SESSION_KEY_EXPIRATION_TIME_SIZE) /
        1000;
    if (time(NULL) > num_valid || time(NULL) - *st_time > relvalidity) {
        return 0;
    } else {
        return 1;
    }
}

session_key_t *send_session_key_request_check_protocol(
    config_t *config, unsigned char *target_key_id) {
    // TODO: check if needed
    // Temporary code. need to load?
    unsigned char target_session_key_cache[10];
    unsigned int target_session_key_cache_length;
    target_session_key_cache_length =
        (unsigned char)sizeof("none") / sizeof(unsigned char) - 1;
    memcpy(target_session_key_cache, "none", target_session_key_cache_length);

    if (strncmp((const char *)config->network_protocol, "TCP", 3) ==
        0) {  // TCP
        session_key_t *s_key = send_session_key_req_via_TCP(config);
        printf("received %d keys\n", config->numkey);

        // SecureCommServer.js handleSessionKeyResp
        //  if(){} //TODO: migration
        //  if(){} //TODO: check received_dist_key null;
        //  if(strncmp(callback_params.target_session_key_cache, "Clients",
        //  callback_params.target_session_key_cache_length) == 0){} //TODO:
        //  check.
        if (strncmp((const char *)target_session_key_cache, "none",
                    target_session_key_cache_length) == 0) {
            // check received (keyId from auth == keyId from entity_client)
            if (strncmp((const char *)s_key->key_id,
                        (const char *)target_key_id,
                        SESSION_KEY_ID_SIZE) != 0) {
                error_handling("Session key id is NOT as expected\n");
                // SecureCommServer.js sendHandshake2Callback
            } else {
                printf("Session key id is as expected\n");
            }
            return s_key;
        }
    }
    if (strncmp((const char *)config->network_protocol, "UDP", 3) ==
        0) {  
        // TODO(Dongha Kim): Implement session key request via UDP.
        session_key_t *s_key = send_session_key_req_via_UDP();
        return s_key;
    }
    return 0;
}

session_key_list_t *send_session_key_req_via_TCP(config_t *config_info) { //TODO: , distribution_key_t *existing_dist_key, distribution_key_t *new_dist_key
    int sock;
    connect_as_client((const char *)config_info->auth_ip_addr,
                      (const char *)config_info->auth_port_num, &sock);

    // will be input from config.
    unsigned char *path_pub =
        malloc(strlen((const char *)config_info->auth_pubkey_path));
    unsigned char *path_priv =
        malloc(strlen((const char *)config_info->entity_privkey_path));
    memset(path_pub, 0, strlen((const char *)config_info->auth_pubkey_path));
    memcpy(path_pub, config_info->auth_pubkey_path,
           strlen((const char *)config_info->auth_pubkey_path) - 1);

    memset(path_priv, 0,
           strlen((const char *)config_info->entity_privkey_path));
    memcpy(path_priv, config_info->entity_privkey_path,
           strlen((const char *)config_info->entity_privkey_path) - 1);

    int num_key = config_info->numkey;
    session_key_list_t *session_key_list;
    session_key_list->num_key = 3;
    session_key_list->s_key = malloc(sizeof(session_key_t) * num_key);
    // session_key_t *session_key_list = malloc(sizeof(session_key_t) * num_key);
    unsigned char entity_nonce[NONCE_SIZE];
    while (1) {
        unsigned char received_buf[1000];
        unsigned int received_buf_length =
            read(sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == AUTH_HELLO) {
            unsigned int auth_Id;
            unsigned char auth_nonce[NONCE_SIZE];
            auth_Id = read_unsigned_int_BE(data_buf, AUTH_ID_LEN);
            memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE);
            RAND_bytes(entity_nonce, NONCE_SIZE);
            unsigned int serialized_length;
            unsigned char *serialized = auth_hello_reply_message(
                entity_nonce, auth_nonce, num_key, config_info->name,
                strlen((const char *)config_info->name), config_info->purpose,
                strlen((const char *)config_info->purpose), &serialized_length);

            // TODO: when distribution key exists.
            unsigned int enc_length;
            unsigned char *enc = encrypt_and_sign(
                serialized, serialized_length, (const char *)path_pub,
                (const char *)path_priv, &enc_length);
            free(serialized);

            unsigned char message[1024];
            unsigned int message_length;
            make_sender_buf(enc, enc_length, SESSION_KEY_REQ_IN_PUB_ENC,
                            message, &message_length);
            write(sock, message, message_length);
            free(enc);
        } else if (message_type == SESSION_KEY_RESP_WITH_DIST_KEY) {
            signed_data_t signed_data;
            distribution_key_t dist_key;
            size_t key_size = RSA_KEY_SIZE;

            // parse data
            unsigned int encrypted_session_key_length =
                data_buf_length - (key_size * 2);
            unsigned char *encrypted_session_key =
                (unsigned char *)malloc(encrypted_session_key_length);
            memcpy(signed_data.data, data_buf, key_size);
            memcpy(signed_data.sign, data_buf + key_size, key_size);
            memcpy(encrypted_session_key, data_buf + key_size * 2,
                   encrypted_session_key_length);

            // verify
            SHA256_verify(signed_data.data, key_size, signed_data.sign,
                          key_size, (const char *)path_pub);
            printf("auth signature verified\n");

            // decrypt encrypted_distribution_key
            size_t decrypted_distribution_key_length;
            unsigned char *decrypted_distribution_key = private_decrypt(
                signed_data.data, key_size, RSA_PKCS1_PADDING,
                (const char *)path_priv, &decrypted_distribution_key_length);

            // parse decrypted_distribution_key to mac_key & cipher_key
            parse_distribution_key(&dist_key, decrypted_distribution_key,
                                   decrypted_distribution_key_length);
            free(decrypted_distribution_key);

            // decrypt session_key with decrypted_distribution_key
            unsigned int decrypted_session_key_response_length;
            unsigned char *decrypted_session_key_response =
                symmetric_decrypt_authenticate(
                    encrypted_session_key, encrypted_session_key_length,
                    dist_key.mac_key, dist_key.mac_key_size,
                    dist_key.cipher_key, dist_key.cipher_key_size, IV_SIZE,
                    &decrypted_session_key_response_length);
            free(encrypted_session_key);

            // parse decrypted_session_key_response for nonce comparison &
            // session_key.
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(decrypted_session_key_response,
                                       decrypted_session_key_response_length,
                                       reply_nonce, session_key_list->s_key);

            printf("reply_nonce in sessionKeyResp: ");
            print_buf(reply_nonce, NONCE_SIZE);
            if (strncmp((const char *)reply_nonce, (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                error_handling("auth nonce NOT verified");
            } else {
                printf("auth nonce verified!\n");
            }
            close(sock);
            free(path_pub);
            free(path_priv);
            return session_key_list;
        }
    }
}

session_key_list_t *send_session_key_req_via_UDP() {
    session_key_list_t *s_key;
    return s_key;
    // TODO(Dongha Kim): Implemen this function.
    error_handling("This function is not implemented yet.");
}

unsigned char *check_handshake1_send_handshake2(
    unsigned char *received_buf, unsigned int received_buf_length,
    unsigned char *server_nonce, session_key_t *s_key,
    unsigned int *ret_length) {
    unsigned int decrypted_length;
    unsigned char *decrypted = symmetric_decrypt_authenticate(
        received_buf + SESSION_KEY_ID_SIZE,
        received_buf_length - SESSION_KEY_ID_SIZE, s_key->mac_key, MAC_KEY_SIZE,
        s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
        &decrypted_length);

    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);

    printf("client's nonce: ");  // client's nonce,, received nonce
    print_buf(hs.reply_nonce, HS_NONCE_SIZE);

    RAND_bytes(server_nonce, HS_NONCE_SIZE);
    printf("server's nonce: ");
    print_buf(server_nonce, HS_NONCE_SIZE);

    // send handshake 2
    unsigned int buf_length = HS_INDICATOR_SIZE;
    unsigned char buf[HS_INDICATOR_SIZE];
    memset(buf, 0, HS_INDICATOR_SIZE);
    serialize_handshake(server_nonce, hs.nonce, buf);

    unsigned char *ret = symmetric_encrypt_authenticate(
        buf, HS_INDICATOR_SIZE, s_key->mac_key, MAC_KEY_SIZE, s_key->cipher_key,
        CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, ret_length);
    return ret;
}
