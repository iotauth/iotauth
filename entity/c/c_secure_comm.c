#include "c_secure_comm.h"

unsigned char entity_client_state;
unsigned char entity_server_state;
long int st_time;

unsigned char *auth_hello_reply_message(unsigned char *entity_nonce,
                                        unsigned char *auth_nonce, int num_key,
                                        char *sender, char *purpose,
                                        unsigned int *ret_length) {
    size_t sender_length = strlen(sender);
    size_t purpose_length = strlen(purpose);

    unsigned char *ret = (unsigned char *)malloc(
        NONCE_SIZE * 2 + NUMKEY_SIZE + sender_length + purpose_length +
        8 /* +8 for two var length ints */);
    unsigned char num_key_buf[NUMKEY_SIZE];
    memset(num_key_buf, 0, NUMKEY_SIZE);
    write_in_n_bytes(num_key, NUMKEY_SIZE, num_key_buf);

    size_t offset = 0;
    memcpy(ret + offset, entity_nonce, NONCE_SIZE);
    offset += NONCE_SIZE;

    memcpy(ret + offset, auth_nonce, NONCE_SIZE);
    offset += NONCE_SIZE;

    memcpy(ret + offset, num_key_buf, NUMKEY_SIZE);
    offset += NUMKEY_SIZE;

    unsigned char var_length_int_buf[4];
    unsigned int var_length_int_len;

    num_to_var_length_int(sender_length, var_length_int_buf,
                          &var_length_int_len);
    memcpy(ret + offset, var_length_int_buf, var_length_int_len);
    offset += var_length_int_len;

    memcpy(ret + offset, sender, sender_length);
    offset += sender_length;

    num_to_var_length_int(purpose_length, var_length_int_buf,
                          &var_length_int_len);
    memcpy(ret + offset, var_length_int_buf, var_length_int_len);
    offset += var_length_int_len;

    memcpy(ret + offset, purpose, purpose_length);
    offset += purpose_length;

    *ret_length = offset;

    return ret;
}

unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len,
                                SST_ctx_t *ctx, unsigned int *message_length) {
    size_t encrypted_length;
    unsigned char *encrypted = public_encrypt(buf, buf_len, RSA_PKCS1_PADDING,
                                              ctx->pub_key, &encrypted_length);
    size_t sigret_length;
    unsigned char *sigret =
        SHA256_sign(encrypted, encrypted_length, ctx->priv_key, &sigret_length);
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
    memcpy(parsed_distribution_key->abs_validity, buf,
           DIST_KEY_EXPIRATION_TIME_SIZE);
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
                                session_key_list_t *session_key_list) {
    memcpy(reply_nonce, buf, NONCE_SIZE);
    unsigned int buf_idx = NONCE_SIZE;
    unsigned int ret_length;
    unsigned char *ret =
        parse_string_param(buf, buf_length, buf_idx, &ret_length);
    // TODO: need to apply cryptoSpec?
    //~~use ret~~
    free(ret);
    buf_idx += ret_length;
    unsigned int session_key_list_length =
        read_unsigned_int_BE(&buf[buf_idx], 4);

    buf_idx += 4;
    for (int i = 0; i < session_key_list_length; i++) {
        buf = buf + buf_idx;
        buf_idx =
            parse_session_key(&session_key_list->s_key[i], buf, buf_length);
    }
    session_key_list->num_key = (int)session_key_list_length;
    session_key_list->rear_idx = session_key_list->num_key % MAX_SESSION_KEY;
}

unsigned char *serialize_session_key_req_with_distribution_key(
    unsigned char *serialized, unsigned int serialized_length,
    distribution_key_t *dist_key, unsigned char *name,
    unsigned int *ret_length) {
    unsigned int temp_length;
    unsigned char *temp = symmetric_encrypt_authenticate(
        serialized, serialized_length, dist_key->mac_key,
        dist_key->mac_key_size, dist_key->cipher_key, dist_key->cipher_key_size,
        AES_CBC_128_IV_SIZE, &temp_length);
    unsigned int name_length = strlen(name);
    unsigned char length_buf[] = {name_length};
    unsigned char *ret = malloc(1 + name_length + temp_length);
    unsigned int offset = 0;
    memcpy(ret, length_buf, 1);
    offset += 1;
    strcpy(ret + offset, name);
    offset += name_length;
    memcpy(ret + offset, temp, temp_length);
    free(temp);
    *ret_length = 1 + strlen(name) + temp_length;
    return ret;
}

unsigned char *parse_handshake_1(session_key_t *s_key,
                                 unsigned char *entity_nonce,
                                 unsigned int *ret_length) {
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
                            SST_session_ctx_t *session_ctx) {
    unsigned int decrypted_length;
    unsigned char *decrypted = symmetric_decrypt_authenticate(
        data, data_length, session_ctx->s_key->mac_key, MAC_KEY_SIZE,
        session_ctx->s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
        &decrypted_length);
    unsigned int received_seq_num =
        read_unsigned_int_BE(decrypted, SEQ_NUM_SIZE);
    if (received_seq_num != session_ctx->received_seq_num) {
        error_handling("Wrong sequence number expected.");
    }
    if (check_session_key_validity(session_ctx->s_key)) {
        error_handling("Session key expired!\n");
    }
    session_ctx->received_seq_num++;
    printf("Received seq_num: %d\n", received_seq_num);
    printf("%s\n", decrypted + SEQ_NUM_SIZE);
}

int check_session_key_validity(session_key_t *session_key) {
    return check_validity(session_key->abs_validity);
}

int check_validity(unsigned char *validity) {
    if (time(NULL) >
        read_unsigned_long_int_BE(validity, KEY_EXPIRATION_TIME_SIZE) / 1000) {
        return 1;
    } else {
        return 0;
    }
}

session_key_list_t *send_session_key_request_check_protocol(
    SST_ctx_t *ctx, unsigned char *target_key_id) {
    // TODO: check if needed
    // Temporary code. need to load?
    unsigned char target_session_key_cache[10];
    unsigned int target_session_key_cache_length;
    target_session_key_cache_length =
        (unsigned char)sizeof("none") / sizeof(unsigned char) - 1;
    memcpy(target_session_key_cache, "none", target_session_key_cache_length);
    if (strcmp((const char *)ctx->config->network_protocol, "TCP") ==
        0) {  // TCP
        session_key_list_t *s_key_list = send_session_key_req_via_TCP(ctx);
        printf("received %d keys\n", ctx->config->numkey);

        // SecureCommServer.js handleSessionKeyResp
        //  if(){} //TODO: migration
        //  if(){} //TODO: check received_dist_key null;
        //  if(strncmp(callback_params.target_session_key_cache, "Clients",
        //  callback_params.target_session_key_cache_length) == 0){}
        if (strncmp((const char *)target_session_key_cache, "none",
                    target_session_key_cache_length) == 0) {
            // check received (keyId from auth == keyId from entity_client)
            if (strncmp((const char *)s_key_list->s_key[0].key_id,
                        (const char *)target_key_id,
                        SESSION_KEY_ID_SIZE) != 0) {
                error_handling("Session key id is NOT as expected\n");
            } else {
                printf("Session key id is as expected\n");
            }
            return s_key_list;
        }
    }
    if (strcmp((const char *)ctx->config->network_protocol, "UDP") == 0) {
        // TODO:(Dongha Kim): Implement session key request via UDP.
        session_key_list_t *s_key_list = send_session_key_req_via_UDP(NULL);
        return s_key_list;
    }
    return 0;
}

session_key_list_t *send_session_key_req_via_TCP(SST_ctx_t *ctx) {
    int sock;
    connect_as_client((const char *)ctx->config->auth_ip_addr,
                      (const char *)ctx->config->auth_port_num, &sock);

    session_key_list_t *session_key_list = malloc(sizeof(session_key_list_t));

    session_key_list->s_key = malloc(sizeof(session_key_t) * MAX_SESSION_KEY);

    unsigned char entity_nonce[NONCE_SIZE];
    while (1) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
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
                entity_nonce, auth_nonce, ctx->config->numkey,
                ctx->config->name, ctx->config->purpose, &serialized_length);
            if (check_validity(
                    ctx->dist_key->abs_validity)) {  // when dist_key expired
                printf(
                    "Current distribution key expired, requesting new "
                    "distribution key as well...\n");
                unsigned int enc_length;
                unsigned char *enc = encrypt_and_sign(
                    serialized, serialized_length, ctx, &enc_length);
                free(serialized);
                unsigned char message[MAX_AUTH_COMM_LENGTH];
                unsigned int message_length;
                make_sender_buf(enc, enc_length, SESSION_KEY_REQ_IN_PUB_ENC,
                                message, &message_length);
                write(sock, message, message_length);
                free(enc);
            } else {
                unsigned int enc_length;
                unsigned char *enc =
                    serialize_session_key_req_with_distribution_key(
                        serialized, serialized_length, ctx->dist_key,
                        ctx->config->name, &enc_length);
                unsigned char message[MAX_AUTH_COMM_LENGTH];
                unsigned int message_length;
                make_sender_buf(enc, enc_length, SESSION_KEY_REQ, message,
                                &message_length);
                write(sock, message, message_length);
                free(enc);
            }
        } else if (message_type == SESSION_KEY_RESP) {
            printf(
                "Received session key response encrypted with distribution "
                "key\n");
            unsigned int decrypted_length;
            unsigned char *decrypted = symmetric_decrypt_authenticate(
                data_buf, data_buf_length, ctx->dist_key->mac_key,
                ctx->dist_key->mac_key_size, ctx->dist_key->cipher_key,
                ctx->dist_key->cipher_key_size, AES_CBC_128_IV_SIZE,
                &decrypted_length);
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(decrypted, decrypted_length, reply_nonce,
                                       session_key_list);

            printf("reply_nonce in sessionKeyResp: ");
            print_buf(reply_nonce, NONCE_SIZE);
            if (strncmp((const char *)reply_nonce, (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {
                error_handling("auth nonce NOT verified");
            } else {
                printf("auth nonce verified!\n");
            }
            close(sock);
            return session_key_list;

        } else if (message_type == SESSION_KEY_RESP_WITH_DIST_KEY) {
            signed_data_t signed_data;
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
                          key_size, ctx->pub_key);
            printf("auth signature verified\n");

            // decrypt encrypted_distribution_key
            size_t decrypted_dist_key_buf_length;
            unsigned char *decrypted_dist_key_buf =
                private_decrypt(signed_data.data, key_size, RSA_PKCS1_PADDING,
                                ctx->priv_key, &decrypted_dist_key_buf_length);

            // parse decrypted_dist_key_buf to mac_key & cipher_key
            parse_distribution_key(ctx->dist_key, decrypted_dist_key_buf,
                                   decrypted_dist_key_buf_length);
            free(decrypted_dist_key_buf);

            // decrypt session_key with decrypted_dist_key_buf
            unsigned int decrypted_session_key_response_length;
            unsigned char *decrypted_session_key_response =
                symmetric_decrypt_authenticate(
                    encrypted_session_key, encrypted_session_key_length,
                    ctx->dist_key->mac_key, ctx->dist_key->mac_key_size,
                    ctx->dist_key->cipher_key, ctx->dist_key->cipher_key_size,
                    IV_SIZE, &decrypted_session_key_response_length);
            free(encrypted_session_key);

            // parse decrypted_session_key_response for nonce comparison &
            // session_key.
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(decrypted_session_key_response,
                                       decrypted_session_key_response_length,
                                       reply_nonce, session_key_list);

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
            return session_key_list;
        }
    }
}

session_key_list_t *send_session_key_req_via_UDP(SST_ctx_t *ctx) {
    session_key_list_t *s_key_list;
    return s_key_list;
    // TODO:(Dongha Kim) Implement this function.
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

    printf("client's nonce: ");
    print_buf(hs.nonce, HS_NONCE_SIZE);

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

int check_session_key(unsigned int key_id, session_key_list_t *s_key_list,
                      int idx) {
    unsigned int list_key_id = read_unsigned_int_BE(
        s_key_list->s_key[idx].key_id, SESSION_KEY_ID_SIZE);

    if (key_id == list_key_id) {
        return idx;
    } else {
        return -1;
    }
}

void add_session_key_to_list(session_key_t *s_key,
                             session_key_list_t *existing_s_key_list) {
    existing_s_key_list->num_key++;
    if (existing_s_key_list->num_key > MAX_SESSION_KEY) {
        printf(
            "Warning: Session_key_list is full. Deleting oldest key, and "
            "adding new "
            "key.\n");
        existing_s_key_list->num_key = MAX_SESSION_KEY;
    }
    memcpy(&existing_s_key_list->s_key[existing_s_key_list->rear_idx], s_key,
           sizeof(session_key_t));
    existing_s_key_list->rear_idx =
        (existing_s_key_list->rear_idx + 1) % MAX_SESSION_KEY;
}

void append_session_key_list(session_key_list_t *dest,
                             session_key_list_t *src) {
    if (dest->num_key + src->num_key > MAX_SESSION_KEY) {
        int temp = dest->num_key + src->num_key - MAX_SESSION_KEY;
        printf(
            "Warning: Losing %d keys from original list. Overwriting %d more "
            "keys.\n",
            temp, temp);
    }
    for (int i = 0; i < src->num_key; i++) {
        add_session_key_to_list(
            &src->s_key[mod((i + src->rear_idx - src->num_key),
                            MAX_SESSION_KEY)],
            dest);
    }
}

void free_session_key_t(session_key_t *session_key) {
    free(session_key->mac_key);
    free(session_key->cipher_key);
}

void update_validity(session_key_t *session_key) {
    write_in_n_bytes(
        (time(NULL) + read_unsigned_long_int_BE(session_key->rel_validity,
                                                KEY_EXPIRATION_TIME_SIZE) /
                          1000) *
            1000,
        KEY_EXPIRATION_TIME_SIZE, session_key->abs_validity);
}

int check_session_key_list_addable(int num_key,
                                   session_key_list_t *s_ley_list) {
    if (MAX_SESSION_KEY - s_ley_list->num_key < num_key) {
        // Checks (num_key) number from the oldest session_keys.
        int temp = 1;
        for (int i = 0; i < num_key; i++) {
            temp = temp && check_session_key_validity(&s_ley_list->s_key[mod(
                               (i + s_ley_list->rear_idx - s_ley_list->num_key),
                               MAX_SESSION_KEY)]);
        }
        return !temp;
    } else {
        return 0;
    }
}
