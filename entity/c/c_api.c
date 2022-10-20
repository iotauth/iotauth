#include "c_api.h"

extern unsigned char entity_client_state;
extern unsigned char entity_server_state;

SST_ctx_t *init_SST(char *config_path) {
    SST_ctx_t *ctx = malloc(sizeof(SST_ctx_t));
    ctx->config = load_config(config_path);
    int numkey = ctx->config->numkey;

    ctx->pub_key = load_auth_public_key(ctx->config->auth_pubkey_path);
    ctx->priv_key = load_entity_private_key(ctx->config->entity_privkey_path);
    if (numkey > MAX_SESSION_KEY) {
        printf(
            "Too much requests of session keys. The max number of requestable "
            "session keys are %d",
            MAX_SESSION_KEY);
    }
    return ctx;
}

session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list) {
    if (existing_s_key_list != NULL) {
        if (check_session_key_list_addable(ctx->config->numkey,
                                           existing_s_key_list)) {
            printf("Unable to get_session_key().\n");
            return existing_s_key_list;
        }
    }
    session_key_list_t *earned_s_key_list;
    if (strcmp((const char *)ctx->config->network_protocol, "TCP") == 0) {
        earned_s_key_list = send_session_key_req_via_TCP(ctx);
    } else if (strcmp((const char *)ctx->config->network_protocol, "UDP") ==
               0) {
        earned_s_key_list = send_session_key_req_via_UDP(ctx);
    }

    if (existing_s_key_list == NULL) {
        return earned_s_key_list;
    } else {
        append_session_key_list(existing_s_key_list, earned_s_key_list);
        free_session_key_list_t(earned_s_key_list);
        return existing_s_key_list;
    }
}

SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx) {
    // Initialize SST_session_ctx_t
    SST_session_ctx_t *session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->received_seq_num = 0;
    session_ctx->sent_seq_num = 0;

    int sock;
    connect_as_client((const char *)ctx->config->entity_server_ip_addr,
                      (const char *)ctx->config->entity_server_port_num, &sock);
    unsigned char entity_nonce[HS_NONCE_SIZE];
    unsigned int parsed_buf_length;
    unsigned char *parsed_buf =
        parse_handshake_1(s_key, entity_nonce, &parsed_buf_length);
    unsigned char sender_HS_1[MAX_HS_BUF_LENGTH];
    unsigned int sender_HS_1_length;
    make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_1,
                    sender_HS_1, &sender_HS_1_length);
    write(sock, sender_HS_1, sender_HS_1_length);
    free(parsed_buf);
    entity_client_state = HANDSHAKE_1_SENT;

    // received handshake 2
    unsigned char received_buf[MAX_HS_BUF_LENGTH];
    unsigned int received_buf_length =
        read(sock, received_buf, sizeof(received_buf));
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SKEY_HANDSHAKE_2) {
        if (entity_client_state != HANDSHAKE_1_SENT) {
            printf(
                "Comm init failed: wrong sequence of handshake, "
                "disconnecting...\n");
        }
        unsigned int parsed_buf_length;
        unsigned char *parsed_buf = check_handshake_2_send_handshake_3(
            data_buf, data_buf_length, entity_nonce, s_key, &parsed_buf_length);
        unsigned char sender_HS_2[MAX_HS_BUF_LENGTH];
        unsigned int sender_HS_2_length;
        make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_3,
                        sender_HS_2, &sender_HS_2_length);
        write(sock, sender_HS_2, sender_HS_2_length);
        free(parsed_buf);
        update_validity(s_key);
        printf("switching to IN_COMM\n");
        entity_client_state = IN_COMM;
    }
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
    session_ctx->sock = sock;
    return session_ctx;
}

SST_session_ctx_t *server_secure_comm_setup(
    SST_ctx_t *ctx, int clnt_sock, session_key_list_t *existing_s_key_list) {
    // Initialize SST_session_ctx_t
    SST_session_ctx_t *session_ctx = malloc(sizeof(SST_session_ctx_t));

    session_ctx->received_seq_num = 0;
    session_ctx->sent_seq_num = 0;
    session_ctx->sock = clnt_sock;

    entity_server_state = IDLE;
    unsigned char server_nonce[HS_NONCE_SIZE];

    session_key_t *s_key;
    while (1) {
        unsigned char received_buf[MAX_HS_BUF_LENGTH];
        int received_buf_length =
            read(clnt_sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_1) {
            printf("received session key handshake1\n");
            if (entity_server_state != IDLE) {
                error_handling(
                    "Error during comm init - in wrong state, expected: IDLE, "
                    "disconnecting...\n");
            }
            printf("switching to HANDSHAKE_1_RECEIVED state.\n");
            entity_server_state = HANDSHAKE_1_RECEIVED;
            unsigned char expected_key_id[SESSION_KEY_ID_SIZE];
            memcpy(expected_key_id, data_buf, SESSION_KEY_ID_SIZE);
            unsigned int expected_key_id_int =
                read_unsigned_int_BE(expected_key_id, SESSION_KEY_ID_SIZE);

            // If the entity_server already has the corresponding session key,
            // it does not have to request session key from Auth
            int session_key_found = -1;
            if (existing_s_key_list != NULL) {
                for (int i = 0; i < existing_s_key_list->num_key; i++) {
                    session_key_found = check_session_key(
                        expected_key_id_int, existing_s_key_list, i);
                }
            }
            if (session_key_found >= 0) {
                s_key = &existing_s_key_list->s_key[session_key_found];
            } else if (session_key_found == -1) {
                // WARNING: The following line overwrites the purpose.
                sprintf(ctx->config->purpose, "{\"keyId\":%d}",
                        expected_key_id_int);

                session_key_list_t *s_key_list;
                s_key_list = send_session_key_request_check_protocol(
                    ctx, expected_key_id);
                s_key = s_key_list->s_key;
                if (existing_s_key_list != NULL) {
                    add_session_key_to_list(s_key, existing_s_key_list);
                }
            }
            if (entity_server_state != HANDSHAKE_1_RECEIVED) {
                error_handling(
                    "Error during comm init - in wrong state, expected: "
                    "HANDSHAKE_1_RECEIVED, disconnecting...");
            }
            unsigned int parsed_buf_length;
            unsigned char *parsed_buf = check_handshake1_send_handshake2(
                data_buf, data_buf_length, server_nonce, s_key,
                &parsed_buf_length);

            unsigned char sender[MAX_HS_BUF_LENGTH];
            unsigned int sender_length;
            make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_2,
                            sender, &sender_length);
            write(clnt_sock, sender, sender_length);
            free(parsed_buf);
            printf("switching to HANDSHAKE_2_SENT\n");
            entity_server_state = HANDSHAKE_2_SENT;

        } else if (message_type == SKEY_HANDSHAKE_3) {
            printf("received session key handshake3!\n");
            if (entity_server_state != HANDSHAKE_2_SENT) {
                error_handling(
                    "Error during comm init - in wrong state, expected: IDLE, "
                    "disconnecting...\n");
            }
            unsigned int decrypted_length;
            unsigned char *decrypted = symmetric_decrypt_authenticate(
                data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE,
                s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
                &decrypted_length);
            HS_nonce_t hs;
            parse_handshake(decrypted, &hs);
            free(decrypted);
            // compare my_nonce and received_nonce
            if (strncmp((const char *)hs.reply_nonce,
                        (const char *)server_nonce, HS_NONCE_SIZE) != 0) {
                error_handling(
                    "Comm init failed: server NOT verified, nonce NOT matched, "
                    "disconnecting...\n");
            } else {
                printf("server authenticated/authorized by solving nonce!\n");
            }
            update_validity(s_key);
            printf("switching to IN_COMM\n");
            entity_server_state = IN_COMM;
            memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
            return session_ctx;
        }
    }
}

void *receive_thread(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length = 0;
    while (1) {
        received_buf_length =
            read(session_ctx->sock, received_buf, sizeof(received_buf));
        if (received_buf_length == 0) {
            printf("Socket closed!\n");
            close(session_ctx->sock);
            return 0;
        }
        if (received_buf_length == -1) {
            printf("Connection error!\n");
            return 0;
        }
        receive_message(received_buf, received_buf_length, session_ctx);
    }
}

void receive_message(unsigned char *received_buf,
                     unsigned int received_buf_length,
                     SST_session_ctx_t *session_ctx) {
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SECURE_COMM_MSG) {
        print_recevied_message(data_buf, data_buf_length, session_ctx);
    }
}

void send_secure_message(char *msg, unsigned int msg_length,
                         SST_session_ctx_t *session_ctx) {
    if (check_session_key_validity(&session_ctx->s_key)) {
        error_handling("Session key expired!\n");
    }
    unsigned char buf[SEQ_NUM_SIZE + msg_length];
    memset(buf, 0, SEQ_NUM_SIZE + msg_length);
    write_in_n_bytes(session_ctx->sent_seq_num, SEQ_NUM_SIZE, buf);
    memcpy(buf + SEQ_NUM_SIZE, (unsigned char *)msg, msg_length);

    // encrypt
    unsigned int encrypted_length;
    unsigned char *encrypted = symmetric_encrypt_authenticate(
        buf, SEQ_NUM_SIZE + msg_length, session_ctx->s_key.mac_key,
        MAC_KEY_SIZE, session_ctx->s_key.cipher_key, CIPHER_KEY_SIZE,
        AES_CBC_128_IV_SIZE, &encrypted_length);

    session_ctx->sent_seq_num++;
    unsigned char
        sender_buf[MAX_PAYLOAD_LENGTH];  // TODO: Currently the send message
                                         // does not support dynamic sizes, the
                                         // max length is shorter than 1024.
                                         // Must need to decide static or
                                         // dynamic buffer size.
    unsigned int sender_buf_length;
    make_sender_buf(encrypted, encrypted_length, SECURE_COMM_MSG, sender_buf,
                    &sender_buf_length);
    free(encrypted);
    write(session_ctx->sock, sender_buf, sender_buf_length);
}

void free_session_key_list_t(session_key_list_t *session_key_list) {
    free(session_key_list->s_key);
    free(session_key_list);
}

void free_SST_ctx(SST_ctx_t *ctx) {
    OPENSSL_free(ctx->priv_key);
    OPENSSL_free(ctx->pub_key);
    free_config_t(ctx->config);
}
