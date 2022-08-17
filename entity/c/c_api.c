#include "c_api.h"

extern int sent_seq_num;
extern unsigned char entity_client_state;
extern unsigned char entity_server_state;
extern long int st_time;

config_t *load_config(char *path) { return load_config_t(path); } //key load.

session_key_list_t *get_session_key(config_t *config_info) { //TODO: struct ctx - distribution_key, config_t, pubkey, privkey
    if (strcmp((const char *)config_info->network_protocol, "TCP") == 0) {
        return send_session_key_req_via_TCP(config_info);
    } else if (strcmp((const char *)config_info->network_protocol, "UDP") ==
               0) {
        return send_session_key_req_via_UDP();
    }
    return 0;
}

int secure_connect_to_server(session_key_t *s_key, config_t *config_info) {
    int sock;
    connect_as_client((const char *)config_info->entity_server_ip_addr,
                      (const char *)config_info->entity_server_port_num, &sock);
    unsigned char entity_nonce[HS_NONCE_SIZE];
    unsigned int parsed_buf_length;
    unsigned char *parsed_buf =
        parse_handshake_1(s_key, entity_nonce, &parsed_buf_length);
    unsigned char sender_HS_1[128];  // TODO: actually only needs 19 bytes.
    unsigned int sender_HS_1_length;
    make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_1,
                    sender_HS_1, &sender_HS_1_length);
    write(sock, sender_HS_1, sender_HS_1_length);
    free(parsed_buf);
    entity_client_state = HANDSHAKE_1_SENT;

    // received handshake 2
    unsigned char received_buf[1000];
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
        unsigned char sender_HS_2[256];
        unsigned int sender_HS_2_length;
        make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_3,
                        sender_HS_2, &sender_HS_2_length);
        write(sock, sender_HS_2, sender_HS_2_length);
        free(parsed_buf);
        printf("switching to IN_COMM\n");
        entity_client_state = IN_COMM;
    }
    sent_seq_num = 0;
    st_time = 0;
    printf("wait\n");
    return sock;
}

session_key_t *server_secure_comm_setup(config_t *config, int clnt_sock) { //TODO: optional session_key_list
    entity_server_state = IDLE;
    unsigned char server_nonce[HS_NONCE_SIZE];
    session_key_t *s_key;
    while (1) {
        unsigned char received_buf[1024];
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
            /*
            // TODO: Need to check if the entity_server currently holds the
            session key of the expected_key_id.
            // If the entity_server already has the corresponding session key,
            it does not have to request session key from Auth. int
            session_key_found = check_session_key(server_args[i].s_key->key_id,
            &server_args, fd_max);
            */
            int session_key_found = -1;
            if (session_key_found > 0) {
                // TODO: implement when session_key_found
            } else if (session_key_found == -1) {
                unsigned char temp_buf[SESSION_KEY_ID_SIZE];
                sprintf((char *)temp_buf, "%d", expected_key_id_int);
                memcpy(config->purpose + 9, temp_buf, SESSION_KEY_ID_SIZE);

                s_key = send_session_key_request_check_protocol(
                    config, expected_key_id);

                if (entity_server_state != HANDSHAKE_1_RECEIVED) {
                    error_handling(
                        "Error during comm init - in wrong state, expected: "
                        "HANDSHAKE_1_RECEIVED, disconnecting...");
                }

                unsigned int parsed_buf_length;
                unsigned char *parsed_buf = check_handshake1_send_handshake2(
                    data_buf, data_buf_length, server_nonce, s_key,
                    &parsed_buf_length);

                unsigned char sender[256];
                unsigned int sender_length;
                make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_2,
                                sender, &sender_length);
                write(clnt_sock, sender, sender_length);
                free(parsed_buf);
                printf("switching to HANDSHAKE_2_SENT\n");
                entity_server_state = HANDSHAKE_2_SENT;
            }
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
            printf("switching to IN_COMM\n");
            entity_server_state = IN_COMM;
            return s_key;
        }
    }
}

void *receive_thread(void *arguments) {
    while (1) {
        arg_struct_t *args = (arg_struct_t *)arguments;
        unsigned char received_buf[1000];
        unsigned int received_buf_length =
            read(args->sock, received_buf, sizeof(received_buf));
        receive_message(received_buf, received_buf_length, args->s_key);
    }
}

void receive_message(unsigned char *received_buf,
                     unsigned int received_buf_length, session_key_t *s_key) {
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SECURE_COMM_MSG) {
        print_recevied_message(data_buf, data_buf_length, s_key);
    }
}

void send_secure_message(char *msg, unsigned int msg_length,
                         session_key_t *s_key, int sock) {
    if (!check_validity(sent_seq_num, s_key->rel_validity, s_key->abs_validity,
                        &st_time)) {
        error_handling("Session key expired!\n");
    }
    unsigned char *buf = (unsigned char *)malloc(SEQ_NUM_SIZE + msg_length);
    memset(buf, 0, SEQ_NUM_SIZE + msg_length);
    write_in_n_bytes(sent_seq_num, SEQ_NUM_SIZE, buf);
    memcpy(buf + SEQ_NUM_SIZE, (unsigned char *)msg, msg_length);

    // encrypt
    unsigned int encrypted_length;
    unsigned char *encrypted = symmetric_encrypt_authenticate(
        buf, SEQ_NUM_SIZE + msg_length, s_key->mac_key, MAC_KEY_SIZE,
        s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
        &encrypted_length);
    free(buf);
    sent_seq_num++;
    unsigned char sender_buf[1024];  // TODO: Currently the send message does
                                     // not support dynamic sizes, the max
                                     // length is shorter than 1024. Must need
                                     // to decide static or dynamic buffer size.
    unsigned int sender_buf_length;
    make_sender_buf(encrypted, encrypted_length, SECURE_COMM_MSG, sender_buf,
                    &sender_buf_length);
    free(encrypted);
    write(sock, sender_buf, sender_buf_length);
}
