#include "c_common.h"

void error_handling(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void print_buf(unsigned char *buf, size_t size) {
    char hex[size * 3 + 1];
    for(size_t i = 0; i < size; i++) {
        sprintf(hex + 3 * i, "%.2x ", buf[i]);
    }
    printf("Hex: %s\n", hex);
}

void generate_nonce(int length, unsigned char *buf) {
    int x = RAND_bytes(buf, length);
    if (x == -1) {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}

void write_in_n_bytes(uint64_t num, int n, unsigned char *buf) {
    for (int i = 0; i < n; i++) {
        buf[i] |= num >> 8 * (n - 1 - i);
    }
}

unsigned int read_unsigned_int_BE(unsigned char *buf, int byte_length) {
    int num = 0;
    for (int i = 0; i < byte_length; i++) {
        num |= buf[i] << 8 * (byte_length - 1 - i);
    }
    return num;
}

unsigned long int read_unsigned_long_int_BE(unsigned char *buf,
                                            int byte_length) {
    unsigned long int num_valid = 1LU;
    for (int i = 0; i < byte_length; i++) {
        unsigned long int num = 1LU << 8 * (byte_length - 1 - i);
        num_valid |= num * buf[i];
    }
    return num_valid;
}

void var_length_int_to_num(unsigned char *buf, unsigned int buf_length,
                           unsigned int *payload_length,
                           unsigned int *payload_buf_length) {
    unsigned int num = 0;
    *payload_buf_length = 0;
    for (int i = 0; i < buf_length; i++) {
        num |= (buf[i] & 127) << (7 * i);
        if ((buf[i] & 128) == 0) {
            *payload_length = num;
            *payload_buf_length = i + 1;
            break;
        }
    }
}

unsigned char *parse_received_message(unsigned char *received_buf,
                                      unsigned int received_buf_length,
                                      unsigned char *message_type,
                                      unsigned int *data_buf_length) {
    *message_type = received_buf[0];
    unsigned int payload_buf_length;
    var_length_int_to_num(received_buf + MESSAGE_TYPE_SIZE, received_buf_length,
                          data_buf_length, &payload_buf_length);
    return received_buf + MESSAGE_TYPE_SIZE +
           payload_buf_length;
}

void num_to_var_length_int(unsigned int data_length, unsigned char *payload_buf,
                           unsigned int *payload_buf_length) {
    *payload_buf_length = 1;
    while (data_length > 127) {
        payload_buf[*payload_buf_length - 1] = 128 | data_length & 127;
        *payload_buf_length += 1;
        data_length >>= 7;
    }
    payload_buf[*payload_buf_length - 1] = data_length;
}

void make_buffer_header(unsigned int data_length, unsigned char MESSAGE_TYPE,
                        unsigned char *header, unsigned int *header_length) {
    unsigned char payload_buf[MAX_PAYLOAD_BUF_SIZE];
    unsigned int payload_buf_len;
    num_to_var_length_int(data_length, payload_buf, &payload_buf_len);
    *header_length = MESSAGE_TYPE_SIZE + payload_buf_len;
    header[0] = MESSAGE_TYPE;
    memcpy(header + MESSAGE_TYPE_SIZE, payload_buf, payload_buf_len);
}

void concat_buffer_header_and_payload(
    unsigned char *header, unsigned int header_length, unsigned char *payload,
    unsigned int payload_length, unsigned char *ret, unsigned int *ret_length) {
    memcpy(ret, header, header_length);
    memcpy(ret + header_length, payload, payload_length);
    *ret_length = header_length + payload_length;
}

void make_sender_buf(unsigned char *payload, unsigned int payload_length,
                     unsigned char MESSAGE_TYPE, unsigned char *sender,
                     unsigned int *sender_length) {
    unsigned char header[MAX_PAYLOAD_BUF_SIZE + 1];
    unsigned int header_length;
    make_buffer_header(payload_length, MESSAGE_TYPE, header, &header_length);
    concat_buffer_header_and_payload(header, header_length, payload,
                                     payload_length, sender, sender_length);
}

void connect_as_client(const char *ip_addr, const char *port_num, int *sock) {
    struct sockaddr_in serv_addr;
    int str_len;
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if (*sock == -1) {
        error_handling("socket() error");
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  // IPv4
    serv_addr.sin_addr.s_addr =
        inet_addr(ip_addr);  // the ip_address to connect to
    serv_addr.sin_port = htons(atoi(port_num));
    if (connect(*sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        error_handling("connect() error!");
    }
    printf("\n\n------------Connected-------------\n");
}

void serialize_handshake(unsigned char *nonce, unsigned char *reply_nonce,
                         unsigned char *ret) {
    if (nonce == NULL && reply_nonce == NULL) {
        error_handling("Error: handshake should include at least on nonce.");
    }
    unsigned char indicator = 0;
    if (nonce != NULL) {
        indicator += 1;
        memcpy(ret + 1, nonce, HS_NONCE_SIZE);
    }
    if (reply_nonce != NULL) {
        indicator += 2;
        memcpy(ret + 1 + HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    // TODO: add dhParam options.
    ret[0] = indicator;
}

void parse_handshake(unsigned char *buf, HS_nonce_t *ret) {
    if ((buf[0] & 1) != 0) {
        memcpy(ret->nonce, buf + 1, HS_NONCE_SIZE);
    }
    if ((buf[0] & 2) != 0) {
        memcpy(ret->reply_nonce, buf + 1 + HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
    if ((buf[0] & 4) != 0) {
        memcpy(ret->dhParam, buf + 1 + HS_NONCE_SIZE * 2, HS_NONCE_SIZE);
    }
}

int mod(int a, int b) {
    int r = a % b;
    return r < 0 ? r + b : r;
}
