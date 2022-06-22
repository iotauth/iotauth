#include "c_secure_comm.h"

/*
function:   prints the seq_num & message.
            This decrypts the received 'payload', with the 'session_key', and calculates the seq_num.
input: seq_num(the seq_num must be saved), payload(data to decrypt), session_key
*/

//TODO: debugging 필요할수도 있음.
void receive_message(unsigned int * seq_num, unsigned char * payload, unsigned int payload_length, session_key * session_key)
{
    //TODO: check validity
    // 영빈이형이 이쪽 만들어주면 좋을듯? 함수로 하나 빼서?
    unsigned int decrypted_length;
    unsigned char decrypted = symmetric_decrypt_authenticate(payload, payload_length, session_key->mac_key, MAC_KEY_SIZE, session_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE, &decrypted_length);
    *seq_num = read_unsigned_int_BE(decrypted, SEQ_NUM_SIZE);
    printf("Received seq_num: %d\n", *seq_num);
    printf("%s\n", decrypted+SEQ_NUM_SIZE);
}

//TODO: 영빈이형이 하면 좋을듯.
void check_validity(){}