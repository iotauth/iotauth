#include "entity_auth.h"



distribution_key dist_key; 
sessionkey sess_key[10];
nonce entity_nonce[3]; //TODO: 덮어씌우기
start_time validity_time;
save_message save_msg[100];

int entity_auth(unsigned char * msg, size_t size)
{
    if(msg[0] == AUTH_HELLO)
    {
        print_buf(msg, 14);
        unsigned char sender[] = "net1.client";
        unsigned char purpose[] = "{\"group\":\"Servers\"}";
        int num_key = 3;

        nonce_sort(msg,size);
        nonce_generator(msg,NONCE_SIZE);
        slice(entity_nonce[0].nonce,msg,0,8);
        print_buf(entity_nonce[0].nonce,8);
        num_key_to_buffer(msg, NONCE_SIZE*2,num_key); // TODO: 
        int msg_len = save_senpup(msg,NONCE_SIZE*2+NUMKEY_SIZE, sender,strlen(sender),purpose,strlen(purpose));

        int total_len = encrypt_sign(msg,msg_len); // TODO: int로 return하냐? 아니면 void로해서 pointer로 return하냐 ? (보낼 사이즈)
        msg[0] = SESSION_KEY_REQ_IN_PUB_ENC; // TODO: 질문: msg shift하는게 효율적인가?
        return total_len;
    }
    else if(msg[0] == SESSION_KEY_RESP_WITH_DIST_KEY)
    {
        printf("\nreceived session key response with distribution key attached! \n");
        int payload_len = payload_length(msg+1,size);
        int buf_len = payload_buf_length(payload_len); // TODO: 함수 두 개로 나누는게 좋은지? 아니면 struct로 만드는게 좋은지? 이유: 너무 많이 쓰임!
        printf("payload len: %d, buf len: %d\n",payload_len,buf_len );
        unsigned char *s1 = malloc(payload_len - DIST_ENC_SIZE);
        slice(s1,msg,DIST_ENC_SIZE+1+buf_len,1+buf_len+payload_len);
        dist_key_decrypt(msg, 1+buf_len,  &dist_key);
        sess_key_decrypt(s1, payload_len - DIST_ENC_SIZE, sess_key, &dist_key);
        if(strncmp((char *)s1, (char *) entity_nonce[0].nonce, NONCE_SIZE) == 0 )
        {
            printf("Nonce is consistent. \n");
        }
        else
            printf("auth nonce NOT verified\n");
        return 0;
        free(s1);
    }
}

int handshake1(unsigned char * msg, size_t size)
{
    memset(msg,0,size);
    unsigned char nonce_buf[NONCE_SIZE*2 +1];
    memset(nonce_buf,0,sizeof(nonce_buf));
    nonce_generator(entity_nonce[1].nonce,NONCE_SIZE);
    memcpy(nonce_buf+1,entity_nonce[1].nonce,8);
    nonce_buf[0] = ENTITY_HELLO; //1
    print_buf(nonce_buf,17);
    print_buf(sess_key[0].key_id,8);
    print_buf(sess_key[0].cipher_key, CIPHER_KEY_SIZE);
    print_buf(sess_key[0].mac_key, MAC_KEY_SIZE);
    int a = symm_enc_authenticate(sess_key[0], msg, nonce_buf,sizeof(nonce_buf), 1);
    print_buf(msg,a);
    return 1+1+a;
}

int handshake2(unsigned char * msg, size_t size)
{
    print_buf(msg,size);
    symm_dec_authenticate(sess_key[0],msg,size);
    parse_handshake(msg,&entity_nonce[2]);
    if(strncmp((char *)entity_nonce[1].nonce, (char *) entity_nonce[2].reply_nonce, NONCE_SIZE) == 0 )
    {
        printf("Nonce is the same \n");
    }
    else
        printf("auth nonce NOT verified\n");
    unsigned char nonce_buf[NONCE_SIZE*2 +1];
    memset(nonce_buf,0,17);
    nonce_buf[0] = 2;
    memcpy(nonce_buf+1+NONCE_SIZE,entity_nonce[2].nonce,NONCE_SIZE);
    int a = symm_enc_authenticate(sess_key[0],msg, nonce_buf, 17, 0);
    printf("size? %d \n", a);
    int b = payload_buf_length(a);
    memcpy(msg+1+b,msg,a);
    put_in_buf(msg,a);
    msg[0] = SKEY_HANDSHAKE_3;
    return 1+b+a;
}
void send_message(int my_sock, unsigned char * msg)
{
    unsigned int seq_num = 0;
    validity_time.st_time = 0;

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
                num_valid |= num*sess_key[0].abs_validity[i];
            }
            printf("abs_valid : %ld\n", num_valid);
            num_valid = num_valid/1000;
            long int relvalidity = read_variable_UInt(sess_key[0].rel_validity, 0, 6)/1000;
            
            if(time(NULL) > num_valid || time(NULL) - validity_time.st_time >relvalidity)
            {
                printf("session key is expired");
                break;
            }
            else
            {
                unsigned char message[32]; 
                unsigned char message_buf[32]; 
                memset(message,0,32);
                memset(message_buf,0,32);
                scanf("%s", message);
                message_buf[7] += seq_num;
                memcpy(message_buf+8,message,strlen(message));
                // print_buf(message_buf,32);
                int a = symm_enc_authenticate(sess_key[0],msg,message_buf,sizeof(message_buf),0);
                // printf("size? %d \n", a);
                int b = payload_buf_length(a);
                memcpy(msg+1+b,msg,a);
                put_in_buf(msg,a);
                msg[0] = SECURE_COMM_MSG;

                write(my_sock,msg,a+b+1);

                seq_num += 1;
            }

        }
    
        else if(strncmp((char *) command, (char *) "finComm", 7) == 0 )
        {
            printf("Exit !!\n");
            break;
        }
    }
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
            num_valid |= num*sess_key[0].abs_validity[i];
        }
        printf("abs_valid : %ld\n", num_valid);
        num_valid = num_valid/1000;
        long int relvalidity = read_variable_UInt(sess_key[0].rel_validity, 0, 6)/1000;
        if(time(NULL) > num_valid || time(NULL) - validity_time.st_time >relvalidity)
        {
            printf("session key is expired");
            break;
        }
        else
        {
        symm_dec_authenticate(sess_key[0],buf_msg,str_len);
        
        memset(save_msg[n].receive_message,0,sizeof(save_msg[n].receive_message));
        int seq_num = print_seq_num(buf_msg);
        
        save_msg[n].receive_seq_num = seq_num ; 
        
        slice(save_msg[n].receive_message,buf_msg,8,sizeof(save_msg[n].receive_message));
        printf("message : %s\n", save_msg[n].receive_message);
        n +=1;
        }
    }
}