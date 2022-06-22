#include "common.h"



void nonce_generator(unsigned char * nonce_buf, int size_n)  // nonce generator;
{
    int x = RAND_bytes(nonce_buf,size_n);
    if(x == -1)
    {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}   

void slice(unsigned char * des_buf, unsigned char * buf, int a, int b )
{
    for(int i=0;i<b-a;i++)
    {
        des_buf[i] = buf[a+i];
    }
}
// buffer에서 길이 구할 때!
int payload_buf_length(int b)
{   
    int n = 1;
    while(b > 127)
    {
        n += 1;
        b >>=7;
    }
    return n;
}
int payload_length(unsigned char * message, int b)
{
    int num = 0;
    for (int i =0; i<b; i++)
    {
        num |= (message[i]& 127) <<(7 * i);
        if((message[i]&128) == 0 )
        {
            break;
        }
    }
    return num;
}


// buffer 만들어야 할 때!

int put_in_buf(unsigned char *buffer, int a)
{
    int n = 1;
    while(a > 127)
    {
        buffer[n] = 128 | a & 127;
        n += 1;
        a >>=7;
    }
    buffer[n] = a;
    return n;
}
void print_buf(unsigned char * print_buffer, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", print_buffer[i]);
    printf("\n");
}

void print_string(unsigned char * buffer, int n, int b)
{
    for(n; n<b ; n++)
    {
        printf("%c", buffer[n]);
    }
    printf("\n");
}

int print_seq_num(unsigned char *buf)
{
    int seq=0;
    for(int i =0 ; i<sizeof(buf);i++)
    {
        seq |= buf[i] <<(8 * (sizeof(buf)-i-1));
    }
    printf("Sequence number : %d\n",seq);
    return seq;
}

// payload를 버퍼로 옮길 때!!
void num_key_to_buffer(unsigned char * buffer, int index, int n)
{
        for(int i=0 ; i < NUMKEY_SIZE; i++)
        {
            buffer[index+i] |=  n >> 8*(NUMKEY_SIZE-1-i);
        }
}

void nonce_sort(unsigned char *buffer, size_t size)
{
    int payload_len = payload_length(buffer,1);
    int buf_len = payload_buf_length(payload_len);
    slice(buffer,buffer,5+buf_len,5+buf_len+NONCE_SIZE); // msg type + buf_len + ID
    memcpy(buffer+8,buffer,8);
}

int save_senpup(unsigned char *buffer, int index, 
            unsigned char * s, size_t num_s, unsigned char * p, size_t num_p)
{
    unsigned char n_s[1]; 
    unsigned char n_p[1];
    memset(n_s,num_s,1);
    memset(n_p,num_p,1);
    memcpy(buffer+index, n_s, 1);
    memcpy(buffer+index+1 , s, num_s);
    memcpy(buffer+index+1+num_s , n_p, 1);
    memcpy(buffer+index+1+num_s+1 , p, num_p);
    return index+2+num_s+num_p;
}

int read_variable_UInt(unsigned char * read_buf,int offset, int byteLength)
{
    int num =0;
    unsigned long int sum =1LU;
    for(int i =0; i<byteLength;i++)
    {
        num |= read_buf[offset+i]<< 8*(byteLength-1-i);
    }
    return num; 
}

void parse_handshake(unsigned char * buff, nonce *A) {

    if ((buff[0] & 1) != 0) {
        // nonce exists
        slice(A->nonce,buff,1, 1 + NONCE_SIZE);
    }
    if ((buff[0] & 2) != 0) {
        // replayNonce exists
        slice(A->reply_nonce,buff,1+NONCE_SIZE,1+NONCE_SIZE*2);
    }
    if ((buff[0] & 4) != 0) {
        slice(A->dhParam,buff,1+NONCE_SIZE*2,1+NONCE_SIZE*3);
    }
    
};