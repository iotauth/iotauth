
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h> 
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <pthread.h>

#define abc 6
#define ddd 1+abc*2

typedef struct{
    unsigned char * hi;
    unsigned int hello;
    unsigned char good[10];
}tester;

int main(){

    int c = NULL;
    printf("%d\n", c);
}