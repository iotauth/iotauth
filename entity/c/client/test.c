#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "secure_comm.h"


unsigned char message[1024];
unsigned char sub_message[1024];

int main(int argc, char* argv[])
{
    
    size_t size = (&message)[1] - message;
    printf("message size:  %ld\n",size);
    TCP_connection(argc, argv, message,size);

}