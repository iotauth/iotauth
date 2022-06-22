#ifndef ENTITY_AUTH
#define ENTITY_AUTH

#include "crypto.h"

int entity_auth(unsigned char * message, size_t size);
int handshake1(unsigned char * msg, size_t size);
int handshake2(unsigned char * msg, size_t size);
void send_message(int my_sock, unsigned char * msg);
void *receive_message(void *multiple_arg); 

#endif