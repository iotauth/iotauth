#ifndef SECURE_COMM
#define SECURE_COMM

#include "entity_auth.h"


// void (*TCP_connection)(int argc, char* argv[])
void TCP_connection(int argc, char* argv[], unsigned char  *message, size_t size);

// void TCP_connection(int argc, char* argv[]);

#endif