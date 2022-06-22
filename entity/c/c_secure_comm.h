#ifndef C_SECURE_COMM_H
#define C_SECURE_COMM_H

#include "c_crypto.h"

//This file includes functions that uses the struct "session_key"

void receive_message(unsigned int * seq_num, unsigned char * payload, unsigned int payload_length, session_key * session_key);

#endif