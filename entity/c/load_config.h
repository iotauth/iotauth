#ifndef LOAD_CONFIG_H
#define LOAD_CONFIG_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX 256
#define EIN 1
#define EIP 2
#define EINK 3
#define AIPP 4
#define EIPP 5
#define AIIA 6
#define AIP 7
#define ESIIP 8
#define ESIP 9
#define NP 10

typedef struct
{
    unsigned char name[32];
    unsigned char purpose[32];
    unsigned char numkey[1];
    unsigned char auth_pubkey_path[50];
    unsigned char entity_privkey_path[50];
    unsigned char auth_ip_addr[17];
    unsigned char auth_port_num[6];
    unsigned char entity_server_ip_addr[17];
    unsigned char entity_server_port_num[6];
    unsigned char network_protocol[4];
} config_t;

// Get a value by comparing a string of conditional statement with a variable.
// @param ptr input variable to compare with string
// @return value
int get_key_value(char *ptr);

// Load config file from path and save the information in config struct.
// @param path config file path
// @return config struct to use when connecting to Auth
config_t *load_config_t(char *path);

#endif // LOAD_CONFIG_H
