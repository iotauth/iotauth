#ifndef LOAD_CONFIG_H
#define LOAD_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 256
#define ENTITY_INFO_NAME 1
#define ENTITY_INFO_PURPOSE 2
#define ENTITY_INFO_NUMKEY 3
#define AUTH_INFO_PUBKEY_PATH 4
#define ENTITY_INFO_PRIVKEY_PATH 5
#define AUTH_INFO_IP_ADDRESS 6
#define AUTH_INFO_PORT 7
#define ENTITY_SERVER_INFO_IP_ADDRESS 8
#define ENTITY_SERVER_INFO_PORT_NUMBER 9
#define NETWORK_PROTOCOL 10

typedef struct {
    char name[32];
    char purpose[32];
    int numkey;
    char *auth_pubkey_path;
    char *entity_privkey_path;
    char auth_ip_addr[17];
    char auth_port_num[6];
    char entity_server_ip_addr[17];
    char entity_server_port_num[6];
    char network_protocol[4];
} config_t;

// Get a value by comparing a string of conditional statement with a variable.
// @param ptr input variable to compare with string
// @return value
int get_key_value(char *ptr);

// Load config file from path and save the information in config struct.
// @param path config file path
// @return config struct to use when connecting to Auth
config_t *load_config(char *path);

// Free memory used in config_t.
// @param config struct config_t to be freed.
void free_config_t(config_t *config);

#endif  // LOAD_CONFIG_H
