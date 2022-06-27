#include <stdio.h>
#include <string.h> 
#include "common.h"
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

typedef struct{
    unsigned char name[32];
    unsigned char purpose[32];
    unsigned char numkey[1];
    unsigned char auth_pubkey_path[36];
    unsigned char entity_privkey_path[44] ;
    unsigned char auth_ip_addr[15];
    unsigned char auth_port_num[5];
    unsigned char entity_server_ip_addr[15];
    unsigned char entity_server_port_num[5];
}config;

const char entity_info_name[] = "entityInfo.name";
const char entity_info_purpose[] = "entityInfo.purpose";
const char entity_info_numkey[] = "entityInfo.number_key";
const char authinfo_pubkey_path[] = "authInfo.pubkey.path";
const char entity_info_privkey_path[] = "entityInfo.privkey.path";
const char authInfo_ip_address[] = "auth.ip.address" ;
const char authInfo_port[] = "auth.port.number" ;
const char entity_serverInfo_ip_address[] = "entity.server.ip.address" ;
const char entity_serverInfo_port_number[] = "entity.server.port.number" ;

void file_log(char path)
{
    FILE* fp = fopen(path, "r");  //open test file as 'r'(read) mode.
    char buffer[MAX] = { 0, };
    char *pline;

    printf("config\n");
    while(!feof(fp))
    {
        pline = fgets(buffer,MAX,fp);
        unsigned char *ptr = strtok(pline, "=");
        int a;
}

int get_key_value(char * ptr)
{
    if(strcmp(ptr, entity_info_name) == 0) return EIN;
    else if(strcmp(ptr, entity_info_purpose) == 0) return EIP;
    else if(strcmp(ptr, entity_info_numkey) == 0) return EINK;
    else if(strcmp(ptr, authinfo_pubkey_path) == 0) return AIPP;
    else if(strcmp(ptr, entity_info_privkey_path) == 0) return EIPP;
    else if(strcmp(ptr, authInfo_ip_address) == 0) return AIIA;
    else if(strcmp(ptr, authInfo_port) == 0) return AIP;
    else if(strcmp(ptr, entity_serverInfo_ip_address) == 0) return ESIIP;
    else if(strcmp(ptr, entity_serverInfo_port_number) == 0) return ESIP;
    else return -1;
}

// int main (int argc, char *argv[])
// {
//     char path;
//     file_log(path);
//     get_key_value();
// }

void main()
{
    config * config_info = load_config();
}

config * load_config()
    FILE* fp = fopen("a.config", "r");  //open test file as 'r'(read) mode.
    char buffer[MAX] = { 0, };
    char *pline;

    printf("config\n");
    file_log("a.config");
    while(!feof(fp))
    {
        pline = fgets(buffer,MAX,fp);
        unsigned char *ptr = strtok(pline, "=");
        int a;
        while(ptr != NULL)
        {
            switch (get_key_value(ptr))
            {
                case EIN:
                    ptr = strtok(NULL, " ");
                    printf("name: %s\n", ptr);
                    memcpy(c.name,ptr,sizeof(c.name));
                    break;
                case EIP:
                    ptr = strtok(NULL, " ");
                    printf("purpose: %s\n", ptr);
                    memcpy(c.purpose,ptr,sizeof(c.purpose));
                    break;
                case EINK:
                    ptr = strtok(NULL, " ");
                    printf("Numkey: %s\n", ptr);
                    memcpy(c.numkey,ptr,sizeof(c.numkey));
                    break;
                case AIPP:
                    ptr = strtok(NULL, " ");
                    printf("Pubkey path of Auth: %s\n", ptr);
                    memcpy(c.auth_pubkey_path, ptr, sizeof(c.auth_pubkey_path));
                    break;
                case EIPP:
                    ptr = strtok(NULL, " ");
                    printf("Privkey path of Entity: %s\n", ptr);
                    memcpy(c.entity_privkey_path, ptr, sizeof(c.entity_privkey_path));
                    break;
                case AIIA:
                    ptr = strtok(NULL, " ");
                    printf("IP address of Auth: %s\n", ptr);
                    memcpy(c.auth_ip_addr, ptr, sizeof(c.auth_ip_addr));
                    break;
                case AIP:
                    ptr = strtok(NULL, " ");
                    printf("Port number of Auth: %s\n", ptr);
                    memcpy(c.auth_port_num,ptr,sizeof(c.auth_port_num));
                    break;
                case ESIIP:
                    ptr = strtok(NULL, " ");
                    printf("IP address of entity server: %s\n", ptr);
                    memcpy(c.entity_server_ip_addr, ptr, sizeof(c.entity_server_ip_addr));
                    break;
                case ESIP:
                    ptr = strtok(NULL, " ");
                    printf("Port number of entity server: %s\n", ptr);
                    memcpy(c.entity_server_port_num,ptr,sizeof(c.entity_server_port_num));
                    break;
            }
            break;


            // ptr = strtok(NULL, " ");
        }

    }
    
// gcc -g c_common.c c_crypto.c c_secure_comm.c c_api.c -o c_api -lcrypto
    fclose(fp); //close file pointer.
    
    

    printf("c.numkey: %s\n", c.numkey);
    printf("~~\n");
    printf("c.auth_port_num: %s\n", c.auth_port_num);
    printf("~~\n");
    printf("c.entity_port_num: %s\n", c.entity_server_port_num);
    printf("~~\n");

    print_buf(c.auth_port_num,sizeof(c.auth_port_num));

}