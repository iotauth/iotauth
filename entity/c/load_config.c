#include <stdio.h>
#include <string.h> 
#include <stdlib.h>
#include "load_config.h"


const char entity_info_name[] = "entityInfo.name";
const char entity_info_purpose[] = "entityInfo.purpose";
const char entity_info_numkey[] = "entityInfo.number_key";
const char authinfo_pubkey_path[] = "authInfo.pubkey.path";
const char entity_info_privkey_path[] = "entityInfo.privkey.path";
const char authInfo_ip_address[] = "auth.ip.address" ;
const char authInfo_port[] = "auth.port.number" ;
const char entity_serverInfo_ip_address[] = "entity.server.ip.address" ;
const char entity_serverInfo_port_number[] = "entity.server.port.number" ;



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



config * load_config(char * path) 
{
    config *c = malloc(sizeof(config));
    FILE* fp = fopen(path, "r");  //test파일을 r(읽기) 모드로 열기
    char buffer[MAX] = { 0, };
    char *pline;

    printf("--config 내용--\n");
    // file_log("a.config");
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
                    printf("name: %s", ptr);
                    memcpy(c->name, ptr, sizeof(c->name));
                    break;
                case EIP:
                    ptr = strtok(NULL, " ");
                    printf("purpose: %s", ptr);
                    memcpy(c->purpose,ptr,sizeof(c->purpose));
                    break;
                case EINK:
                    ptr = strtok(NULL, " ");
                    printf("Numkey: %s", ptr);
                    memcpy(c->numkey,ptr,sizeof(c->numkey));
                    break;
                case AIPP:
                    ptr = strtok(NULL, " ");
                    printf("Pubkey path of Auth: %s", ptr);
                    memcpy(c->auth_pubkey_path, ptr, sizeof(c->auth_pubkey_path));
                    break;
                case EIPP:
                    ptr = strtok(NULL, " ");
                    printf("Privkey path of Entity: %s", ptr);
                    memcpy(c->entity_privkey_path, ptr, sizeof(c->entity_privkey_path));
                    break;
                case AIIA:
                    ptr = strtok(NULL, " ");
                    printf("IP address of Auth: %s", ptr);
                    memcpy(c->auth_ip_addr, ptr, sizeof(c->auth_ip_addr));
                    break;
                case AIP:
                    ptr = strtok(NULL, " ");
                    printf("Port number of Auth: %s", ptr);
                    memcpy(c->auth_port_num,ptr,sizeof(c->auth_port_num));
                    break;
                case ESIIP:
                    ptr = strtok(NULL, " ");
                    printf("IP address of entity server: %s", ptr);
                    memcpy(c->entity_server_ip_addr, ptr, sizeof(c->entity_server_ip_addr));
                    break;
                case ESIP:
                    ptr = strtok(NULL, " ");
                    printf("Port number of entity server: %s\n", ptr);
                    memcpy(c->entity_server_port_num,ptr,sizeof(c->entity_server_port_num));
                    break;
            }
            break;
        }
    }
    fclose(fp); //파일 포인터 닫기
    return c;
}


// How to use//
// void main()
// {
//     char path[] = "a.config";
//     config * config_info = load_config(path);
// }
