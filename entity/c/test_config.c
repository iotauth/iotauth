#include "load_config.h"
#include "c_common.h"
int main(int argc, char* argv[])
{

    char path[] = "a.config";
    config_t * config_info = load_config(path);

    printf("오류\n");
    print_buf(config_info->auth_ip_addr, strlen(config_info->auth_ip_addr));
    printf("오류\n");
    print_buf(config_info->auth_port_num, sizeof(config_info->auth_port_num));
    printf("오류\n");
    print_buf(config_info->auth_pubkey_path,strlen(config_info->auth_pubkey_path));
    printf("오류\n");
    print_buf(config_info->entity_privkey_path,strlen(config_info->entity_privkey_path));
    printf("오류\n");
    print_buf(config_info->entity_server_ip_addr,strlen(config_info->entity_server_ip_addr));
    printf("오류\n");
    print_buf(config_info->entity_server_port_num,sizeof(config_info->entity_server_port_num));
    printf("오류\n");
    print_buf(config_info->name,strlen(config_info->name));
    printf("오류\n");
    print_buf(config_info->numkey,sizeof(config_info->numkey));
    printf("오류\n");
    print_buf(config_info->purpose,strlen(config_info->purpose));
    printf("오류\n");

    printf("\n\n\n\n\n");

     int my_sock;
    struct sockaddr_in serv_addr;
    int str_len;

    my_sock = socket(PF_INET,SOCK_STREAM,0); 
    if(my_sock == -1)
        printf("socket error \n");
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
    printf("addr: %d \n",serv_addr.sin_addr.s_addr);
    serv_addr.sin_addr.s_addr=inet_addr(config_info->auth_ip_addr);
    printf("addr: %d \n",serv_addr.sin_addr.s_addr);
    serv_addr.sin_port=htons(atoi(argv[2]));
    printf("port num: %d \n", serv_addr.sin_port);
    serv_addr.sin_port=htons(atoi(config_info->auth_port_num));
    printf("port num: %d \n", serv_addr.sin_port);
    
    if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2??
        printf("connect error\n");
    unsigned char message[1000];
    memset(message,0x00,sizeof(message));
    str_len = read(my_sock,message,sizeof(message)-1); // message
    if(str_len==-1)
        printf("read error\n");
    if(message[0] == 0)
    {
        printf("Received AUTH_HELLO Message!!! \n");
        printf("Receiving message from Auth : ");
        print_buf(message, str_len);
    }

}