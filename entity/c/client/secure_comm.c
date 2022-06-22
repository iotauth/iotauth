
#include "secure_comm.h"

pthread_t thread[10];

void TCP_connection(int argc, char* argv[], unsigned char  *message, size_t size)
{
        int my_sock;
        struct sockaddr_in serv_addr;
        int str_len;
        if(argc != 3)
        {
            printf("%s <IP> <PORT>\n", argv[0]);
            exit(1);
        }
        my_sock = socket(PF_INET,SOCK_STREAM,0); 
        if(my_sock == -1)
            printf("socket error \n");
        memset(&serv_addr,0,sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
        serv_addr.sin_port=htons(atoi(argv[2]));
        if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2??
            printf("connect error\n");
        while(1)
        {
            str_len = read(my_sock,message,size-1); // message
            if(str_len==-1)
                printf("read error\n");
            printf("str_len : %d\n",str_len);
            print_buf(message,str_len);

            int buffer_len = entity_auth(message, size);
            if(message[0] == SESSION_KEY_REQ_IN_PUB_ENC)
            {
                write(my_sock, message, buffer_len);
            }
            else
            {
                break;
            }
        }

        if(argc != 3)
        {
            printf("%s <IP> <PORT>\n", argv[0]);
            exit(1);
        }
        my_sock = socket(PF_INET,SOCK_STREAM,0); //1
        if(my_sock == -1)
            printf("socket error \n");
        
        serv_addr.sin_port=htons(atoi("21100")); //21100

        if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2
            printf("connect error\n");
        int length = handshake1(message,size);

        write(my_sock, message,length);

        str_len = read(my_sock,message,size-1); // message
        printf("str_len : %d\n", str_len);
        length = handshake2(message,str_len);

        write(my_sock, message,length);


        message_arg *multiple_arg;
        multiple_arg = (message_arg *)malloc(sizeof(message_arg));
        multiple_arg->sock = my_sock;
        pthread_create(thread, NULL, &receive_message, (void *)multiple_arg);
        send_message(my_sock,message);

        free(multiple_arg);
}