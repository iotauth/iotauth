/*
gcc -g server.c common.c -o server -lcrypto -lm
gcc -g server.c common.c secure_server.c auth.c -o server -lcrypto -lm -pthread

./server 21100
*/
/*
.toString('hex').match(/../g).join(' ')
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
node client.js configs/net1/client.config
node client.js configs/net1/client_0.config

node server.js configs/net1/server.config
gcc -g client.c -o client -lcrypto -lm
./client 127.0.0.1 21900
Ubuntu terminator: Ctrl+Shift+w: close, Ctrl+Shift+e: , Ctrl+Shift+o: horizontally
Window terminal: Alt+Shift++, Alt+Shift+-, Alt+Shift+arrows: resize
*/

#include "common.h"
#include "secure_server.h"

void initialize_server(int options);

int main(int argc, char * argv[]){
    client_list.client_list_length = 0;
    pthread_create(&p_thread[0], NULL, &scan_command, NULL);
    initialize_server(1); //TODO: options =1 
    return 0;
}

void initialize_server(int options){
    if(options == 1){ //TCP = 1
        initialize_TCP_server();
        return;
    }
    if(options == 2){ //UDP = 2
        initialize_UDP_server();
        return;
    }
    else{
        error_handling("check options");
    }
}
