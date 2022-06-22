#include <stdio.h>

void ReadXBytes(int socket, unsigned int x, void* buffer)
{
    int bytesRead = 0;
    int result;
    while (bytesRead < x)
    {
        result = read(socket, buffer + bytesRead, x - bytesRead);
        if (result < 1 )
        {
            // Throw your error.
        }

        bytesRead += result;
    }
}

int main(){
    printf("hello world\n");
    unsigned char temp [8];
    read(socket, temp, sizeof(temp));
    
    long int length = 0; //8byte
    char* buffer = 0;
    printf("%d\n", sizeof(temp) );

    // we assume that sizeof(length) will return 4 here.
//     ReadXBytes(socketFileDescriptor, sizeof(length), (void*)(&length));
//     buffer = new char[length];
//     ReadXBytes(socketFileDescriptor, length, (void*)buffer);
}