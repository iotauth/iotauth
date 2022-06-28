#include <stdio.h>
#include <string.h> 
#include <stdlib.h>


#define SESSION_KEY_EXPIRATION_TIME_SIZE 6 // validity size;

long int validity_st_time = 0; // default number of communication starting time.
int seq_num = 0; // default number of sender's sequence.
// input(start_time, sequence number, relative validity, absolute validity)
int time_validity(long int st_time, int seq_n, unsigned char *rel_validity, unsigned char *abs_validity )
{
    if( seq_n == 0 && st_time == 0)
    {       
        st_time = time(NULL);
    }
    unsigned long int num_valid =1LU;
    for(int i =0; i<SESSION_KEY_EXPIRATION_TIME_SIZE;i++)
    {
        unsigned long int num =1LU << 8*(SESSION_KEY_EXPIRATION_TIME_SIZE-1-i); 
        num_valid |= num*abs_validity[i];
    }
    printf("abs_valid : %ld\n", num_valid);
    num_valid = num_valid/1000;
    long int relvalidity = read_variable_UInt(rel_validity, 0, 6)/1000;
    if(time(NULL) > num_valid || time(NULL) - st_time >relvalidity)
    {
        printf("session key is expired");
        return 0;
    }
    else
    {
        return 1;
    }
}


int main()
{
    

}