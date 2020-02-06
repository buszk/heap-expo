#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define BUFSIZE   512
    

int main(int argc, char **argv) {   
    char *buf1;
    char *buf2;
    char *buf3;

    buf1 = (char *) malloc(BUFSIZE);
    buf2 = (char *) malloc(BUFSIZE);

    buf2[0] = '2';

    free(buf2);

    buf3 = (char *) malloc(BUFSIZE);
    char *bufd = (char *) malloc(BUFSIZE);
    *buf3 = '3';
    char c = *buf2;

    printf("%p: %c, %d\n", buf2, c, c);

}


