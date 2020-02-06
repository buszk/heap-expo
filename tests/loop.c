#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define BUFSIZE   512

char* a;

int main(int argc, char **argv) {   

    for (int i = 0; i < 100; i++) {
        a = malloc(100);
    } 
    return 0;

}
