#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define BUFSIZE   512
    
int main(int argc, char **argv) {   

    char **list = (char**) malloc(sizeof(char*) * 100);

    for (int i = 0; i < 100; i++) {
        list[i] = (char*) malloc(16);
    }

    free(list[2]);
    free(list[1]);

    list[2] = (char *) malloc(16);
    char c = *list[1];

    printf("%016lx: %016lx, %016lx, %016lx", (uintptr_t)list, (uintptr_t)list[0], 
            (uintptr_t)list[1], (uintptr_t)list[2]);
    printf("%c\n", c);


}
