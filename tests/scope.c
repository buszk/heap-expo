#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define BUFSIZE   512

int main(int argc, char **argv) {   

    int input = 10;

    if (input >= 10) {
        char *p1;
        p1 = malloc(8);
        free(p1);
    }

    if (input > 5) {
        int flag;
        free(0);
        
    }


}
