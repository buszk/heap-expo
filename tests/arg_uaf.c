#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vul_func(char *vul) {
    printf("%p\n", &vul);
    free(vul);
    printf("%c\n", *vul);
}

int main() {
    char *g = malloc(10);
    printf("%p: %c\n", &g, *g);
    vul_func(g);
    //printf("%c\n", *g);
}
