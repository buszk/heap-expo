#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#define INLINE __attribute__((noinline)) 
#define INLINE
void INLINE vul_func(char **vul) {
    free(*vul);
    printf("%c\n", **vul);
}
char *g;

int main() {
    char **ref;
    g = malloc(10);
    printf("%c\n", *g);
    ref = &g;
    vul_func(ref);
    //printf("%c\n", *g);
}
