
#include <stdlib.h>
#include <stdio.h>
struct  st{
    volatile char* p;
    int abc;

};

void f(struct  st ob) {
    free(ob.p);
}

struct  st cp;

int main() {
    struct  st ob;
    cp.p = malloc(10);
    ob = cp;
    f(cp);
    char c = *ob.p;
    printf("%c", c);
}
