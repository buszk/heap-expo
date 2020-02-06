
#include <stdlib.h>
#include <stdio.h>
struct st{
    union{
    int a;
    char* p;
    }u;
};

void f(struct st ob) {
    free(ob.u.p);
}
int main() {
    struct st ob, cp;
    ob.u.p = malloc(10);
    cp = ob;
    f(ob);
    char c = *cp.u.p;
    printf("%c", c);
}
