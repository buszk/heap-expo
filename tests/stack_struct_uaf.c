
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
    struct st ob;
    ob.u.p = malloc(10);
    f(ob);
    char c = *ob.u.p;
    printf("%c", c);
}
