#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void* my_realloc(void* ptr, size_t size) {
    void* ptr1 = malloc(size);
    memcpy(ptr1, ptr, 100);
    free(ptr);
    return ptr1;
}
int main() {

    char* p1 = malloc(100);
    void* p2 = my_realloc(p1, 200);
    *p1 = 'a';
    printf("%016lx\n", (unsigned long)p1);
    return 0;
    
}
