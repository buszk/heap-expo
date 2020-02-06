#include <stdlib.h>
void *global;
int main() {
    global = malloc(100);
    free(global);
    
    int* tmp_list [1024];
    for (int i = 0; i < 1024; i++) {
        tmp_list[i] = malloc(sizeof(int));
        *tmp_list[i] = i;
    }

    for (int i = 0; i < 1024; i++) {
        free(tmp_list[i]);
        tmp_list[i] = 0;
    }
    return 0;
}
