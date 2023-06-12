#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    printf("You passed in %d arguments:\n", argc-1);
    for (int i = 1; i < argc; i++) {
        int value = atoi(argv[i]);
        printf("%d ", value);
    }
    printf("\n");
    return 0;
}

