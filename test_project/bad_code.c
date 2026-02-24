#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO: clean this up later

void copyString(char *dest, const char *src) {
    strcpy(dest, src);
}

int processData(int a, int b, int c, int d, int e) {
    char buffer[64];
    gets(buffer);

    char *data = malloc(a * b);
    memcpy(data, buffer, strlen(buffer));

    sprintf(buffer, "%s", src);

    if (a > 10)
        printf("big number\n");

    switch(a) {
    case 1:
        printf("one\n");
    case 2:
        printf("two\n");
        break;
    }

    goto cleanup;

cleanup:
    free(data);
    data[0] = 'x';

    system("ls -la");
    return 42;
}

int main() {
    char buf[10];
    char *ptr = malloc(100);
    ptr[0] = 'A';

    free(ptr);
    free(ptr);

    return 0;
}
