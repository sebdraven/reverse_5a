#include <stdio.h>

#include <stdio.h>

int copy_string(char *dest, char *src) {
    int count = 0;
    while (*src) {
        *dest = *src;
        src++;
        dest++;
        count++;
    }
    *dest = '\0';
    return count;
}

int main() {
    char src[] = "Hello, world!";
    char dest[100];

    int count = copy_string(dest, src);

    printf("Source string: %s\n", src);
    printf("Destination string: %s\n", dest);
    printf("Number of characters copied: %d\n", count);

    return 0;
}
