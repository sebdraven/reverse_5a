#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <Windows.h>
#include <strsafe.h>

int addition(int a, int b) {
    return a + b;
}

char* concatenation(char* str1, char* str2) {
    size_t str1Len = strlen(str1);
    size_t str2Len = strlen(str2);
    size_t concatLen = str1Len + str2Len + 1;
    char* result = VirtualAlloc(NULL, concatLen, MEM_COMMIT, PAGE_READWRITE);
    if (result == NULL) {
        return NULL;
    }
    StringCchCopy(result, concatLen, str1);
    StringCchCat(result, concatLen, str2);
    return result;
}

int main() {
    int a = 5;
    int b = 7;
    int sum = addition(a, b);
    printf("The sum of %d and %d is %d\n", a, b, sum);

    char* str1 = "Hello, ";
    char* str2 = "world!";
    char* concat = concatenation(str1, str2);
    if (concat == NULL) {
        printf("Error: failed to allocate memory for concatenation\n");
        return 1;
    }
    printf("The concatenation of \"%s\" and \"%s\" is \"%s\"\n", str1, str2, concat);

    char buffer[256];
    sprintf(buffer, "The sum of %d and %d is %d", a, b, sum);

    free(concat);
    return 0;
}
