#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define KEY_LENGTH 256

void swap(uint8_t *a, uint8_t *b) {
    uint8_t tmp = *a;
    *a = *b;
    *b = tmp;
}

void initialize_sbox(uint8_t s[KEY_LENGTH], const uint8_t *key, int key_length) {
    int j = 0;
    for (int i = 0; i < KEY_LENGTH; i++) {
        s[i] = i;
    }

    for (int i = 0; i < KEY_LENGTH; i++) {
        j = (j + s[i] + key[i % key_length]) % KEY_LENGTH;
        swap(&s[i], &s[j]);
    }
}

void rc4_process_file(HANDLE input, HANDLE output, const uint8_t *key, int key_length) {
    uint8_t s[KEY_LENGTH];
    initialize_sbox(s, key, key_length);

    int i = 0, j = 0;
    uint8_t in_byte, out_byte;
    DWORD bytesRead, bytesWritten;

    while (ReadFile(input, &in_byte, 1, &bytesRead, NULL) && bytesRead > 0) {
        i = (i + 1) % KEY_LENGTH;
        j = (j + s[i]) % KEY_LENGTH;
        swap(&s[i], &s[j]);
        uint8_t t = (s[i] + s[j]) % KEY_LENGTH;
        out_byte = in_byte ^ s[t];
        WriteFile(output, &out_byte, 1, &bytesWritten, NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <input_file> <output_file> <key>\n", argv[0]);
        return 1;
    }

    const char *input_filename = argv[1];
    const char *output_filename = argv[2];
    const char *key = argv[3];

    HANDLE input_file = CreateFile(input_filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening input file: %lu\n", GetLastError());
        return 1;
    }

    HANDLE output_file = CreateFile(output_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening output file: %lu\n", GetLastError());
        CloseHandle(input_file);
        return 1;
    }

    rc4_process_file(input_file, output_file, (uint8_t *)key, strlen(key));

    CloseHandle(input_file);
    CloseHandle(output_file);

    return 0;
}
