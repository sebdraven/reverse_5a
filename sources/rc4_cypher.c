#include <stdio.h>
#include <stdint.h>
#include <string.h>

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

void rc4(uint8_t *plaintext, uint8_t *ciphertext, int length, const uint8_t *key, int key_length) {
    uint8_t s[KEY_LENGTH];
    initialize_sbox(s, key, key_length);

    int i = 0, j = 0;
    for (int pos = 0; pos < length; pos++) {
        i = (i + 1) % KEY_LENGTH;
        j = (j + s[i]) % KEY_LENGTH;
        swap(&s[i], &s[j]);
        uint8_t t = (s[i] + s[j]) % KEY_LENGTH;
        ciphertext[pos] = plaintext[pos] ^ s[t];
    }
}

int main() {
    uint8_t key[] = "examplekey";
    uint8_t message[] = "Hello, World!";
    uint8_t encrypted[sizeof(message)];
    uint8_t decrypted[sizeof(message)];

    rc4(message, encrypted, sizeof(message), key, sizeof(key) - 1);
    rc4(encrypted, decrypted, sizeof(message), key, sizeof(key) - 1);

    printf("Original:   %s\n", message);
    printf("Encrypted:  ");
    for (int i = 0; i < sizeof(message); i++) {
        printf("%02X ", encrypted[i]);
    }
    printf("\nDecrypted:  %s\n", decrypted);

    return 0;
}
