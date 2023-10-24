#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define KEY_LENGTH 256

// Pointers to the functions
HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL (WINAPI *pCloseHandle)(HANDLE);

void swap(uint8_t *a, uint8_t *b) {
    uint8_t tmp = *a;
    *a = *b;
    *b = tmp;
}

void rot13_decode(char *str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] = 'a' + (str[i] - 'a' + 13) % 26;
        } else if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = 'A' + (str[i] - 'A' + 13) % 26;
        }
    }
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

    while (pReadFile(input, &in_byte, 1, &bytesRead, NULL) && bytesRead > 0) {
        i = (i + 1) % KEY_LENGTH;
        j = (j + s[i]) % KEY_LENGTH;
        swap(&s[i], &s[j]);
        uint8_t t = (s[i] + s[j]) % KEY_LENGTH;
        out_byte = in_byte ^ s[t];
        pWriteFile(output, &out_byte, 1, &bytesWritten, NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s -e/-d <input_file> <output_file> <key>\n", argv[0]);
        return 1;
    }

    char loadLibraryFuncName[] = "YbnqYvoenelN";
    rot13_decode(loadLibraryFuncName);
    pLoadLibraryA = (HMODULE (WINAPI *)(LPCSTR))GetProcAddress(GetModuleHandle("kernel32.dll"), loadLibraryFuncName);

    char getProcAddressFuncName[] = "TrgCebsbezNqqerff";
    rot13_decode(getProcAddressFuncName);
    pGetProcAddress = (FARPROC (WINAPI *)(HMODULE, LPCSTR))GetProcAddress(GetModuleHandle("kernel32.dll"), getProcAddressFuncName);

    HMODULE hKernel32 = pLoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        fprintf(stderr, "Failed to load kernel32.dll\n");
        return 1;
    }

    char createFileFuncName[] = "PernxSvyrN";
    rot13_decode(createFileFuncName);
    pCreateFileA = (HANDLE (WINAPI *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))pGetProcAddress(hKernel32, createFileFuncName);

    char readFileFuncName[] = "ErnqSvyr";
    rot13_decode(readFileFuncName);
    pReadFile = (BOOL (WINAPI *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))pGetProcAddress(hKernel32, readFileFuncName);

    char writeFileFuncName[] = "JevgrSvyr";
    rot13_decode(writeFileFuncName);
    pWriteFile = (BOOL (WINAPI *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))pGetProcAddress(hKernel32, writeFileFuncName);

    char closeHandleFuncName[] = "PybfrUnaqyr";
    rot13_decode(closeHandleFuncName);
    pCloseHandle = (BOOL (WINAPI *)(HANDLE))pGetProcAddress(hKernel32, closeHandleFuncName);

    HANDLE hInputFile = pCreateFileA(argv[2], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hOutputFile = pCreateFileA(argv[3], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hInputFile == INVALID_HANDLE_VALUE || hOutputFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open input or output file.\n");
        return 1;
    }

    rc4_process_file(hInputFile, hOutputFile, (uint8_t *)argv[4], strlen(argv[4]));

    pCloseHandle(hInputFile);
    pCloseHandle(hOutputFile);

    return 0;
}
