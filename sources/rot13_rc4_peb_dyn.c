#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define KEY_LENGTH 256

// Définitions pour accéder à la structure du PEB
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    char* FullDllName;
    char* BaseDllName;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

FARPROC GetProcAddressFromPEB(HMODULE hModule, const char* funcName) {
    PPEB peb = (PPEB)__readfsdword(0x30); // Obtenir le PEB du processus en cours
    PLDR_MODULE ldrModule = (PLDR_MODULE)peb->Ldr->InMemoryOrderModuleList.Flink;
    HMODULE kernel32Base = NULL;

    while (ldrModule->BaseAddress) {
        if (strstr(ldrModule->BaseDllName, "kernel32.dll"))
 {
            kernel32Base = (HMODULE)ldrModule->BaseAddress;
            break;
        }
        ldrModule = (PLDR_MODULE)ldrModule->InMemoryOrderModuleList.Flink;
    }

    if (!kernel32Base) return NULL;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)kernel32Base;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)kernel32Base + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)kernel32Base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* namePtr = (DWORD*)((DWORD_PTR)kernel32Base + exportDirectory->AddressOfNames);
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* currentFuncName = (char*)((DWORD_PTR)kernel32Base + namePtr[i]);
        if (strcmp(currentFuncName, funcName) == 0) {
            WORD ordinal = ((WORD*)((DWORD_PTR)kernel32Base + exportDirectory->AddressOfNameOrdinals))[i];
            DWORD funcRVA = ((DWORD*)((DWORD_PTR)kernel32Base + exportDirectory->AddressOfFunctions))[ordinal];
            return (FARPROC)((DWORD_PTR)kernel32Base + funcRVA);
        }
    }

    return NULL;
}

// Fonctions RC4 et ROT13
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

    // Utilisez les pointeurs de fonction pour appeler les fonctions d'API Windows
    BOOL (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = GetProcAddressFromPEB(GetModuleHandleA("kernel32.dll"), "ReadFile");
    BOOL (WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = GetProcAddressFromPEB(GetModuleHandleA("kernel32.dll"), "WriteFile");

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

    char funcName1[] = "YbnqYvoenelA";  // "LoadLibraryA" after rot13 decode
    char funcName2[] = "TrgZhgubyngureNcc"; // "GetModuleHandleA" after rot13 decode
    rot13_decode(funcName1);
    rot13_decode(funcName2);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE (WINAPI *pLoadLibraryA)(const char *) = (HMODULE (WINAPI *)(const char *))GetProcAddressFromPEB(hKernel32, funcName1);
    HANDLE (WINAPI *pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = (HANDLE (WINAPI *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddressFromPEB(pLoadLibraryA("kernel32.dll"), "CreateFileA");
    HANDLE (WINAPI *pCloseHandle)(HANDLE) = (HANDLE (WINAPI *)(HANDLE))GetProcAddressFromPEB(pLoadLibraryA("kernel32.dll"), "CloseHandle");

    HANDLE hInputFile = pCreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE) {
        perror("Failed to open input file");
        return 1;
    }

    HANDLE hOutputFile = pCreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE) {
        pCloseHandle(hInputFile);
        perror("Failed to open or create output file");
        return 1;
    }

    rc4_process_file(hInputFile, hOutputFile, (uint8_t *)argv[4], strlen(argv[4]));

    pCloseHandle(hInputFile);
    pCloseHandle(hOutputFile);

    return 0;
}
