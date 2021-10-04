// RunShellcode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>

#include "../ExtractShellcode/shellcode.h"
#include <stdio.h>

int main() {

    printf("Running shellcode...\n");

    int size = sizeof(shellcode) / sizeof(shellcode[0]);
    LPVOID ptr = (LPVOID)VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    memcpy(ptr, shellcode, size);

    ((void(*)())ptr)();

    printf("Shell code returned gracefully\n");
    return 0;
}