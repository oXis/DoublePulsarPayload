// DoublePulsarPayload.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "stdio.h"
#include "tools.h"

int main() {
    printf("[?] KERNEL32.DLL: 0x%x\n", getHash("KERNEL32.DLL"));
    printf("[?] LoadLibraryA: 0x%x\n", getHash("LoadLibraryA"));
    printf("[?] GetProcAddress: 0x%x\n", getHash("GetProcAddress"));
    printf("[?] VirtualAlloc: 0x%x\n", getHash("VirtualAlloc"));
    printf("[?] VirtualProtect: 0x%x\n", getHash("VirtualProtect"));
    printf("[?] VirtualFree: 0x%x\n", getHash("VirtualFree"));
    printf("[?] RtlAddFunctionTable: 0x%x\n", getHash("RtlAddFunctionTable"));

    printf("[?] CreateThread: 0x%x\n", getHash("CreateThread"));
    printf("[?] CreateRemoteThread: 0x%x\n", getHash("CreateRemoteThread"));
    printf("[?] WaitForSingleObject: 0x%x\n", getHash("WaitForSingleObject"));
    printf("[?] GetModuleHandleA: 0x%x\n", getHash("GetModuleHandleA"));

    printf("[+] Done!\n");
}
