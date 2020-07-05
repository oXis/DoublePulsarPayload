#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <malloc.h>

#ifdef _M_AMD64
#include <intrin.h>
#elif defined(_M_ARM)
#include <armintr.h>
#endif

#define hashKERNEL32 0x6e2bca17
#define hashLoadLibraryA 0x8a8b4676
#define hashGetProcAddress 0x1acaee7a
#define hashVirtualAlloc 0x302ebe1c
#define hashVirtualProtect 0x1803b7e3
#define hashVirtualFree 0xe183277b
#define hashRtlAddFunctionTable 0xb11a8928

#define hashCreateThread 0x68a8c443
#define hashCreateRemoteThread 0x11a0eb1
#define hashWaitForSingleObject 0x5c62ca81
#define hashGetModuleHandleA 0x61eebcec

#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))

FARPROC WINAPI GetExportAddress(HMODULE hMod, DWORD lpProcNameHash);
HMODULE WINAPI GetModuleBaseAddress(DWORD moduleNameHash);

typedef int (WINAPI* typemainCRTStartup)(void);

typedef BOOL (APIENTRY* typeDllEntryProc)(HINSTANCE hModule, DWORD dwReason, LPVOID);
typedef HMODULE (WINAPI* typeLoadLibraryA)(LPCSTR lpFileName);
typedef FARPROC (WINAPI* typeGetProcAddressA)(HMODULE hModule, LPCSTR  lpProcName);
typedef LPVOID (WINAPI* typeVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* typeVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL (WINAPI* typeVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOLEAN (__cdecl* typeRtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

typedef HMODULE (WINAPI* typeGetModuleHandleA)(LPCSTR lpModuleName);

typedef HANDLE (WINAPI* typeCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef HANDLE (WINAPI* typeCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef DWORD (WINAPI* typeWaitForSingleObject)(HANDLE hHandle, DWORD  dwMilliseconds);


inline BOOL IsOrdinal(UINT_PTR pvTest)
{
    CONST UINT_PTR MASK = ~(UINT_PTR(0xFFFF));
    return (pvTest & MASK) == 0 ? TRUE : FALSE;
}

inline PPEB GetPEB()
{
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

inline PIMAGE_NT_HEADERS GetNTHeaders(HMODULE imageBase)
{
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)imageBase;
    return (PIMAGE_NT_HEADERS)((SIZE_T)imageBase + dos_header->e_lfanew);
}

inline PIMAGE_OPTIONAL_HEADER GetOptionalHeader(HMODULE imageBase)
{
    return (PIMAGE_OPTIONAL_HEADER)((LPVOID)((SIZE_T)imageBase + ((PIMAGE_DOS_HEADER)(imageBase))->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)));
}

//#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader) + ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))