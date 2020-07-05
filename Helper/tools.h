#pragma once
#include <Windows.h>

#define KEY_SHELLCODE 0x05
#define KEY_DLL 0x12

// those OFFSET should be changed when the shellcode if modified.
#define SHELLCODE_XOR_OFFSET 70 // from start of the shellcode to SHELLCODE_XOR_OFFSET
#define SHELLCODE_WIPE_OFFSET 50 // from end of the shellcode to SHELLCODE_WIPE_OFFSET

typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;

__inline DWORD getHash(const char* str);

__inline void* mmemcpy(void* dst, const void* src, int size)
{
    if (dst && src && size > 0)
    {
        byte* to = (byte*)dst;
        byte* from = (byte*)src;
        while (size--) *to++ = *from++;
    }
    return dst;
}

__inline void* mmemset(void* ptr, int c, int count)
{
    if (ptr && count > 0)
    {
        volatile byte* p = (byte*)ptr;
        for (int i = 0; i < count; i++, p++)
            *p = c;
    }
    return ptr;
}