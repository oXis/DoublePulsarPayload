# Intro

After reading the f-secure [blog post](https://blog.f-secure.com/doublepulsar-usermode-analysis-generic-reflective-dll-loader/) about DoublePulsar usermode shellcode, I wanted to reproduce it purely in C++. I am no way near to be a C++ guru or l33t hacker but I thought that would be a good exercice.

The blog breaks down the steps taken by the shellcode.

    1. A call-pop is used to self-locate so the shellcode can use static offsets from this address.
    2. Required Windows API functions are located by matching hashed module names, and looping through and exported function to match hashed function names.
    3. The DLL headers are parsed for key metadata.
    4. Memory is allocated of the correct size, at the preferred base address if possible. Any offset from the preferred base address is saved for later use.
    5. Each section from the DLL is copied into the appropriate offset in memory.
    6. Imports are processed, with dependent libraries loaded (using LoadLibrary) and the Import Address Table (IAT) is filled in.
    7. Relocations are processed and fixed up according to the offset from the preferred base address.
    8. Exception (SEH) handling is set up with RtlAddFunctionTable.
    9. Each section’s memory protections are updated to appropriate values based on the DLL headers.
    10. DLLs entry point is called with DLL_PROCESS_ATTACH.
    11. The requested ordinal is resolved and called.
    12. After the requested function returns, the DLL entry point is called with DLL_PROCESS_DETACH.
    13. RtlDeleteFunctionTable removed exception handling.
    14. The entire DLL in memory is set to writable, and zeroed out.
    15. The DLLs memory is freed.
    16. The shellcode then zeros out itself, except for the very end of the function, which allows the APC call to return gracefully.

Furthermore, I wanted to add a bit a compression, and XOR obfuscation.

# DoublePulsarPayload

I used Visual Studio 2019 Community on Windows 7.

## DoublePulsarShellcode
Code of the shellcode. This is basically yet another reflective DLL loader. The shellcode is XOR encrypted with a key, the compressed DLL is also XOR encrypted but with a different key.

`map.txt` gives us the offset of the shellcode functions inside the PE file. It's used but `ExtractShellcode.exe`

## ExtractShellcode
Open `MyMessageBox.dll` and `DoublePulsarShellcode.exe`. The DLL is LZO compressed. The code then dumps all the bytes in a header file.

The shellcode is organisze that way.
```
|----------------------|
|        XORed         |
|      SHELLCODE       |
|                      |
|                      |
|----------------------|
| sizeShellcode        |
|----------------------|
| ordToCall            |
|----------------------|
| compressedSizeDllFile|
|----------------------|
| sizeDllFile          |
|----------------------|
| flag                 |
|----------------------|
|      Compressed      |
|        XORed         |
|         DLL          |
|                      |
|                      |
|                      |
|                      |
|----------------------|
```

At the end of execution, the shellcode Free and Zero the loaded DLL, the compressed DLL and also it's own memory up to a certain offset to allow graceful return.

ExtractShellcode requires `lzo.lib`, so grab a copy of LZO and compile it. Then change
`#include "../../lzo-2.06/include/lzo/lzo1z.h"` and `#pragma comment(lib, "../Release/lzo-2.06.lib")`
to the correct location.

Run this command to extract the shellcode. `shellcode.bin` contains raw shellcode bytes.
`.\ExtractShellcode.exe ..\..\DoublePulsarShellcode\map.txt ..\..\RunShellcode\shellcode.h`

## Helper
Contains headers for the shellcode and also print hash of WinAPI functions
## MyMessageBox
DLL to include.
## RunShellcode
Code to test the shellcode. It just loads it and jump to it. This code depends on all of the previous projects, so if you compile first, Visual Studio will compile all required projects and also run `ExtractShellcode.exe` for you.

# Credit
Stephen Fewer for the Reflective DLL loader technique. Many others that posted code on Github.
And of course, The Shadow Brokers and the National Security Agency ;).

# Licence
DoublePulsarePayload is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of
the License, or (at your option) any later version.

DoublePulsarePayload is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DoublePulsarePayload; see the file LICENCE.
If not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.