package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"./Config"
	"./lzoCompress"
)

type Args struct {
	bin       string
	shellcode string
	ord       int64
}

var args *Args

func init() {

	var name string
	flag.StringVar(&name, "bin", "", "exe/dll to transform into shellcode")

	var shellcode string
	flag.StringVar(&shellcode, "shellcode", "", "Shellcode location")

	var ordToCall int64
	flag.Int64Var(&ordToCall, "ord", 1, "ordinal to call")

	flag.Parse()

	args = &Args{bin: name, shellcode: shellcode, ord: ordToCall}
}

func makeHeader() *os.File {
	f, err := os.OpenFile("shellcode.h", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		panic(err)
	}

	f.WriteString("#pragma once\n")
	f.WriteString("unsigned char shellcode[] = {")

	return f
}

func writeHeader(f *os.File, b []byte) {

	for i := range b {
		if i%16 == 0 {
			f.WriteString("\n")
		}
		f.WriteString(fmt.Sprintf("0x%02x,", b[i]))
	}
}

func main() {
	lzoCompress.Init_lzo()

	if len(args.bin) == 0 || len(args.shellcode) == 0 {
		fmt.Println("Usage: defaults.go -name")
		flag.PrintDefaults()
		os.Exit(1)
	}

	data, err := os.ReadFile(args.bin)
	if err != nil {
		panic(err)
	}

	uncompressedBinSize := (uint32)(len(data))

	cData, ierr := lzoCompress.Compress(data)
	if ierr != 0 {
		panic(ierr)
	}

	compressedBinSize := (uint32)(len(cData))

	shellcode, err := os.ReadFile(args.shellcode)
	if err != nil {
		panic(err)
	}

	shellcodeSize := (uint16)(len(shellcode))

	for i := range cData {
		cData[i] ^= Config.KEY_DLL
	}

	for i := range shellcode[Config.SHELLCODE_XOR_OFFSET:] {
		shellcode[Config.SHELLCODE_XOR_OFFSET+i] ^= Config.KEY_SHELLCODE
	}

	shellcodeSizeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(shellcodeSizeBytes, shellcodeSize)
	for i := range shellcodeSizeBytes {
		shellcodeSizeBytes[i] ^= Config.KEY_SHELLCODE
	}
	fmt.Printf("Shellcode size: %v (%02x)\n", shellcodeSize, shellcodeSizeBytes)

	compressedBinSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(compressedBinSizeBytes, compressedBinSize)
	for i := range compressedBinSizeBytes {
		compressedBinSizeBytes[i] ^= Config.KEY_SHELLCODE
	}
	fmt.Printf("Compressed size %v (%02x)\n", len(cData), compressedBinSizeBytes)

	uncompressedBinSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(uncompressedBinSizeBytes, uncompressedBinSize)
	for i := range uncompressedBinSizeBytes {
		uncompressedBinSizeBytes[i] ^= Config.KEY_SHELLCODE
	}
	fmt.Printf("Uncompressed size %v (%02x)\n", len(data), uncompressedBinSizeBytes)

	f := makeHeader()
	defer f.Close()

	writeHeader(f, shellcode)                                                      // Shellcode
	writeHeader(f, shellcodeSizeBytes)                                             // Size of shellcode
	writeHeader(f, []byte{byte(args.ord) ^ Config.KEY_SHELLCODE})                  // Ord to call if dll
	writeHeader(f, compressedBinSizeBytes)                                         // Size of compressed exe/dll file
	writeHeader(f, uncompressedBinSizeBytes)                                       // Size of uncompressed exe/dll file
	writeHeader(f, []byte{'M' ^ Config.KEY_SHELLCODE, 'Z' ^ Config.KEY_SHELLCODE}) // flag to look for
	writeHeader(f, cData)                                                          // pe/dll

	f.WriteString("\n};")
}
