package lzoCompress

/*
#cgo CFLAGS: -I../../lzo-2.10/include/
#cgo LDFLAGS: -L../ -llzo2 -Wl,-rpath=./
#include "lzo/lzoconf.h"
#include "lzo/lzo1z.h"

// lzo_init is a macro -- we need a function so we can call it from Go
static int my_lzo_init(void) { return lzo_init(); }

// how big a work buffer do we need to allocate for this algorithm
// again, a macro so we need to be able to call it from Go
static int lzo1z_999_mem_compress() { return LZO1Z_999_MEM_COMPRESS; }
*/
import "C"

import "unsafe"

func Init_lzo() {
	C.my_lzo_init()
}

func lzo1z_999_compress(b []byte, out []byte, out_size *int, wrkmem []byte) C.int {
	return C.lzo1z_999_compress((*C.uchar)(unsafe.Pointer(&b[0])), C.lzo_uint(len(b)),
		(*C.uchar)(unsafe.Pointer(&out[0])), (*C.lzo_uint)(unsafe.Pointer(out_size)),
		unsafe.Pointer(&wrkmem[0]))
}

// for an input of n, what is the worst-case compression we might get
func lzo1z_1_output_size(n int) int {
	return (n + n/16 + 64 + 3)
}

// // Decompress decompresses the byte array b passed in into the byte array o, and returns the size of the valid uncompressed data.
// // If o is not large enough to hold the  compressed data, an error is returned.
// func Decompress(b []byte, o []byte) (uint, int) {

// 	// both and input param (size of 'o') and output param (decompressed size)
// 	out_size := uint(len(o))

// 	err := C.lzo1z_decompress((*C.uchar)(unsafe.Pointer(&b[0])), C.lzo_uint(len(b)),
// 		(*C.uchar)(unsafe.Pointer(&o[0])), (*C.lzo_uint)(unsafe.Pointer(&out_size)), nil)

// 	// decompression failed :(
// 	if err != 0 {
// 		return out_size, int(err)
// 	}

// 	return out_size, 0
// }

// Compress compresses a byte array and returns the compressed stream
func Compress(b []byte) ([]byte, int) {

	// our output buffer, sized to contain a worst-case compression
	out_size := lzo1z_1_output_size(len(b))
	out := make([]byte, out_size)

	out_size = 0 // here it's used to store the size of the compressed data

	var err C.int
	wrkmem := make([]byte, C.lzo1z_999_mem_compress())
	err = lzo1z_999_compress(b, out, &out_size, wrkmem)

	// compression failed :(
	if err != 0 {
		return out[0:out_size], int(err)
	}

	return out[0:out_size], 0
}
