package Config

const KEY_SHELLCODE = 0x05
const KEY_DLL = 0x12

// those OFFSET should be changed when the shellcode if modified.
const SHELLCODE_XOR_OFFSET = 70  // from start of the shellcode to SHELLCODE_XOR_OFFSET
const SHELLCODE_WIPE_OFFSET = 50 // from end of the shellcode to SHELLCODE_WIPE_OFFSET
