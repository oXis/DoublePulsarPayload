CC = x86_64-w64-mingw32-gcc

# Build flags
CFLAGS := -I. -fno-toplevel-reorder -mwindows -fPIC -O0 -nostdlib -Wl,-Tlinker.ld -fpermissive

.PHONY: all
all:
	@$(CC) $(CFLAGS) DoublePulsarShellcode.cpp lzo1z_d1.c -o run.dll
	@objcopy -O binary --only-section=.text run.dll shellcode.bin
	
.PHONY: clean
clean:
	rm *.dll
	rm *.bin
