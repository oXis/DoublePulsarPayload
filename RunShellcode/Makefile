CC = x86_64-w64-mingw32-gcc

# Build flags
CFLAGS := -mconsole

.PHONY: all
all:
	@$(CC) $(CFLAGS) RunShellcode.cpp -o RunShellcode.exe
	
.PHONY: clean
clean:
	rm *.exe