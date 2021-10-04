CC = x86_64-w64-mingw32-gcc

# Build flags
CFLAGS := -mwindows -O0
 
.PHONY: all
all:
	@$(CC) Helper.cpp -o Helper.exe
	
.PHONY: clean
clean:
	rm *.exe