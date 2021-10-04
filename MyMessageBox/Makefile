CC = x86_64-w64-mingw32-gcc

# Build flags
CFLAGS := --shared -s -mwindows -Os -Wl,-eDllMain

.PHONY: all
all:
	@$(CC) $(CFLAGS) MyMessageBox.cpp -o MyMessageBox.dll
	
.PHONY: clean
clean:
	rm *.dll