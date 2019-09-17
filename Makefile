CC=gcc
CFLAGS=-Iinclude/ -D_FILE_OFFSET_BITS=64
LDFLAGS=-lcrypt

all: 
	@$(CC) $(CFLAGS) src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin $(LDFLAGS)

debug: 
	@$(CC) $(CFLAGS) -DDEBUG src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin $(LDFLAGS)
clean:
	@rm mimipenguin

.PHONY: all
