CC=gcc
STRIP=strip --strip-unneeded
CFLAGS=-Iinclude/ -D_FILE_OFFSET_BITS=64 -O3 -Wno-unused-result
LDFLAGS=-lcrypt

all: 
	@$(CC) $(CFLAGS) src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin $(LDFLAGS)
	@$(CC) $(CFLAGS) -m32 src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin_x32 $(LDFLAGS)
	@$(STRIP) mimipenguin
	@$(STRIP) mimipenguin_x32

static: 
	@$(CC) $(CFLAGS) -static src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin $(LDFLAGS)
	@$(CC) $(CFLAGS) -m32 -static src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin_x32 $(LDFLAGS)
	@$(STRIP) mimipenguin
	@$(STRIP) mimipenguin_x32
debug: 
	@$(CC) $(CFLAGS) -DDEBUG src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin $(LDFLAGS)
	@$(CC) $(CFLAGS) -m32 -DDEBUG src/scanner.c src/users.c src/targets.c src/mimipenguin.c -o mimipenguin_x32 $(LDFLAGS)

clean:
	@rm mimipenguin
	@rm mimipenguin_x32

.PHONY: all
