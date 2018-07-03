CC=gcc
CFLAGS=-Isrc/


all: 
	$(CC) $(CFLAGS) src/mimipenguin.c -o mimipenguin
	strip mimipenguin

32: 
	$(CC) $(CFLAGS) src/mimipenguin.c -m32 -o mimipenguin_x32
	strip mimipenguin_x32
clean:
	@rm mimipenguin*

.PHONY: all
