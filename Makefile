CC=gcc
CFLAGS=-Wall -std=c2x -g -fsanitize=address
LDFLAGS=-lm -pthread
TESTFLAGS=-Wall -Werror -fprofile-arcs -ftest-coverage
INCLUDE=-Iinclude
CMOCKALIB=-Xlinker libs/libcmocka-static.a
FILES=src/chk/pkgchk.c src/crypt/sha256.c src/add/inputs.c src/add/keys.c

.PHONY: clean

# default rule
build: pkgmain

pkgmain: src/pkgmain.c $(FILES)
	$(CC) $^ $(INCLUDE) $(CFLAGS) $(LDFLAGS) -o $@

# tests
test:
	bash test.sh

testing: tests/testing.c $(FILES)
	$(CC) $^ $(INCLUDE) $(LDFLAGS) $(TESTFLAGS) $(CMOCKALIB) -o $@ 
	$(CC) src/pkgmain.c $(FILES) $(INCLUDE) $(LDFLAGS) $(TESTFLAGS) $(CMOCKALIB) -o pkgchk

pkgchecker: src/pkgmain.c src/chk/pkgchk.c
	$(CC) $^ $(INCLUDE) $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f pkgmain

clean-tests:
	rm -f testing pkgchk *.gcno *gcda *.c.gcov

