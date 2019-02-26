all: dump

CFLAGS ?= -Wall -Wextra

dump: dump.c

clean:
	rm -f dump

.PHONY: clean
