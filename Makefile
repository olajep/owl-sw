all: dump

CFLAGS ?= -Wall -Wextra

dump: dump.c adump.c

clean:
	rm -f dump

.PHONY: clean
