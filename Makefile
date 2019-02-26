all: dump

dump: dump.c adump.c

clean:
	rm -f dump

.PHONY: clean
