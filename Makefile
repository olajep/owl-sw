CC  := gcc
AR  := $(CROSS_COMPILE)$(AR)
AS  := $(CROSS_COMPILE)$(AS)
CC  := $(CROSS_COMPILE)$(CC)
CXX := $(CROSS_COMPILE)$(CXX)
CPP := $(CROSS_COMPILE)$(CPP)

CANONICAL_TARGET ?= riscv64-unknown-linux-gnu-

CFLAGS ?= -Wall -Wextra -g -O0

TARGETS = dump owl mininit
all: $(TARGETS)

# Remove when owl.h becomes stable and lives in sysroot/usr/include
dump.o owl.o: owl.h

dump: dump.o source_hashmap.o
dump.o: syscalltable.h mcalltable.h source_hashmap.h

dump:
	$(CC) $^ -o $@ -lstdc++

offs2vaddr: offs2vaddr.o

syscalltable.h: syscalltable-gen.h
GENERATED = syscalltable-gen.h
syscalltable-gen.h: syscalltable-in.h
	$(CANONICAL_TARGET)cpp $< -o $@

owl: owl.o

mininit: mininit.c
	$(CANONICAL_TARGET)gcc $(CFLAGS) -static $^ -o $@
	$(CANONICAL_TARGET)strip -g $@


clean:
	rm -f $(TARGETS) $(GENERATED) *.o

.PHONY: clean
