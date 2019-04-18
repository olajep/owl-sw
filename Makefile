CC  := gcc
AR  := $(CROSS_COMPILE)$(AR)
AS  := $(CROSS_COMPILE)$(AS)
CC  := $(CROSS_COMPILE)$(CC)
CXX := $(CROSS_COMPILE)$(CXX)
CPP := $(CROSS_COMPILE)$(CPP)

CANONICAL_TARGET ?= riscv64-unknown-linux-gnu-

CFLAGS ?= -Wall -Wextra -g -O0

TARGETS = dump owl
all: $(TARGETS)

dump: dump.o
dump.o: syscalltable.h

syscalltable.h: syscalltable-gen.h
GENERATED = syscalltable-gen.h
syscalltable-gen.h: syscalltable-in.h
	$(CANONICAL_TARGET)cpp $< -o $@

owl: owl.o

clean:
	rm -f $(TARGETS) $(GENERATED) *.o

.PHONY: clean
