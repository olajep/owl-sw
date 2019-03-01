CC  := gcc
AR  := $(CROSS_COMPILE)$(AR)
AS  := $(CROSS_COMPILE)$(AS)
CC  := $(CROSS_COMPILE)$(CC)
CXX := $(CROSS_COMPILE)$(CXX)
CPP := $(CROSS_COMPILE)$(CPP)

CFLAGS ?= -Wall -Wextra -g -O0

TARGETS = dump owl
all: $(TARGETS)

dump: dump.o

owl: owl.o

clean:
	rm -f $(TARGETS) *.o

.PHONY: clean
