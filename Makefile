CC  := gcc
AR  := $(CROSS_COMPILE)$(AR)
AS  := $(CROSS_COMPILE)$(AS)
CC  := $(CROSS_COMPILE)$(CC)
CXX := $(CROSS_COMPILE)$(CXX)
CPP := $(CROSS_COMPILE)$(CPP)

CFLAGS ?= -Wall -Wextra

all: dump

dump: dump.o

clean:
	rm -f dump *.o

.PHONY: clean
