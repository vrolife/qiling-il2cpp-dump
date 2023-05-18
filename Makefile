include config.mk

all: dump.elf

dump.elf: dump.o Makefile il2cpp-api-functions.h
	$(LD) -pie -e entry -o $@ $(LIBC) $(RT) dump.o

clean:
	rm -f *.o *.elf *.a
