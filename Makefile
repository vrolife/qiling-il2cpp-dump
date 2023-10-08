include config.mk

all: dump.elf

dump.elf: dump.o Makefile il2cpp-api-functions.h
#	$(LD) -pie -e entry -o $@ dump.o $(LDFLAGS) $(LIBCXX) $(LIBC) $(RT)
	$(CXX) -static -nostdlib -nostartfiles  -pie -e entry -o $@ dump.o -lc++_static -lc++abi -lunwind -lc -lcompiler_rt-extras $(RT)

clean:
	rm -f *.o *.elf *.a
