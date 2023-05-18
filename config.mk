TOOLCHAIN=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64
CC=$(TOOLCHAIN)/bin/aarch64-linux-android21-clang
CXX=$(TOOLCHAIN)/bin/aarch64-linux-android21-clang++
LD=$(TOOLCHAIN)/bin/ld.lld
OBJOCPY=$(TOOLCHAIN)/bin/llvm-objcopy
CFLAGS=-fPIC -nostdinc -Isysroot/include

RT=$(TOOLCHAIN)/lib64/clang/14.0.6/lib/linux/libclang_rt.builtins-aarch64-android.a
LIBC=sysroot/lib/libc.a

%%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

%%.o: %.cpp
	$(CXX) $(CFLAGS) -c -o $@ $^
