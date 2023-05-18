#!/bin/sh

export CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang

cd musl

./configure --disable-shared --prefix=$PWD/../sysroot

make install
