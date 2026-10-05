#!/bin/sh
set -eu
cd "$(dirname "$0")"
ndk_root=${ANDROID_NDK_HOME:-/usr/lib/android-sdk/ndk/25.2.9519653}
compiler_dir="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
mkdir -p dist/arm64-v8a dist/armeabi-v7a
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="$compiler_dir/aarch64-linux-android24-clang" go build -trimpath -buildmode=c-shared -ldflags='-s -w' -o dist/arm64-v8a/libanet_dpi.so .
GOOS=android GOARCH=arm GOARM=7 CGO_ENABLED=1 CC="$compiler_dir/armv7a-linux-androideabi24-clang" go build -trimpath -buildmode=c-shared -ldflags='-s -w' -o dist/armeabi-v7a/libanet_dpi.so .
