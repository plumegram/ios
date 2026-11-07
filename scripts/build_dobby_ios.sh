#!/usr/bin/env bash
# Собирает Dobby из исходников под iOS (arm64, device) в статическую libdobby.a.
# Результат: build/ios/libdobby.a + build/ios/include/dobby.h
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/build/dobby-src"
BUILD="$ROOT/build/dobby-ios"
OUT="$ROOT/build/ios"

REF="${DOBBY_REF:-master}"
IOS_MIN="${IOS_MIN:-13.0}"
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CC_BIN="$(xcrun -f clang)"
CXX_BIN="$(xcrun -f clang++)"

echo "==> SDK:      $SDK"
echo "==> Dobby:    $REF"
echo "==> min iOS:  $IOS_MIN"

rm -rf "$SRC" "$BUILD"
mkdir -p "$SRC" "$OUT"

echo "==> fetch Dobby"
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/jmpews/Dobby.git
git -C "$SRC" fetch -q --depth 1 origin "$REF"
git -C "$SRC" checkout -q FETCH_HEAD
echo "    commit: $(git -C "$SRC" rev-parse --short HEAD)"

echo "==> configure"
cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_SYSTEM_PROCESSOR=arm64 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_SYSROOT="$SDK" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_MIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DDOBBY_DEBUG=OFF \
  -DPlugin.SymbolResolver=ON \
  -DPlugin.ImportTableReplace=OFF \
  -DDOBBY_BUILD_EXAMPLE=OFF \
  -DDOBBY_BUILD_TEST=OFF \
  -DCMAKE_C_COMPILER="$CC_BIN" \
  -DCMAKE_CXX_COMPILER="$CXX_BIN"

echo "==> build dobby_static"
# собираем только статическую либу: framework-таргет DobbyX (Darwin-only) нам не нужен
cmake --build "$BUILD" --target dobby_static -j "$JOBS"

LIB="$(find "$BUILD" -name 'libdobby.a' -type f | head -n1)"
if [ -z "$LIB" ]; then
  echo "!! libdobby.a не найдена. Что вообще собралось:"
  find "$BUILD" -maxdepth 4 -type f \( -name '*.a' -o -name '*.dylib' \) || true
  exit 1
fi

mkdir -p "$OUT/include"
cp "$LIB" "$OUT/libdobby.a"
cp "$SRC/include/dobby.h" "$OUT/include/dobby.h"

echo "==> ok: $OUT/libdobby.a"
lipo -info "$OUT/libdobby.a"
