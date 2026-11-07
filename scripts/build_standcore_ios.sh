#!/usr/bin/env bash
# Собирает standcore_ios.cpp в standcore.dylib (iOS arm64) и линкует libdobby.a.
# Переменные: SERVER_IP (куда редиректить), IOS_MIN, DOBBY_LIB, OUT_DIR
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT_DIR:-$ROOT/build/ios}"
DOBBY_LIB="${DOBBY_LIB:-$OUT/libdobby.a}"
SRC="$ROOT/standcore_ios.cpp"
IOS_MIN="${IOS_MIN:-13.0}"
SERVER_IP="${SERVER_IP:-2.26.123.219}"

if [ ! -f "$DOBBY_LIB" ]; then
  echo "!! нет $DOBBY_LIB — сначала запусти scripts/build_dobby_ios.sh"
  exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CXX_BIN="$(xcrun -f clang++)"
mkdir -p "$OUT"

echo "==> compiling standcore.dylib (server=$SERVER_IP, min iOS=$IOS_MIN)"
"$CXX_BIN" \
  -arch arm64 \
  -mios-version-min="$IOS_MIN" \
  -isysroot "$SDK" \
  -std=c++17 -O2 \
  -fvisibility=hidden -fexceptions -fno-rtti \
  -Wall -Wno-unused-parameter -Wno-cast-function-type \
  -I "$OUT/include" \
  -DSC_SERVER_IP_OVERRIDE="\"$SERVER_IP\"" \
  -dynamiclib \
  -install_name "@executable_path/Frameworks/standcore.dylib" \
  -Wl,-undefined,dynamic_lookup \
  -Wl,-dead_strip \
  "$SRC" "$DOBBY_LIB" \
  -o "$OUT/standcore.dylib"

# ad-hoc подпись: без неё dylib не загрузится на устройстве.
# финальную подпись всё равно делает тот, кто пересобирает IPA (ldid/Sideloadly).
codesign --force --sign - "$OUT/standcore.dylib" 2>/dev/null || echo "!! codesign пропущен"

echo "==> ok: $OUT/standcore.dylib"
lipo -info "$OUT/standcore.dylib"
echo "--- Dobby symbols ---"
# -g = только внешние символы; Dobby должен быть определён (T), а не undefined
nm -g "$OUT/standcore.dylib" | grep -E ' T _Dobby' || echo "!! Dobby не слинковался"
