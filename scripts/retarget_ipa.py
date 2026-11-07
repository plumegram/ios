#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Понижает заявленную минимальную версию iOS у готового .ipa:

  1. Info.plist  -> MinimumOSVersion (и LSMinimumSystemVersion, если есть)
  2. каждый Mach-O -> LC_BUILD_VERSION minos / LC_VERSION_MIN_IPHONEOS,
     но только если текущее значение выше целевого

Это именно приведение заявленных требований в соответствие с бинарями:
если Mach-O собран с minos 11.0, а plist требует 15.0 — установка
блокируется только plist'ом, и понижение честное. Обратное неверно:
если бинарь требует больше, чем целевая версия, скрипт это покажет.

Архитектуры не трогаются: добавить armv7 невозможно, если слайсов нет.

Использование:
    python retarget_ipa.py -i game.ipa -o game-ios12.ipa --min-ios 12.0
"""

import argparse
import os
import plistlib
import shutil
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from inject_dylib import patch_macho as add_load_command
except Exception:  # inject_dylib рядом не обязателен, если не просили --inject
    add_load_command = None

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION = 0x32
PLATFORM_IOS = 2


def ver_str(v):
    return "%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF)


def ver_int(s):
    parts = [int(x) for x in str(s).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def is_macho(head):
    if len(head) < 32:
        return False
    return struct.unpack_from("<I", head, 0)[0] in (MH_MAGIC_64, 0xFEEDFACE)


def patch_macho_minos(data, target, name):
    """Понижает minos. Возвращает (новые байты, было, стало|None)."""
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MH_MAGIC_64:
        return data, None, None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    out = bytearray(data)
    before = None
    changed = False
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", out, off)
        if cmd == LC_BUILD_VERSION:
            platform, minos = struct.unpack_from("<II", out, off + 8)
            if platform == PLATFORM_IOS:
                before = minos
                if minos > target:
                    struct.pack_into("<I", out, off + 12, target)
                    changed = True
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            minos = struct.unpack_from("<I", out, off + 8)[0]
            if before is None:
                before = minos
            if minos > target:
                struct.pack_into("<I", out, off + 8, target)
                changed = True
        off += size
    if before is None:
        return data, None, None
    return (bytes(out) if changed else data), before, (target if changed else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--ipa", required=True)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--min-ios", default="12.0", help="целевая минимальная версия, напр. 12.0")
    ap.add_argument("--drop-key", action="append", default=None, metavar="KEY",
                    help="удалить ключ из Info.plist (можно несколько раз), "
                         "напр. UISupportedDevices")
    ap.add_argument("--inject", default=None, metavar="DYLIB",
                    help="заодно вшить dylib в Frameworks/ и добавить LC_LOAD_DYLIB")
    ap.add_argument("--inject-name", default=None, help="имя dylib внутри Frameworks/")
    args = ap.parse_args()

    if os.path.abspath(args.ipa) == os.path.abspath(args.out):
        raise SystemExit("--out не должен совпадать с --ipa")

    target = ver_int(args.min_ios)
    print("цель: iOS %s (0x%08x)" % (args.min_ios, target))

    with zipfile.ZipFile(args.ipa) as zin:
        apps = {n.split("/")[1] for n in zin.namelist()
                if n.startswith("Payload/") and n.split("/")[1].endswith(".app")}
        if len(apps) != 1:
            raise SystemExit("ожидался один .app в Payload/, найдено: %s" % (apps or "ничего"))
        app = apps.pop()
        prefix = "Payload/%s/" % app
        plist_path = prefix + "Info.plist"

        raw = zin.read(plist_path)
        is_binary = raw[:8] == b"bplist00"
        info = plistlib.loads(raw)
        old_min = info.get("MinimumOSVersion")
        print("Info.plist MinimumOSVersion: %s -> %s" % (old_min, args.min_ios))
        print("UIDeviceFamily: %s%s" % (info.get("UIDeviceFamily"),
                                        "" if info.get("UIDeviceFamily") == [1, 2] else "  (не все устройства)"))
        info["MinimumOSVersion"] = args.min_ios
        if "LSMinimumSystemVersion" in info:
            info["LSMinimumSystemVersion"] = args.min_ios

        for key in (args.drop_key or []):
            for k in [key, key + "~ipad", key + "~iphone"]:
                if k in info:
                    print("удаляю ключ %s = %s" % (k, info[k]))
                    del info[k]

        new_plist = plistlib.dumps(
            info, fmt=plistlib.FMT_BINARY if is_binary else plistlib.FMT_XML, sort_keys=False)

        # какие Mach-O надо править
        to_patch = {}
        for n in zin.namelist():
            if not n.startswith(prefix) or n.endswith("/"):
                continue
            with zin.open(n) as f:
                if not is_macho(f.read(32)):
                    continue
            data = zin.read(n)
            new, before, after = patch_macho_minos(data, target, n)
            if after is not None:
                to_patch[n] = new
                print("  minos %s -> %s  %s" % (ver_str(before), ver_str(after), n.split(prefix)[1]))

        if not to_patch:
            print("  Mach-O править не нужно: все уже <= %s" % args.min_ios)

        # опционально: заодно вшить dylib (одним проходом, без второго архива)
        dest = None
        if args.inject:
            if add_load_command is None:
                raise SystemExit("рядом нет inject_dylib.py — не могу вшить dylib")
            with open(args.inject, "rb") as f:
                inject_bytes = f.read()
            inject_name = args.inject_name or os.path.basename(args.inject)
            dest = prefix + "Frameworks/" + inject_name
            exe_path = prefix + info["CFBundleExecutable"]
            if exe_path not in zin.namelist():
                raise SystemExit("не нашёл исполняемый файл %s" % exe_path)
            exe_data = to_patch.get(exe_path) or zin.read(exe_path)
            print("вшиваю %s (%d байт) -> %s"
                  % (inject_name, len(inject_bytes), dest.split(prefix)[1]))
            patched, changed = add_load_command(
                exe_data, "@executable_path/Frameworks/" + inject_name)
            to_patch[exe_path] = patched
            if not changed:
                print("  LC_LOAD_DYLIB уже был")
            if dest in zin.namelist():
                print("  %s уже есть в бандле — перезапишу" % inject_name)

        print("пересборка архива (%d записей)..." % len(zin.infolist()))
        with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zout:
            for i, item in enumerate(zin.infolist(), 1):
                if item.is_dir():
                    zout.writestr(item, b"")
                elif dest and item.filename == dest:
                    continue  # запишем ниже, свежий файл
                elif item.filename == plist_path:
                    zout.writestr(item, new_plist)
                elif item.filename in to_patch:
                    zout.writestr(item, to_patch[item.filename])
                else:
                    with zin.open(item) as src, zout.open(item, "w") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                if i % 200 == 0:
                    print("  %d/%d" % (i, len(zin.infolist())), flush=True)

            if dest:
                zi = zipfile.ZipInfo(dest)
                zi.external_attr = 0o755 << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, inject_bytes)

    print("готово: %s (%.1f МБ)" % (args.out, os.path.getsize(args.out) / 1048576))
    print("подпись сброшена — нужна переподпись при установке")


if __name__ == "__main__":
    sys.exit(main())
