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

        print("пересборка архива (%d записей)..." % len(zin.infolist()))
        with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zout:
            for i, item in enumerate(zin.infolist(), 1):
                if item.is_dir():
                    zout.writestr(item, b"")
                elif item.filename == plist_path:
                    zout.writestr(item, new_plist)
                elif item.filename in to_patch:
                    zout.writestr(item, to_patch[item.filename])
                else:
                    with zin.open(item) as src, zout.open(item, "w") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                if i % 200 == 0:
                    print("  %d/%d" % (i, len(zin.infolist())), flush=True)

    print("готово: %s (%.1f МБ)" % (args.out, os.path.getsize(args.out) / 1048576))
    print("подпись сброшена — нужна переподпись при установке")


if __name__ == "__main__":
    sys.exit(main())
