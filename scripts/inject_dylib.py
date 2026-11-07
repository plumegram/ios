#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Вшивает dylib в .ipa:

  1. кладёт dylib в Payload/<App>.app/Frameworks/
  2. добавляет в главный исполняемый файл приложения LC_LOAD_DYLIB
     с путём @executable_path/Frameworks/<name>

Load-команда пишется в свободный хвост заголовка Mach-O (между концом
load commands и первой секцией), поэтому данные не сдвигаются и все
fileoff/offset в файле остаются валидными. Если запаса нет — скрипт
падает, а не пытается двигать сегменты.

Подпись после такой правки невалидна: IPA надо переподписать при установке
(Sideloadly / AltStore / ldid), они подписывают все Mach-O в бандле.

Использование:
    python inject_dylib.py -i game.ipa -d standcore.dylib -o game+mod.ipa
"""

import argparse
import os
import plistlib
import shutil
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
CPU_ARM64 = 16777228
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x8000001F


def align8(v):
    return (v + 7) & ~7


def iter_load_commands(data, ncmds):
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if size < 8:
            raise ValueError("битый load command @ %d" % off)
        yield off, cmd, size
        off += size


def first_section_offset(data, ncmds):
    """Минимальный file-offset данных первой секции — граница запаса в заголовке."""
    best = None
    for off, cmd, size in iter_load_commands(data, ncmds):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from("<I", data, off + 64)[0]
        so = off + 72
        for _ in range(nsects):
            ssize = struct.unpack_from("<Q", data, so + 40)[0]
            s_off = struct.unpack_from("<I", data, so + 48)[0]
            if ssize and s_off:
                best = s_off if best is None else min(best, s_off)
            so += 80
    return best


def existing_dylibs(data, ncmds):
    out = []
    for off, cmd, size in iter_load_commands(data, ncmds):
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB):
            name_off = struct.unpack_from("<I", data, off + 8)[0]
            raw = data[off + name_off: off + size]
            out.append(raw.split(b"\0")[0].decode("utf-8", "replace"))
    return out


def patch_macho(data, dylib_path):
    if len(data) < 32:
        raise ValueError("файл слишком мал для Mach-O")

    magic, cputype, _cpusub, filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(
        "<IiiIIII", data, 0
    )
    if magic != MH_MAGIC_64:
        raise ValueError("не Mach-O 64 (magic=0x%08x)" % magic)
    if cputype != CPU_ARM64:
        raise ValueError("не arm64 (cputype=%d)" % cputype)
    if filetype != MH_EXECUTE:
        raise ValueError("не MH_EXECUTE (filetype=%d)" % filetype)

    if dylib_path in existing_dylibs(data, ncmds):
        print("    LC_LOAD_DYLIB уже есть — пропускаю")
        return data, False

    name = dylib_path.encode("utf-8") + b"\0"
    cmdsize = align8(24 + len(name))
    # struct dylib_command: cmd, cmdsize, name(lc_str), timestamp, current, compat
    cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 2, 0x10000, 0x10000) + name
    cmd += b"\0" * (cmdsize - len(cmd))

    header_end = 32 + sizeofcmds
    first_data = first_section_offset(data, ncmds)
    if first_data is None:
        raise ValueError("не нашёл ни одной секции с данными")
    slack = first_data - header_end
    print("    load commands: %d, конец заголовка %d, первая секция %d, запас %d байт"
          % (ncmds, header_end, first_data, slack))
    if slack < cmdsize:
        raise ValueError(
            "в заголовке только %d байт запаса, нужно %d — правка без сдвига невозможна"
            % (slack, cmdsize)
        )

    out = bytearray(data)
    out[header_end:header_end + cmdsize] = cmd
    struct.pack_into("<I", out, 16, ncmds + 1)
    struct.pack_into("<I", out, 20, sizeofcmds + cmdsize)

    # контрольная проверка: команды по-прежнему разбираются до конца
    last = 32
    for off, c, s in iter_load_commands(bytes(out), ncmds + 1):
        last = off + s
    if last != 32 + sizeofcmds + cmdsize:
        raise ValueError("после правки load commands не сходятся")
    print("    добавлен LC_LOAD_DYLIB (%d байт) @ %d" % (cmdsize, header_end))
    return bytes(out), True


def find_app(zf):
    apps = {n.split("/")[1] for n in zf.namelist()
            if n.startswith("Payload/") and n.count("/") >= 1 and n.split("/")[1].endswith(".app")}
    if len(apps) != 1:
        raise SystemExit("ожидался ровно один .app в Payload/, найдено: %s" % (apps or "ничего"))
    app = apps.pop()
    prefix = "Payload/%s/" % app
    with zf.open(prefix + "Info.plist") as f:
        info = plistlib.load(f)
    return app, prefix, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--ipa", required=True, help="исходный .ipa")
    ap.add_argument("-d", "--dylib", required=True, help="что вшиваем")
    ap.add_argument("-o", "--out", required=True, help="куда писать .ipa")
    ap.add_argument("--name", default=None, help="имя dylib внутри Frameworks/")
    args = ap.parse_args()

    if os.path.abspath(args.ipa) == os.path.abspath(args.out):
        raise SystemExit("--out не должен совпадать с --ipa")

    dylib_name = args.name or os.path.basename(args.dylib)
    with open(args.dylib, "rb") as f:
        dylib_bytes = f.read()

    with zipfile.ZipFile(args.ipa) as zin:
        app, prefix, info = find_app(zin)
        exe = info["CFBundleExecutable"]
        exe_path = prefix + exe
        print("app:        %s" % app)
        print("bundle id:  %s %s (%s)"
              % (info.get("CFBundleIdentifier"), info.get("CFBundleShortVersionString"),
                 info.get("CFBundleVersion")))
        print("executable: %s (%d байт)"
              % (exe_path, zin.getinfo(exe_path).file_size))
        print("dylib:      %s (%d байт) -> %sFrameworks/%s"
              % (dylib_name, len(dylib_bytes), prefix, dylib_name))

        patched, changed = patch_macho(zin.read(exe_path), "@executable_path/Frameworks/" + dylib_name)

        dest = prefix + "Frameworks/" + dylib_name
        total = len(zin.infolist())
        print("пересборка архива (%d записей)..." % total)
        with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zout:
            for i, item in enumerate(zin.infolist(), 1):
                if item.is_dir():
                    zout.writestr(item, b"")
                elif item.filename == exe_path:
                    zout.writestr(item, patched)
                elif item.filename == dest:
                    continue  # перезапишем ниже
                else:
                    with zin.open(item) as src, zout.open(item, "w") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                if i % 200 == 0:
                    print("  %d/%d" % (i, total), flush=True)

            zi = zipfile.ZipInfo(dest)
            zi.external_attr = 0o755 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(zi, dylib_bytes)

    print("готово: %s (%.1f МБ)" % (args.out, os.path.getsize(args.out) / 1048576))
    if changed:
        print("подпись сброшена — при установке нужна переподпись (Sideloadly/AltStore/ldid)")


if __name__ == "__main__":
    sys.exit(main())
