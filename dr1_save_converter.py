#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct

MAGIC = bytes.fromhex('6495ae16')
FOOTER = bytes.fromhex('efbeadde')
SAVE_SIZE = 0x3A9B0
PREFIX_SIZE = 740


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def validate_save(data):
    if len(data) != SAVE_SIZE or data[:4] != MAGIC or data[60:64] != MAGIC:
        raise ValueError('Invalid payload')
    if u32(data, 56) != sum(data[:56]) & 0xFFFFFFFF:
        raise ValueError('Header checksum mismatch')
    if u32(data, len(data) - 4) != sum(data[60:-4]) & 0xFFFFFFFF:
        raise ValueError('Body checksum mismatch')


def parse_vfs(data):
    entries = []
    seen = set()
    offset = 0
    while offset < len(data):
        if data[offset:offset + 4] == FOOTER:
            if offset + 4 != len(data):
                raise ValueError('Unexpected bytes after VFS footer')
            return entries
        if offset + 4 > len(data):
            raise ValueError('Truncated entry header')
        size = u32(data, offset)
        if not 1 <= size <= 255 or offset + 8 + size > len(data):
            raise ValueError('Invalid filename length or truncated header')
        raw = data[offset + 4:offset + 4 + size]
        if b'\0' in raw:
            raise ValueError('Unexpected NUL in filename')
        name = raw.decode('ascii')
        if not re.fullmatch(r'(?:data\d{4}\.bin|icon\d{4}\.png)', name) or name in seen:
            raise ValueError(f'Unsupported or duplicate entry: {name!r}')
        seen.add(name)
        length = u32(data, offset + 4 + size)
        start = offset + 8 + size
        end = start + length
        if end > len(data):
            raise ValueError('Truncated entry payload')
        entries.append((name, data[start:end]))
        offset = end
    raise ValueError('Missing VFS footer')


def build_vfs(entries):
    result = bytearray()
    for name, payload in entries:
        encoded = name.encode('ascii')
        result += struct.pack('<I', len(encoded)) + encoded
        result += struct.pack('<I', len(payload)) + payload
    result += FOOTER
    if parse_vfs(result) != entries:
        raise ValueError('VFS round-trip failed')
    return bytes(result)


def field(text, size):
    encoded = text.encode('utf-8')
    if len(encoded) >= size:
        raise ValueError('Metadata too long')
    return encoded + bytes(size - len(encoded))


def cstring(data):
    return data.split(b'\0', 1)[0].decode('utf-8')


def inspect_vfs(data):
    records = []
    for name, payload in parse_vfs(data):
        record = {'name': name, 'bytes': len(payload)}
        if name.endswith('.bin'):
            if len(payload) != PREFIX_SIZE + SAVE_SIZE or u32(payload, 736) != SAVE_SIZE:
                raise ValueError(f'{name}: unexpected PC wrapper')
            validate_save(payload[PREFIX_SIZE:])
            record.update(title=cstring(payload[64:192]), description=cstring(payload[192:704]),
                          checksums_valid=True)
        records.append(record)
    return records


def convert(root, selected=None, latest_only=False):
    metadata = (root / 'sce_sys/sdslot.dat').read_bytes()
    if len(metadata) != 0x40400 or metadata[:4] != b'SDSL':
        raise ValueError('Unrecognized sdslot.dat')
    paths = sorted(root.glob('data[0-9][0-9][0-9][0-9].bin'))
    if selected is not None:
        paths = [p for p in paths if int(p.stem[4:]) == selected]
    if not paths:
        raise ValueError('No save files found')
    saves = []
    for path in paths:
        payload = path.read_bytes()
        validate_save(payload)
        saves.append((path, payload))
    if latest_only:
        # Use days/hours/minutes/seconds then save count
        saves = [max(saves, key=lambda item: (u32(item[1], 20),
                 struct.unpack_from('<H', item[1], 18)[0], item[1][17], item[1][16], u32(item[1], 28)))]
    timestamp = datetime.datetime.now().strftime('%d.%m.%Y/%H.%M.%S')
    entries, icons, mapping = [], [], []
    for path, payload in saves:
        index = int(path.stem[4:])
        if index >= 256:
            raise ValueError('Slot index outside metadata table')
        target = 0 if latest_only else index
        record = metadata[1024 + index * 1024:2048 + index * 1024]
        title = cstring(record[68:196])
        description = cstring(record[196:708])
        expected = re.search(r'Number of times saved: (\d+)', description)
        if expected is None or int(expected[1]) != u32(payload, 28):
            raise ValueError(f'{path.name}: metadata/save count mismatch')
        wrapper = (field(cstring(record[4:68]), 64) + field(title, 128) +
                   field(description, 512) + field(timestamp, 32) + struct.pack('<I', len(payload)))
        entries.append((f'data{target:04}.bin', wrapper + payload))
        icon_path = cstring(record[708:772])
        if icon_path.startswith('savedata0:'):
            icon_name = icon_path.split(':', 1)[1]
            if icon_name != f'icon{index:04}.png':
                raise ValueError('Unexpected slot icon reference')
            icon = (root / icon_name).read_bytes()
            if not icon.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('Invalid decrypted PNG signature')
            icons.append((f'icon{target:04}.png', icon))
        elif icon_path != 'app0:/Dr1/data/us/save_icon/icon.png':
            raise ValueError('Unknown default icon reference')
        mapping.append({'source': path.name, 'target': f'data{target:04}.bin', 'title': title,
                        'payload_sha256': hashlib.sha256(payload).hexdigest()})
    output = build_vfs(entries + icons)
    inspect_vfs(output)
    return output, mapping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    inspect = subs.add_parser('inspect', help='Validate a PC VFS')
    inspect.add_argument('file', type=Path)
    create = subs.add_parser('convert', help='Build a VFS without changing inputs')
    create.add_argument('directory', type=Path)
    create.add_argument('--output', type=Path, required=True)
    group = create.add_mutually_exclusive_group()
    group.add_argument('--slot', type=int, help='Include only this zero-based slot, retaining its index')
    group.add_argument('--latest-only', action='store_true', help='Put the latest save in slot zero')
    args = parser.parse_args()
    try:
        if args.command == 'inspect':
            print(json.dumps(inspect_vfs(args.file.read_bytes()), indent=2))
        else:
            data, mapping = convert(args.directory, args.slot, args.latest_only)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('xb') as stream:
                stream.write(data)
            print(json.dumps({'output': str(args.output), 'bytes': len(data), 'slots': mapping}, indent=2))
    except (ValueError, OSError, UnicodeError, struct.error) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
