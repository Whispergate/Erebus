"""
VBA Project Compiler — builds a valid vbaProject.bin from VBA source code.

Produces a CFB (Compound File Binary / OLE2) container with the directory
structure that Excel expects:

    Root Entry
    ├── VBA/
    │   ├── _VBA_PROJECT   (fixed header)
    │   ├── dir            (compressed module metadata)
    │   └── <ModuleName>   (compressed VBA source)
    ├── PROJECT            (plain-text project metadata)
    └── PROJECTwm          (module name mapping)

Reference: [MS-OVBA] Office VBA File Format Structure, revision 14.0
Reference: [MS-CFB]  Compound File Binary File Format
"""

import struct
from pathlib import Path
from typing import Optional

from .compression import compress_vba


# ---------------------------------------------------------------------------
# CFB constants
# ---------------------------------------------------------------------------
SECTOR_SIZE = 512
ENDOFCHAIN  = 0xFFFFFFFE
FREESECT    = 0xFFFFFFFF
FATSECT     = 0xFFFFFFFD


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pad(data: bytes, size: int) -> bytes:
    """Pad *data* to the next multiple of *size*."""
    remainder = len(data) % size
    if remainder:
        return data + b'\x00' * (size - remainder)
    return data


def _dir_record(rec_id: int, data: bytes) -> bytes:
    """Encode a single dir-stream record: id (USHORT) + size (ULONG) + data."""
    return struct.pack('<HI', rec_id, len(data)) + data


def _make_dir_entry(
    name: str,
    obj_type: int,
    color: int = 1,
    child: int = 0xFFFFFFFF,
    left: int = 0xFFFFFFFF,
    right: int = 0xFFFFFFFF,
    start: int = 0,
    size: int = 0,
) -> bytes:
    """Build a 128-byte CFB directory entry."""
    entry = bytearray(128)
    encoded = name.encode('utf-16-le')
    entry[0:len(encoded)] = encoded
    struct.pack_into('<H', entry, 64, len(encoded) + 2)  # includes null
    entry[66] = obj_type   # 1=storage, 2=stream, 5=root
    entry[67] = color      # 0=red, 1=black
    struct.pack_into('<I', entry, 68, left)
    struct.pack_into('<I', entry, 72, right)
    struct.pack_into('<I', entry, 76, child)
    struct.pack_into('<I', entry, 116, start)
    struct.pack_into('<I', entry, 120, size)
    return bytes(entry)


# ---------------------------------------------------------------------------
# Stream builders
# ---------------------------------------------------------------------------

def _build_vba_project_stream() -> bytes:
    """_VBA_PROJECT stream — fixed 7-byte header."""
    return struct.pack('<HHbH', 0x61CC, 0xFFFF, 0x00, 0x0003)


def _build_dir_stream(module_name: str) -> bytes:
    """Build and compress the dir stream for a project with one StdModule."""
    mod_cp = module_name.encode('cp1252')
    mod_uni = module_name.encode('utf-16-le')

    raw = b''
    # -- PROJECTINFORMATION --
    raw += _dir_record(0x0001, struct.pack('<I', 3))       # SysKind Win64
    raw += _dir_record(0x004A, struct.pack('<I', 3))       # CompatVersion
    raw += _dir_record(0x0002, struct.pack('<I', 0x0409))  # LCID
    raw += _dir_record(0x0014, struct.pack('<I', 0x0409))  # LCIDInvoke
    raw += _dir_record(0x0003, struct.pack('<H', 0x04E4))  # CodePage cp1252
    raw += _dir_record(0x0004, b'VBAProject')              # Name
    raw += _dir_record(0x0005, b'')                        # DocString
    raw += _dir_record(0x0040, b'')                        # DocStringUnicode
    raw += _dir_record(0x0006, b'')                        # HelpFile1
    raw += _dir_record(0x003D, b'')                        # HelpFile2
    raw += _dir_record(0x0007, struct.pack('<I', 0))       # HelpContext
    raw += _dir_record(0x0008, struct.pack('<I', 0))       # LibFlags
    raw += _dir_record(0x0009, struct.pack('<I', 0x65BE0257))  # Version major
    raw += struct.pack('<H', 17)                           # Version minor
    raw += _dir_record(0x000C, b'')                        # Constants
    raw += _dir_record(0x003C, b'')                        # ConstantsUnicode

    # -- PROJECTMODULES --
    raw += _dir_record(0x000F, struct.pack('<H', 1))       # Count = 1
    raw += _dir_record(0x0013, struct.pack('<H', 0xFFFF))  # Cookie

    # -- MODULE record --
    raw += _dir_record(0x0019, mod_cp)                     # ModuleName
    raw += _dir_record(0x0047, mod_uni)                    # ModuleNameUnicode
    raw += _dir_record(0x001A, mod_cp)                     # StreamName
    raw += _dir_record(0x0032, mod_uni)                    # StreamNameUnicode
    raw += _dir_record(0x001C, b'')                        # DocString
    raw += _dir_record(0x0048, b'')                        # DocStringUnicode
    raw += _dir_record(0x0031, struct.pack('<I', 0))       # TextOffset
    raw += _dir_record(0x001E, struct.pack('<I', 0))       # HelpContext
    raw += _dir_record(0x002C, struct.pack('<H', 0xFFFF))  # Cookie
    raw += _dir_record(0x0021, struct.pack('<I', 0))       # Type = StdModule
    raw += struct.pack('<HI', 0x002B, 0)                   # MODULE terminator
    raw += struct.pack('<HI', 0x0010, 0)                   # PROJECTMODULES terminator

    return compress_vba(raw)


def _build_module_stream(vba_code: str, module_name: str) -> bytes:
    """Build the compressed module stream (performance cache + source)."""
    source = vba_code.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
    attr = f'Attribute VB_Name = "{module_name}"\r\n'
    if 'Attribute VB_Name' not in source:
        source = attr + source
    return compress_vba(source.encode('cp1252', errors='replace'))


def _build_project_stream(module_name: str) -> bytes:
    """Build the plain-text PROJECT stream."""
    eol = b'\r\n'
    parts = [
        b'ID="{00000000-0000-0000-0000-000000000000}"',
        f'Module={module_name}'.encode('cp1252'),
        b'Name="VBAProject"',
        b'HelpContextID="0"',
        b'VersionCompatible32="393222000"',
        b'CMG="0000"',
        b'DPB="0000"',
        b'GC="0000"',
        b'',
        b'[Host Extender Info]',
        b'&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000',
        b'',
        b'[Workspace]',
        f'{module_name}=0, 0, 0, 0, C'.encode('cp1252'),
    ]
    return eol.join(parts) + eol


def _build_projectwm_stream(module_name: str) -> bytes:
    """Build the PROJECTwm stream (name mapping table)."""
    return (
        module_name.encode('cp1252') + b'\x00'
        + module_name.encode('utf-16-le') + b'\x00\x00'
    )


# ---------------------------------------------------------------------------
# CFB assembly
# ---------------------------------------------------------------------------

def _assemble_cfb(streams: list) -> bytes:
    """
    Assemble a minimal CFB (OLE2) file from a list of named streams.

    Args:
        streams: list of (name, data_bytes, is_vba_child) tuples.

    Returns:
        Complete CFB file as bytes.
    """
    # Lay out stream data in sectors
    sector_pool = []     # list of 512-byte sectors
    stream_meta = []     # (name, start_sector, byte_size, is_vba_child)

    for name, data, is_vba in streams:
        start = len(sector_pool)
        padded = _pad(data, SECTOR_SIZE) if data else b'\x00' * SECTOR_SIZE
        for i in range(len(padded) // SECTOR_SIZE):
            sector_pool.append(padded[i * SECTOR_SIZE:(i + 1) * SECTOR_SIZE])
        stream_meta.append((name, start, len(data), is_vba))

    n_data = len(sector_pool)
    dir_sector = n_data
    fat_sector = n_data + 1

    # -- FAT --
    fat = bytearray(SECTOR_SIZE)
    for i in range(SECTOR_SIZE // 4):
        struct.pack_into('<I', fat, i * 4, FREESECT)

    for name, start, size, _ in stream_meta:
        n = max(1, (len(_pad(b'\x00' * size, SECTOR_SIZE)) if size else SECTOR_SIZE) // SECTOR_SIZE)
        for j in range(n):
            nxt = start + j + 1 if j < n - 1 else ENDOFCHAIN
            struct.pack_into('<I', fat, (start + j) * 4, nxt)

    struct.pack_into('<I', fat, dir_sector * 4, ENDOFCHAIN)
    struct.pack_into('<I', fat, fat_sector * 4, FATSECT)

    # -- Directory entries --
    #  0: Root Entry   (child → 1 VBA)
    #  1: VBA storage  (child → 2 first VBA stream, right → 5 PROJECT)
    #  2..4: VBA child streams (_VBA_PROJECT, dir, module)
    #  5: PROJECT       (right → 6)
    #  6: PROJECTwm

    entries = []
    entries.append(_make_dir_entry('Root Entry', 5, child=1, start=ENDOFCHAIN, size=0))
    entries.append(_make_dir_entry('VBA', 1, child=2, right=5))

    vba_items = [(i, m) for i, m in enumerate(stream_meta) if m[3]]
    for idx, (_, (name, start, size, _)) in enumerate(vba_items):
        left = 0xFFFFFFFF
        right = 2 + idx + 1 if idx + 1 < len(vba_items) else 0xFFFFFFFF
        if idx == 1:
            left = 2 + idx - 1
        entries.append(_make_dir_entry(name, 2, start=start, size=size, left=left, right=right))

    root_items = [(i, m) for i, m in enumerate(stream_meta) if not m[3]]
    for idx, (_, (name, start, size, _)) in enumerate(root_items):
        right = len(entries) + 1 if idx + 1 < len(root_items) else 0xFFFFFFFF
        entries.append(_make_dir_entry(name, 2, start=start, size=size, right=right))

    dir_data = _pad(b''.join(entries), SECTOR_SIZE)

    # -- Header --
    header = bytearray(SECTOR_SIZE)
    header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    struct.pack_into('<HH', header, 24, 0x003E, 0x0003)   # v3
    struct.pack_into('<H', header, 28, 0xFFFE)             # little-endian
    struct.pack_into('<H', header, 30, 0x0009)             # sector shift
    struct.pack_into('<H', header, 32, 0x0006)             # mini sector shift
    struct.pack_into('<I', header, 44, 1)                  # FAT sectors
    struct.pack_into('<I', header, 48, dir_sector)         # first dir sector
    struct.pack_into('<I', header, 56, 0x00001000)         # mini cutoff
    struct.pack_into('<I', header, 60, ENDOFCHAIN)         # no mini FAT
    struct.pack_into('<I', header, 68, ENDOFCHAIN)         # no DIFAT
    struct.pack_into('<I', header, 76, fat_sector)         # DIFAT[0]
    for i in range(1, 109):
        struct.pack_into('<I', header, 76 + i * 4, FREESECT)

    # -- Final file --
    out = bytes(header)
    for s in sector_pool:
        out += s
    out += dir_data
    out += bytes(fat)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compile_vba_project(
    vba_code: str,
    module_name: str = "ErebusPayload",
) -> bytes:
    """
    Compile VBA source code into a valid vbaProject.bin binary.

    Args:
        vba_code: Full VBA source code for the module.
        module_name: Name of the standard module inside the VBA project.

    Returns:
        bytes: Complete OLE compound file ready for injection into an
               XLSX/XLSM ZIP archive as ``xl/vbaProject.bin``.
    """
    streams = [
        ('_VBA_PROJECT', _build_vba_project_stream(),            True),
        ('dir',          _build_dir_stream(module_name),         True),
        (module_name,    _build_module_stream(vba_code, module_name), True),
        ('PROJECT',      _build_project_stream(module_name),     False),
        ('PROJECTwm',    _build_projectwm_stream(module_name),   False),
    ]
    return _assemble_cfb(streams)


def compile_vba_project_to_file(
    vba_code: str,
    output_path: str,
    module_name: str = "ErebusPayload",
) -> Path:
    """
    Compile VBA source and write the result to *output_path*.

    Returns:
        Path to the written file.
    """
    data = compile_vba_project(vba_code, module_name)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return out
