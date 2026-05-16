"""
Test suite for plugin_container_vhd.py
Tests Fixed VHD disk image creation with pure-Python FAT16 builder.

Note: build_vhd() requires at least one file in build_path/payload/ to package.
A dummy payload file is seeded into the payload subdirectory before calling.
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_container_vhd import VhdContainerPlugin

passed = 0
failed = 0

# VHD footer magic cookie (first 8 bytes of the 512-byte footer)
VHD_MAGIC = b"conectix"
VHD_FOOTER_SIZE = 512


def report(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  ✓ {name}")
        if detail:
            print(f"    {detail}")
    else:
        failed += 1
        print(f"  ✗ {name}")
        if detail:
            print(f"    {detail}")


def main():
    print("\n=======================================================================")
    print("TEST SUITE: plugin_container_vhd.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_vhd_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        # build_path is the root dir; the plugin reads files from build_path/payload/
        build_path = temp_path / "build"
        build_path.mkdir()
        inner_payload_dir = build_path / "payload"
        inner_payload_dir.mkdir()

        # Seed a dummy payload file so build_vhd() has something to package
        dummy_payload = inner_payload_dir / "payload.exe"
        dummy_payload.write_bytes(b"MZ" + b"\x00" * 510)  # Minimal PE stub

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = VhdContainerPlugin()
            report("VhdContainerPlugin instantiates without error", True)
        except Exception as e:
            report("VhdContainerPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] VHD Build
        print("\n[2] Testing VHD Build")
        print("-" * 70)
        try:
            result = plugin.build_vhd(
                build_path=build_path,
                visible_extension=".exe",
                output_filename="test.vhd",
            )
            report("build_vhd() returns a Path", isinstance(result, pathlib.Path),
                   f"Got: {type(result)}")
            report("Output VHD file exists", result.exists(), f"Path: {result}")
        except Exception as e:
            report("build_vhd()", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [3] VHD File Size and Footer Validation
        print("\n[3] Testing VHD File Size and Footer")
        print("-" * 70)
        vhd_path = build_path / "test.vhd"
        try:
            if vhd_path.exists():
                size = vhd_path.stat().st_size
                report("VHD file size > 512 bytes (minimum VHD footer)",
                       size > VHD_FOOTER_SIZE, f"Size: {size} bytes")

                raw = vhd_path.read_bytes()
                footer = raw[-VHD_FOOTER_SIZE:]
                report("Last 512 bytes exist (VHD footer region)",
                       len(footer) == VHD_FOOTER_SIZE,
                       f"Footer length: {len(footer)}")
                report("VHD footer magic 'conectix' present at footer offset 0",
                       footer[:8] == VHD_MAGIC,
                       f"Got: {footer[:8]!r}, expected: {VHD_MAGIC!r}")
            else:
                report("VHD file size > 512 bytes", False, "File does not exist")
                report("Last 512 bytes exist", False, "File does not exist")
                report("VHD footer magic 'conectix'", False, "File does not exist")
        except Exception as e:
            report("VHD size/footer validation", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] No-Payload Error Handling
        print("\n[4] Testing Error Handling (Empty Payload Directory)")
        print("-" * 70)
        empty_build = temp_path / "empty_build"
        empty_build.mkdir()
        empty_payload = empty_build / "payload"
        empty_payload.mkdir()
        try:
            plugin.build_vhd(
                build_path=empty_build,
                output_filename="empty.vhd",
            )
            report("Raises ValueError for empty payload dir", False,
                   "Expected ValueError but no exception raised")
        except ValueError as ve:
            report("Raises ValueError for empty payload dir", True, f"Message: {ve}")
        except Exception as e:
            report("Raises ValueError for empty payload dir", False,
                   f"Wrong exception type: {type(e).__name__}: {e}")

        # [5] Multiple Files in VHD
        print("\n[5] Testing VHD with Multiple Files")
        print("-" * 70)
        multi_build = temp_path / "multi_build"
        multi_build.mkdir()
        multi_payload = multi_build / "payload"
        multi_payload.mkdir()
        (multi_payload / "payload.exe").write_bytes(b"MZ" + b"\x00" * 510)
        (multi_payload / "lure.pdf").write_bytes(b"%PDF-1.4" + b"\x00" * 100)
        (multi_payload / "trigger.lnk").write_bytes(b"\x4c\x00\x00\x00" + b"\x00" * 76)
        try:
            result_multi = plugin.build_vhd(
                build_path=multi_build,
                output_filename="multi.vhd",
            )
            report("Multi-file VHD created", result_multi.exists())
            if result_multi.exists():
                raw_multi = result_multi.read_bytes()
                footer_multi = raw_multi[-VHD_FOOTER_SIZE:]
                report("Multi-file VHD has valid footer magic",
                       footer_multi[:8] == VHD_MAGIC)
        except Exception as e:
            report("Multi-file VHD creation", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Plugin Registration
        print("\n[6] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'build_vhd'", "build_vhd" in registered)
        except Exception as e:
            report("Plugin registration", False, f"Exception: {e}")
            traceback.print_exc()

        # [7] Plugin Metadata and Validation
        print("\n[7] Testing Plugin Metadata and Validation")
        print("-" * 70)
        try:
            meta = plugin.get_metadata()
            report("get_metadata() returns metadata", meta is not None)
            valid, err = plugin.validate()
            report("validate() returns True", valid is True, f"Error: {err}")
        except Exception as e:
            report("Plugin metadata/validation", False, f"Exception: {e}")
            traceback.print_exc()

    print(f"\nRESULTS: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        traceback.print_exc()
        sys.exit(1)
