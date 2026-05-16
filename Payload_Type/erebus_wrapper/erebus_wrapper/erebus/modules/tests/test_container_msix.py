"""
Test suite for plugin_container_msix.py
Tests AppInstaller manifest generation and MSIX package structure creation.

Note on API:
  build_appinstaller(build_path, msix_uri, ...) - writes to build_path/<output_filename>
  build_msix_structure(build_path, payload_files, ...) - writes to build_path/msix_package/
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_container_msix import MsixContainerPlugin

passed = 0
failed = 0


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
    print("TEST SUITE: plugin_container_msix.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_msix_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = MsixContainerPlugin()
            report("MsixContainerPlugin instantiates without error", True)
        except Exception as e:
            report("MsixContainerPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] AppInstaller Manifest Generation
        print("\n[2] Testing AppInstaller Manifest Generation")
        print("-" * 70)
        HOSTING_URL = "https://cdn.attacker.com/app.msix"
        PACKAGE_NAME = "ErebusApp"
        appinstaller_build_dir = payload_dir / "appinstaller_build"
        appinstaller_build_dir.mkdir()
        try:
            result = plugin.build_appinstaller(
                build_path=appinstaller_build_dir,
                msix_uri=HOSTING_URL,
                output_filename="app.appinstaller",
                package_name=PACKAGE_NAME,
            )
            report("build_appinstaller() returns a Path", isinstance(result, pathlib.Path),
                   f"Got: {type(result)}")
            report(".appinstaller file exists", result.exists(), f"Path: {result}")
            if result.exists():
                size = result.stat().st_size
                report(".appinstaller file size > 0", size > 0, f"Size: {size} bytes")
                content = result.read_text(encoding="utf-8")
                report("Content contains <?xml", "<?xml" in content)
                report("Content contains AppInstaller", "AppInstaller" in content)
                report("Content contains hosting URL", HOSTING_URL in content)
                report("Content contains package name", PACKAGE_NAME in content)
            else:
                report(".appinstaller file size > 0", False, "File does not exist")
                report("Content contains <?xml", False, "File does not exist")
                report("Content contains AppInstaller", False, "File does not exist")
                report("Content contains hosting URL", False, "File does not exist")
                report("Content contains package name", False, "File does not exist")
        except Exception as e:
            report("build_appinstaller()", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] MSIX Package Structure Generation
        print("\n[3] Testing MSIX Package Structure Generation")
        print("-" * 70)
        msix_build_dir = payload_dir / "msix_build"
        msix_build_dir.mkdir()
        # Seed a dummy payload file for the MSIX assets
        dummy_exe = payload_dir / "erebus.exe"
        dummy_exe.write_bytes(b"MZ" + b"\x00" * 510)
        try:
            result_msix = plugin.build_msix_structure(
                build_path=msix_build_dir,
                payload_files=[dummy_exe],
                package_name="ErebusApp",
                display_name="Erebus",
            )
            report("build_msix_structure() returns a Path", isinstance(result_msix, pathlib.Path),
                   f"Got: {type(result_msix)}")
            report("MSIX package directory exists",
                   result_msix.exists() and result_msix.is_dir(), f"Path: {result_msix}")
        except Exception as e:
            report("build_msix_structure()", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [4] MSIX Required Files
        print("\n[4] Testing MSIX Required Files in Package Directory")
        print("-" * 70)
        try:
            manifest = result_msix / "AppxManifest.xml"
            report("AppxManifest.xml exists", manifest.exists(), f"Path: {manifest}")

            content_types = result_msix / "[Content_Types].xml"
            report("[Content_Types].xml exists", content_types.exists(),
                   f"Path: {content_types}")

            if manifest.exists():
                manifest_content = manifest.read_text(encoding="utf-8")
                report("AppxManifest.xml contains ErebusApp package name",
                       "ErebusApp" in manifest_content)
                report("AppxManifest.xml contains display name Erebus",
                       "Erebus" in manifest_content)
        except Exception as e:
            report("MSIX required files check", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] Plugin Registration
        print("\n[5] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'build_appinstaller'",
                   "build_appinstaller" in registered)
            report("register() contains 'build_msix_structure'",
                   "build_msix_structure" in registered)
        except Exception as e:
            report("Plugin registration", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Plugin Metadata and Validation
        print("\n[6] Testing Plugin Metadata and Validation")
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
