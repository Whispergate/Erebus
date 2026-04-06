"""
Test suite for container_iso.py
Tests ISO creation, autorun generation, and file visibility settings.
"""

import pathlib
import sys
import tempfile
import traceback
import shutil

# Import from archive directory
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "archive"))

try:
    import container_iso
    ISO_AVAILABLE = True
except ImportError as e:
    ISO_AVAILABLE = False
    IMPORT_ERROR = str(e)

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
    print("TEST SUITE: container_iso.py")
    print("=======================================================================\n")
    
    if not ISO_AVAILABLE:
        print(f"SKIPPED: {IMPORT_ERROR}")
        print("\nInstall required dependencies:")
        print("  pip install pycdlib")
        print("\n" + "=" * 70)
        print(f"RESULTS: 0 passed, 0 failed (skipped due to missing dependencies)")
        print("=" * 70 + "\n")
        return 0
    
    with tempfile.TemporaryDirectory(prefix="erebus_iso_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        
        # Setup mock build structure
        build_dir = temp_path / "build"
        payload_dir = build_dir / "payload"
        decoy_dir = build_dir / "decoys"
        container_dir = build_dir / "container"
        
        payload_dir.mkdir(parents=True)
        decoy_dir.mkdir(parents=True)
        container_dir.mkdir(parents=True)
        
        # Create test files
        (payload_dir / "test.exe").write_bytes(b"MZ" + b"\x00" * 500)
        (payload_dir / "test.lnk").write_text("dummy lnk")
        (decoy_dir / "document.pdf").write_bytes(b"%PDF-1.4" + b"\x00" * 200)
        
        # [1] Test Basic ISO Creation
        print("\n[1] Testing Basic ISO Creation")
        print("-" * 70)
        try:
            iso_path = container_iso.build_iso(
                volume_id="TEST_ISO",
                enable_autorun=True,
                build_path=build_dir,
                visible_extension=".lnk"
            )
            
            report("build_iso() returns path", iso_path is not None, f"Path: {iso_path}")
            report("ISO file created", iso_path.exists(), f"Size: {iso_path.stat().st_size} bytes")
            report("ISO in container/iso directory", iso_path.parent.name == "iso")
            
            # Check autorun.inf was created
            autorun_path = payload_dir / "autorun.inf"
            report("autorun.inf created", autorun_path.exists())
            if autorun_path.exists():
                content = autorun_path.read_text()
                report("autorun.inf has correct volume", "TEST_ISO" in content)
            
        except Exception as e:
            report("build_iso(basic)", False, f"Exception: {e}")
            traceback.print_exc()

        # [2] Test ISO Creation Without Autorun
        print("\n[2] Testing ISO Creation Without Autorun")
        print("-" * 70)
        try:
            # Clear autorun.inf if it exists
            autorun_path = payload_dir / "autorun.inf"
            if autorun_path.exists():
                autorun_path.unlink()
            
            iso_path2 = container_iso.build_iso(
                volume_id="NO_AUTORUN",
                enable_autorun=False,
                build_path=build_dir,
                visible_extension=".exe"
            )
            
            report("ISO created without autorun", iso_path2.exists())
            report("autorun.inf not created", not (payload_dir / "autorun.inf").exists())
            
        except Exception as e:
            report("build_iso(no autorun)", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] Test Decoy File Integration
        print("\n[3] Testing Decoy File Integration")
        print("-" * 70)
        try:
            # Verify decoy file was copied to payload
            decoy_in_payload = payload_dir / "document.pdf"
            report("Decoy copied to payload dir", decoy_in_payload.exists())
            if decoy_in_payload.exists():
                report("Decoy content preserved", 
                       decoy_in_payload.read_bytes().startswith(b"%PDF-1.4"))
            
        except Exception as e:
            report("Decoy integration", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] Test ISO Name Generation
        print("\n[4] Testing ISO Name Generation")
        print("-" * 70)
        try:
            iso_path3 = container_iso.build_iso(
                volume_id="CUSTOM",
                build_path=build_dir
            )
            
            report("Default ISO name is erebus.iso", iso_path3.name == "erebus.iso")
            
        except Exception as e:
            report("ISO name generation", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] Test with Custom Source ISO
        print("\n[5] Testing with Custom Source ISO (Backdooring)")
        print("-" * 70)
        try:
            # Create a minimal source ISO for testing
            source_iso = temp_path / "source.iso"
            
            # First create an ISO to use as source
            iso_path4 = container_iso.build_iso(
                volume_id="SOURCE",
                build_path=build_dir
            )
            # Copy it as source
            shutil.copy(iso_path4, source_iso)
            
            # Now backdoor it
            backdoored_iso = container_iso.build_iso(
                volume_id="BACKDOOR",
                source_iso=source_iso,
                build_path=build_dir
            )
            
            report("Backdoored ISO created", backdoored_iso.exists())
            report("Backdoored ISO uses source name", backdoored_iso.name == "source.iso")
            
        except Exception as e:
            report("ISO backdooring", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Test Error Handling
        print("\n[6] Testing Error Handling")
        print("-" * 70)
        try:
            # Test with non-existent source ISO
            fake_source = temp_path / "fake.iso"
            iso_path5 = container_iso.build_iso(
                volume_id="TEST",
                source_iso=fake_source,
                build_path=build_dir
            )
            # Should create new ISO even if source doesn't exist
            report("Handles non-existent source ISO", iso_path5.exists())
            
        except Exception as e:
            report("Error handling", False, f"Exception: {e}")
            traceback.print_exc()

    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70 + "\n")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user.\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFATAL ERROR: {e}\n")
        traceback.print_exc()
        sys.exit(1)
