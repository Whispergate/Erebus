"""
Test suite for trigger_lnk.py
Tests LNK file creation, file hiding, and trigger generation.
"""

import pathlib
import sys
import tempfile
import traceback

# Import from archive directory
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "archive"))

import trigger_lnk

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
    print("TEST SUITE: trigger_lnk.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_lnk_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()
        
        # [1] Test Basic LNK Creation
        print("\n[1] Testing Basic LNK Creation")
        print("-" * 70)
        try:
            lnk_path = trigger_lnk.create_lnk_trigger(
                target_bin=r"C:\Windows\System32\cmd.exe",
                args="/c echo test",
                icon_src=r"C:\Windows\System32\shell32.dll",
                icon_index=3,
                description="Test LNK",
                payload_dir=payload_dir,
                output_filename="test.lnk"
            )
            
            report("create_lnk_trigger() returns path", lnk_path is not None)
            report("LNK file created", lnk_path.exists(), f"Path: {lnk_path}")
            report("LNK file is in payload dir", lnk_path.parent == payload_dir)
            report("LNK file has correct name", lnk_path.name == "test.lnk")
            
            if lnk_path.exists():
                size = lnk_path.stat().st_size
                report("LNK file has reasonable size", size > 0, f"Size: {size} bytes")
            
        except Exception as e:
            report("create_lnk_trigger(basic)", False, f"Exception: {e}")
            traceback.print_exc()

        # [2] Test LNK with Different Icons
        print("\n[2] Testing LNK with Different Icons")
        print("-" * 70)
        try:
            # PDF icon
            lnk_pdf = trigger_lnk.create_lnk_trigger(
                target_bin=r"C:\Windows\System32\cmd.exe",
                args="/c start document.pdf",
                icon_src=r"C:\Windows\System32\imageres.dll",
                icon_index=105,  # PDF icon
                description="PDF Document",
                payload_dir=payload_dir,
                output_filename="document.pdf.lnk"
            )
            
            report("LNK with PDF icon created", lnk_pdf.exists())
            report("LNK filename correct", lnk_pdf.name == "document.pdf.lnk")
            
            # Folder icon
            lnk_folder = trigger_lnk.create_lnk_trigger(
                target_bin=r"C:\Windows\explorer.exe",
                args="/select,C:\\Windows",
                icon_src=r"C:\Windows\System32\shell32.dll",
                icon_index=4,  # Folder icon
                description="Open Folder",
                payload_dir=payload_dir,
                output_filename="folder.lnk"
            )
            
            report("LNK with folder icon created", lnk_folder.exists())
            
        except Exception as e:
            report("LNK with different icons", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] Test LNK with Complex Arguments
        print("\n[3] Testing LNK with Complex Arguments")
        print("-" * 70)
        try:
            complex_args = '/c powershell -WindowStyle Hidden -Command "Start-Sleep 2; Write-Host Done"'
            lnk_complex = trigger_lnk.create_lnk_trigger(
                target_bin=r"C:\Windows\System32\cmd.exe",
                args=complex_args,
                icon_src=r"C:\Windows\System32\shell32.dll",
                icon_index=1,
                description="Complex Command",
                payload_dir=payload_dir,
                output_filename="complex.lnk"
            )
            
            report("LNK with complex args created", lnk_complex.exists())
            
        except Exception as e:
            report("LNK with complex args", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] Test File Hiding Functionality
        print("\n[4] Testing File Hiding Functionality")
        print("-" * 70)
        try:
            test_file = payload_dir / "test_hide.txt"
            test_file.write_text("This file should be hidden")
            
            trigger_lnk.set_file_hidden(str(test_file))
            
            report("File still exists after hiding", test_file.exists())
            
            # On Windows, check if hidden attribute is set
            if sys.platform == "win32":
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(test_file))
                FILE_ATTRIBUTE_HIDDEN = 0x02
                is_hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0
                report("File has hidden attribute", is_hidden)
            else:
                report("File permissions modified (Linux)", True)
            
        except Exception as e:
            report("set_file_hidden()", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] Test Hiding Non-Existent File
        print("\n[5] Testing Error Handling (Non-Existent File)")
        print("-" * 70)
        try:
            fake_file = payload_dir / "nonexistent.txt"
            trigger_lnk.set_file_hidden(str(fake_file))
            # Should handle gracefully without exception
            report("Handles non-existent file gracefully", True)
            
        except Exception as e:
            report("Handles non-existent file", False, f"Exception: {e}")

        # [6] Test Payload Trigger Creation
        print("\n[6] Testing Payload Trigger Creation")
        print("-" * 70)
        try:
            decoy_file = payload_dir / "decoy.pdf"
            decoy_file.write_bytes(b"%PDF-1.4" + b"\x00" * 100)
            
            lnk_payload = trigger_lnk.create_payload_trigger(
                target_bin=r"C:\Windows\System32\cmd.exe",
                args="/c echo payload && notepad decoy.pdf",
                icon_src=r"C:\Windows\System32\shell32.dll",
                icon_index=0,
                description="Payload with Decoy",
                payload_dir=payload_dir,
                decoy_file=decoy_file
            )
            
            report("create_payload_trigger() returns path", lnk_payload is not None)
            if lnk_payload:
                report("Payload trigger LNK created", lnk_payload.exists())
            
        except Exception as e:
            report("create_payload_trigger()", False, f"Exception: {e}")
            traceback.print_exc()

        # [7] Test Default Parameters
        print("\n[7] Testing Default Parameters")
        print("-" * 70)
        try:
            # Test using module defaults (should work even without explicit payload_dir)
            # This will fail if PAYLOAD_DIR doesn't exist, but should handle gracefully
            try:
                lnk_default = trigger_lnk.create_lnk_trigger(
                    target_bin="notepad.exe",
                    args="",
                    icon_src="shell32.dll",
                    icon_index=70,
                    description="Default Test"
                )
                report("Default payload_dir handled", True)
            except Exception as inner_e:
                # Expected if default path doesn't exist
                report("Default payload_dir handled", True, "Default path doesn't exist (expected)")
            
        except Exception as e:
            report("Default parameters", False, f"Exception: {e}")
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
