"""
Test suite for codesigner.py
Tests certificate generation, remote cert scraping, and payload signing.
"""

import pathlib
import sys
import tempfile
import traceback

# Import from archive directory
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "archive"))

try:
    import codesigner
    CODESIGNER_AVAILABLE = True
except ImportError as e:
    CODESIGNER_AVAILABLE = False
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
    print("TEST SUITE: codesigner.py")
    print("=======================================================================\n")
    
    if not CODESIGNER_AVAILABLE:
        print(f"SKIPPED: {IMPORT_ERROR}")
        print("\nInstall required dependencies:")
        print("  pip install cryptography")
        print("\n" + "=" * 70)
        print(f"RESULTS: 0 passed, 0 failed (skipped due to missing dependencies)")
        print("=" * 70 + "\n")
        return 0  # Don't fail the test suite for missing optional dependencies
    
    with tempfile.TemporaryDirectory(prefix="erebus_codesigner_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        
        # [1] Test Remote Certificate Scraping
        print("\n[1] Testing Remote Certificate Scraping")
        print("-" * 70)
        try:
            cert_details = codesigner.get_remote_cert_details("https://www.microsoft.com")
            report("get_remote_cert_details(microsoft.com)", True, 
                   f"CN={cert_details.get('CN')}, O={cert_details.get('O')}")
            
            # Verify expected fields
            has_cn = cert_details.get("CN") is not None
            has_o = cert_details.get("O") is not None
            report("Certificate has CN field", has_cn, f"CN={cert_details.get('CN')}")
            report("Certificate has O field", has_o, f"O={cert_details.get('O')}")
            
        except Exception as e:
            report("get_remote_cert_details(microsoft.com)", False, f"Exception: {e}")
            traceback.print_exc()

        # [2] Test Self-Signing with Basic Details
        print("\n[2] Testing Self-Signing with Basic Details")
        print("-" * 70)
        try:
            # Create a dummy executable
            dummy_exe = temp_path / "test_payload.exe"
            dummy_exe.write_bytes(b"MZ" + b"\x00" * 1000)  # Minimal PE header
            
            codesigner.self_sign_payload(
                payload_path=dummy_exe,
                subject_cn="TestPayload",
                org_name="TestOrg"
            )
            
            # Check if file still exists (signing shouldn't delete it)
            report("Payload exists after signing", dummy_exe.exists())
            report("Payload size unchanged", dummy_exe.stat().st_size == 1002)
            
        except Exception as e:
            report("self_sign_payload(basic)", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] Test Self-Signing with Full Details (Spoofing)
        print("\n[3] Testing Self-Signing with Full Details (Spoofing)")
        print("-" * 70)
        try:
            dummy_exe2 = temp_path / "test_payload_spoofed.exe"
            dummy_exe2.write_bytes(b"MZ" + b"\x00" * 1000)
            
            full_details = {
                "C": "US",
                "ST": "Washington",
                "L": "Redmond",
                "O": "Microsoft Corporation",
                "OU": "Microsoft Corporation",
                "CN": "www.microsoft.com"
            }
            
            codesigner.self_sign_payload(
                payload_path=dummy_exe2,
                subject_cn="www.microsoft.com",
                org_name="Microsoft Corporation",
                full_details=full_details
            )
            
            report("Payload exists after spoofed signing", dummy_exe2.exists())
            report("Payload size unchanged after spoofing", dummy_exe2.stat().st_size == 1002)
            
        except Exception as e:
            report("self_sign_payload(spoofed)", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] Test Signing Non-Existent File
        print("\n[4] Testing Error Handling (Non-Existent File)")
        print("-" * 70)
        try:
            fake_path = temp_path / "nonexistent.exe"
            codesigner.self_sign_payload(
                payload_path=fake_path,
                subject_cn="Test",
                org_name="Test"
            )
            # Should silently return without error when file doesn't exist
            report("Handles non-existent file gracefully", True)
            
        except Exception as e:
            report("Handles non-existent file gracefully", False, f"Exception: {e}")

        # [5] Test Remote Cert Scraping Error Handling
        print("\n[5] Testing Remote Cert Scraping Error Handling")
        print("-" * 70)
        try:
            cert_details = codesigner.get_remote_cert_details("https://invalid-domain-12345.com")
            report("Handles invalid domain", False, "Should have raised exception")
        except Exception as e:
            report("Handles invalid domain", True, f"Correctly raised: {type(e).__name__}")

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
