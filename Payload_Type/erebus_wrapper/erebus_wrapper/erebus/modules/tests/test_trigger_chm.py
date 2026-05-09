"""
Test suite for plugin_trigger_chm.py
Tests CHM project directory generation (project.hhp, toc.hhc, default.html, build_chm.bat).
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_trigger_chm import TriggerChmPlugin

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
    print("TEST SUITE: plugin_trigger_chm.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_chm_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = TriggerChmPlugin()
            report("TriggerChmPlugin instantiates without error", True)
        except Exception as e:
            report("TriggerChmPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] CHM Project Creation
        print("\n[2] Testing CHM Project Directory Creation")
        print("-" * 70)
        chm_output_dir = str(payload_dir / "chm")
        try:
            result = plugin.create_chm_project(
                executable=r"C:\Windows\System32\cmd.exe",
                arguments="/c calc",
                output_dir=chm_output_dir,
            )
            report("create_chm_project() returns a Path", isinstance(result, pathlib.Path),
                   f"Got: {type(result)}")
            report("Output directory exists", result.exists() and result.is_dir(),
                   f"Path: {result}")
        except Exception as e:
            report("create_chm_project()", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [3] Required Files Present
        print("\n[3] Testing Required Project Files")
        print("-" * 70)
        out_path = pathlib.Path(chm_output_dir)
        try:
            hhp = out_path / "project.hhp"
            report("project.hhp exists", hhp.exists(), f"Path: {hhp}")

            hhc = out_path / "toc.hhc"
            report("toc.hhc exists", hhc.exists(), f"Path: {hhc}")

            html = out_path / "default.html"
            report("default.html exists", html.exists(), f"Path: {html}")

            bat = out_path / "build_chm.bat"
            report("build_chm.bat exists", bat.exists(), f"Path: {bat}")
        except Exception as e:
            report("Required project files check", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] default.html Content Verification
        print("\n[4] Testing default.html Content")
        print("-" * 70)
        try:
            html_path = out_path / "default.html"
            if html_path.exists():
                content = html_path.read_text(encoding="utf-8")
                report("default.html contains ShortCut CLSID (adb880a6)",
                       "adb880a6" in content.lower())
                report("default.html contains cmd.exe",
                       "cmd.exe" in content or "cmd" in content)
            else:
                report("default.html contains ShortCut CLSID (adb880a6)", False,
                       "default.html does not exist")
                report("default.html contains cmd.exe", False, "default.html does not exist")
        except Exception as e:
            report("default.html content verification", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] Custom Parameters
        print("\n[5] Testing Custom Parameters (rundll32 + custom CHM name)")
        print("-" * 70)
        chm_custom_dir = str(payload_dir / "chm_custom")
        try:
            result_custom = plugin.create_chm_project(
                executable=r"C:\Windows\System32\rundll32.exe",
                arguments="payload.dll,EntryPoint",
                output_dir=chm_custom_dir,
                chm_name="invoice.chm",
                title="Invoice Details",
                lure_text="Please wait while the document loads...",
            )
            report("Custom CHM project created", result_custom.exists())
            if result_custom.exists():
                html_custom = (pathlib.Path(chm_custom_dir) / "default.html")
                if html_custom.exists():
                    content_custom = html_custom.read_text(encoding="utf-8")
                    report("Custom title in default.html", "Invoice Details" in content_custom)
                    report("Custom lure text in default.html",
                           "Please wait while the document loads..." in content_custom)
                else:
                    report("Custom title in default.html", False, "default.html missing")
                    report("Custom lure text in default.html", False, "default.html missing")
        except Exception as e:
            report("Custom CHM parameters", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Plugin Registration
        print("\n[6] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'create_chm_project'",
                   "create_chm_project" in registered)
        except Exception as e:
            report("Plugin registration", False, f"Exception: {e}")
            traceback.print_exc()

        # [7] Plugin Metadata
        print("\n[7] Testing Plugin Metadata")
        print("-" * 70)
        try:
            meta = plugin.get_metadata()
            report("get_metadata() returns metadata", meta is not None)
        except Exception as e:
            report("Plugin metadata", False, f"Exception: {e}")
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
