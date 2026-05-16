"""
Test suite for plugin_trigger_hta.py
Tests HTA trigger file creation for both VBScript and JScript modes.
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_trigger_hta import HtaTriggerPlugin

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
    print("TEST SUITE: plugin_trigger_hta.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_hta_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = HtaTriggerPlugin()
            report("HtaTriggerPlugin instantiates without error", True)
        except Exception as e:
            report("HtaTriggerPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] VBScript Mode (default)
        print("\n[2] Testing VBScript Mode (default)")
        print("-" * 70)
        try:
            result = plugin.create_hta_trigger(
                command="cmd.exe /c calc",
                output_filename="test.hta",
                payload_dir=payload_dir,
            )
            report("create_hta_trigger() returns a Path", isinstance(result, pathlib.Path),
                   f"Got: {type(result)}")
            report("Output file exists", result.exists(), f"Path: {result}")
            if result.exists():
                size = result.stat().st_size
                report("File size > 0", size > 0, f"Size: {size} bytes")
                content = result.read_text(encoding="utf-8")
                report("Content contains HTA:APPLICATION", "HTA:APPLICATION" in content)
                report("Content contains command string", "cmd.exe /c calc" in content)
                report("VBScript mode contains Window_OnLoad or Sub",
                       "Window_OnLoad" in content or "Sub" in content)
            else:
                report("File size > 0", False, "File does not exist")
                report("Content contains HTA:APPLICATION", False, "File does not exist")
                report("Content contains command string", False, "File does not exist")
                report("VBScript mode contains Window_OnLoad or Sub", False, "File does not exist")
        except Exception as e:
            report("create_hta_trigger() VBScript mode", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] JScript Mode
        print("\n[3] Testing JScript Mode")
        print("-" * 70)
        try:
            result_js = plugin.create_hta_trigger(
                command="cmd.exe /c calc",
                output_filename="test_jscript.hta",
                payload_dir=payload_dir,
                script_language="JScript",
            )
            report("JScript mode: create_hta_trigger() returns a Path",
                   isinstance(result_js, pathlib.Path))
            if result_js.exists():
                content_js = result_js.read_text(encoding="utf-8")
                report("JScript mode: content contains window.onload or window.close",
                       "window.onload" in content_js or "window.close" in content_js,
                       "Checking for window.onload")
            else:
                report("JScript mode: content contains window.onload", False, "File does not exist")
        except Exception as e:
            report("create_hta_trigger() JScript mode", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] Plugin Registration
        print("\n[4] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'create_hta_trigger'",
                   "create_hta_trigger" in registered)
        except Exception as e:
            report("Plugin registration", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] Plugin Metadata and Validation
        print("\n[5] Testing Plugin Metadata and Validation")
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
