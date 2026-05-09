"""
Test suite for plugin_trigger_jscript.py
Tests JScript (.js) and Windows Script File (.wsf) trigger creation.
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_trigger_jscript import JScriptTriggerPlugin

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
    print("TEST SUITE: plugin_trigger_jscript.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_jscript_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = JScriptTriggerPlugin()
            report("JScriptTriggerPlugin instantiates without error", True)
        except Exception as e:
            report("JScriptTriggerPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] Basic JScript Trigger Creation
        print("\n[2] Testing Basic JScript Trigger Creation")
        print("-" * 70)
        try:
            result = plugin.create_jscript_trigger(
                command="cmd.exe /c calc",
                output_filename="test.js",
                payload_dir=payload_dir,
            )
            report("create_jscript_trigger() returns a Path", isinstance(result, pathlib.Path),
                   f"Got: {type(result)}")
            report("JS file exists", result.exists(), f"Path: {result}")
            if result.exists():
                size = result.stat().st_size
                report("JS file size > 0", size > 0, f"Size: {size} bytes")
                content = result.read_text(encoding="utf-8")
                report("Content contains WScript.Shell or ActiveXObject",
                       "WScript.Shell" in content or "ActiveXObject" in content)
            else:
                report("JS file size > 0", False, "File does not exist")
                report("Content contains WScript.Shell or ActiveXObject", False, "File does not exist")
        except Exception as e:
            report("create_jscript_trigger() basic", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] Obfuscated Mode
        print("\n[3] Testing Obfuscated Mode (fromCharCode)")
        print("-" * 70)
        try:
            result_obf = plugin.create_jscript_trigger(
                command="cmd.exe /c calc",
                output_filename="test_obf.js",
                payload_dir=payload_dir,
                obfuscate_command=True,
            )
            report("Obfuscated JScript trigger created", result_obf.exists())
            if result_obf.exists():
                content_obf = result_obf.read_text(encoding="utf-8")
                report("Obfuscated content contains fromCharCode",
                       "fromCharCode" in content_obf)
            else:
                report("Obfuscated content contains fromCharCode", False, "File does not exist")
        except Exception as e:
            report("Obfuscated JScript mode", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] Non-Obfuscated Mode (for comparison)
        print("\n[4] Testing Non-Obfuscated Mode")
        print("-" * 70)
        try:
            result_plain = plugin.create_jscript_trigger(
                command="cmd.exe /c calc",
                output_filename="test_plain.js",
                payload_dir=payload_dir,
                obfuscate_command=False,
            )
            report("Plain JScript trigger created", result_plain.exists())
            if result_plain.exists():
                content_plain = result_plain.read_text(encoding="utf-8")
                report("Plain content contains ActiveXObject",
                       "ActiveXObject" in content_plain)
        except Exception as e:
            report("Non-obfuscated JScript mode", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] WSF Trigger Creation
        print("\n[5] Testing WSF Trigger Creation")
        print("-" * 70)
        try:
            result_wsf = plugin.create_wsf_trigger(
                command="cmd.exe /c calc",
                output_filename="test.wsf",
                payload_dir=payload_dir,
            )
            report("create_wsf_trigger() returns a Path",
                   isinstance(result_wsf, pathlib.Path))
            report("WSF file exists", result_wsf.exists(), f"Path: {result_wsf}")
            if result_wsf.exists():
                size = result_wsf.stat().st_size
                report("WSF file size > 0", size > 0, f"Size: {size} bytes")
                content_wsf = result_wsf.read_text(encoding="utf-8")
                report("WSF content contains <job>", "<job" in content_wsf)
                report("WSF content contains <script", "<script" in content_wsf)
            else:
                report("WSF file size > 0", False, "File does not exist")
                report("WSF content contains <job>", False, "File does not exist")
                report("WSF content contains <script", False, "File does not exist")
        except Exception as e:
            report("create_wsf_trigger()", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Plugin Registration
        print("\n[6] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'create_jscript_trigger'",
                   "create_jscript_trigger" in registered)
            report("register() contains 'create_wsf_trigger'",
                   "create_wsf_trigger" in registered)
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
