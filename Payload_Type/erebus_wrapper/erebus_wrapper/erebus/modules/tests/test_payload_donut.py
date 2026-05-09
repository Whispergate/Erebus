"""
Test suite for plugin_payload_donut.py
Tests Donut PE/DLL/.NET to shellcode conversion integration.

donut-shellcode is an optional dependency. Tests adapt gracefully when
the package is not installed - donut_available() returning False is a
valid non-error state.
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_payload_donut import PayloadDonutPlugin

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
    print("TEST SUITE: plugin_payload_donut.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_donut_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = PayloadDonutPlugin()
            report("PayloadDonutPlugin instantiates without error", True)
        except Exception as e:
            report("PayloadDonutPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] donut_available() - must return bool without exception
        print("\n[2] Testing donut_available()")
        print("-" * 70)
        donut_present = None
        try:
            result = plugin.donut_available()
            donut_present = result
            report("donut_available() returns bool without exception",
                   isinstance(result, bool), f"Returned: {result}")
            report("donut_available() result is True or False (not None)",
                   result is not None)
            print(f"    [info] donut-shellcode package installed: {result}")
        except Exception as e:
            report("donut_available() returns bool", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] donut_convert() - non-existent input path
        print("\n[3] Testing donut_convert() with Non-Existent Input")
        print("-" * 70)
        nonexistent = "/nonexistent/file.exe"
        fake_output = str(payload_dir / "out.bin")
        try:
            ok, msg = plugin.donut_convert(
                input_path=nonexistent,
                output_path=fake_output,
            )
            report("donut_convert() returns (bool, str) tuple",
                   isinstance(ok, bool) and isinstance(msg, str),
                   f"Got: ({ok!r}, {msg!r})")
            report("donut_convert() returns False for non-existent file",
                   ok is False, f"ok={ok}, msg={msg}")
            report("Error message mentions the missing path",
                   "nonexistent" in msg or "not found" in msg.lower() or "exist" in msg.lower(),
                   f"msg: {msg}")
        except Exception as e:
            report("donut_convert() graceful failure", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] donut_convert() - valid path but non-PE file (when donut available)
        print("\n[4] Testing donut_convert() with Non-PE File (if donut installed)")
        print("-" * 70)
        if donut_present:
            non_pe = payload_dir / "not_a_pe.txt"
            non_pe.write_text("this is not a PE file")
            fake_output2 = str(payload_dir / "out2.bin")
            try:
                ok2, msg2 = plugin.donut_convert(
                    input_path=str(non_pe),
                    output_path=fake_output2,
                )
                report("donut_convert() returns (bool, str) for non-PE input",
                       isinstance(ok2, bool) and isinstance(msg2, str),
                       f"Got: ({ok2!r}, {msg2!r})")
                # It should either fail gracefully or succeed - either is acceptable
                report("donut_convert() does not raise exception for non-PE input", True)
            except Exception as e:
                report("donut_convert() non-PE input handled gracefully", False,
                       f"Unhandled exception: {e}")
                traceback.print_exc()
        else:
            # donut not installed - test that the "not installed" path returns correctly
            dummy_path = payload_dir / "dummy.exe"
            dummy_path.write_bytes(b"MZ" + b"\x00" * 510)
            dummy_output = str(payload_dir / "dummy_out.bin")
            try:
                ok_ni, msg_ni = plugin.donut_convert(
                    input_path=str(dummy_path),
                    output_path=dummy_output,
                )
                report("donut not installed: donut_convert() returns (False, msg)",
                       ok_ni is False, f"Got: ({ok_ni!r}, {msg_ni!r})")
                report("donut not installed: message mentions pip install",
                       "pip" in msg_ni.lower() or "install" in msg_ni.lower(),
                       f"msg: {msg_ni}")
            except Exception as e:
                report("donut not installed: graceful failure", False, f"Exception: {e}")
                traceback.print_exc()

        # [5] Plugin Registration
        print("\n[5] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'donut_convert'", "donut_convert" in registered)
            report("register() contains 'donut_available'", "donut_available" in registered)
        except Exception as e:
            report("Plugin registration", False, f"Exception: {e}")
            traceback.print_exc()

        # [6] Plugin Metadata and Validation
        print("\n[6] Testing Plugin Metadata and Validation")
        print("-" * 70)
        try:
            meta = plugin.get_metadata()
            report("get_metadata() returns metadata", meta is not None)
            valid = plugin.validate()
            report("validate() returns True (donut absence is not a load failure)",
                   valid is True)
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
