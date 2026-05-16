"""Integration smoke harness for builder.build().

Purpose: safety net for the R2/R3 phase-extraction refactor. Runs build()
end-to-end against a canned parameter fixture, captures the artifacts the
refactor is likely to regress (rendered config.hpp, subprocess command
vectors, final BuildResponse status), and diffs them against golden files
stored alongside this script.

Pre-R1 this harness does not exist and the refactor would be flying blind.
Post-R1 it gates every R2/R3 commit - if an extraction changes any captured
artifact, the test fails loudly and the diff tells the operator whether
the change was intended.

Not a pytest test - runs as a plain script so it works both on the host
(via mythic_stub) and inside the Mythic docker container (where the real
mythic_container exists). Exit code 0 = pass, non-zero = fail.
"""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Path layout: .../Payload_Type/erebus_wrapper/erebus_wrapper/tests/integration
# parents[2] is the outer Payload_Type/erebus_wrapper package root, which
# must be on sys.path so `erebus_wrapper.erebus.builder` resolves.
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

import mythic_stub
mythic_stub.install()

# Importing builder.py registers all plugins via the module-level loader.
from erebus_wrapper.erebus import builder  # noqa: E402


# ---------------------------------------------------------------------------
# Subprocess capture layer
# ---------------------------------------------------------------------------
#
# builder.py uses both async (`asyncio.create_subprocess_exec`) and sync
# (`subprocess.check_output`) subprocess invocations. We intercept both at
# the module level, record every call, and return canned outputs.
#
# The canned outputs are deliberately minimal. They emulate shellcrypt and
# make producing valid artifacts without actually invoking any toolchain.
# ---------------------------------------------------------------------------

subprocess_log: list = []


class _FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


def _canned_shellcrypt_output(cmd: list) -> bytes:
    """Produce a byte blob that looks like shellcrypt's output.

    Build() writes the obfuscated payload to `-o <path>` and parses the
    key/IV out of the C-format stdout on the key-extraction pass. We:
    1. Always touch the `-o` file with canned bytes if the cmd has `-o`.
    2. Print a shellcrypt-flavoured C source on stdout so the key/IV regex
       in build() can extract a plausible key/IV.
    """
    if "-o" in cmd:
        idx = cmd.index("-o")
        out_path = cmd[idx + 1]
        with open(out_path, "wb") as f:
            f.write(b"\xde\xad\xbe\xef" * 64)  # 256 bytes of obfuscated junk
    c_source = (
        b"// canned shellcrypt output\n"
        b"unsigned char key[] = { 0x01, 0x02, 0x03, 0x04 };\n"
        b"unsigned char iv[] = { "
        + b", ".join([b"0x00"] * 16)
        + b" };\n"
        b"unsigned char shellcode[] = { 0xde, 0xad, 0xbe, 0xef };\n"
    )
    return c_source


def _canned_make_output(cmd: list) -> tuple:
    """Emulate `make -C <path> TARGET=exe ... all` producing a PE at the
    expected output path. We look at TARGET=... and touch the right file
    in shellcode_loader_path."""
    target = "exe"
    loader_path = None
    for arg in cmd:
        if arg.startswith("TARGET="):
            target = arg.split("=", 1)[1]
        if arg.startswith("/tmp/") and "Erebus.Loader" in arg:
            loader_path = arg
    # -C <path> form
    if "-C" in cmd:
        loader_path = cmd[cmd.index("-C") + 1]
    if loader_path and target in ("exe", "dll", "cpl", "xll"):
        out_path = Path(loader_path) / f"erebus.{target}"
        # Minimal valid PE stub (MZ + PE signatures enough to parse)
        pe = bytearray(b"MZ")
        pe += b"\x00" * (0x3C - 2)
        pe += b"\x80\x00\x00\x00"  # e_lfanew -> 0x80
        pe += b"\x00" * (0x80 - len(pe))
        pe += b"PE\x00\x00"        # PE sig
        # IMAGE_FILE_HEADER (20 bytes): Machine, NumSections, TimeDateStamp,
        # PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader (0xF0), Characteristics
        pe += b"\x64\x86"          # Machine = AMD64
        pe += b"\x01\x00"          # NumberOfSections = 1
        pe += b"\x00\x00\x00\x00"  # TimeDateStamp
        pe += b"\x00\x00\x00\x00"  # PointerToSymbolTable
        pe += b"\x00\x00\x00\x00"  # NumberOfSymbols
        pe += b"\xF0\x00"          # SizeOfOptionalHeader
        pe += b"\x00\x00"          # Characteristics
        # IMAGE_OPTIONAL_HEADER64 magic + minimum padding
        pe += b"\x0b\x02"          # Magic = PE32+
        pe += b"\x00" * (0xF0 - 2) # rest of opt header (zeros is fine for test)
        # One section header (.text)
        pe += b".text\x00\x00\x00"  # Name
        pe += b"\x00" * 32           # rest of section header
        out_path.write_bytes(bytes(pe))
    return (b"", b"")


# ---------------------------------------------------------------------------
# Patch asyncio.create_subprocess_exec + subprocess.check_output in the
# builder module namespace.
# ---------------------------------------------------------------------------

async def fake_create_subprocess_exec(*cmd, stdout=None, stderr=None, **kwargs):
    cmd_list = list(cmd)
    subprocess_log.append({"kind": "async_exec", "cmd": cmd_list})
    first = Path(cmd_list[0]).name if cmd_list else ""
    if first == "make" or "make" in first:
        out, err = _canned_make_output(cmd_list)
        return _FakeProcess(stdout=out, stderr=err, returncode=0)
    # Assume anything else is shellcrypt (python shellcrypt.py ...)
    _canned_shellcrypt_output(cmd_list)  # side effect: touches -o file
    return _FakeProcess(stdout=b"", stderr=b"", returncode=0)


def fake_check_output(cmd, *args, **kwargs):
    subprocess_log.append({"kind": "sync_check_output", "cmd": list(cmd)})
    # builder.py uses this for the key/IV extraction pass and for getting the
    # raw-format C key array. Both want shellcrypt-shaped C source on stdout.
    data = _canned_shellcrypt_output(list(cmd))
    return data.decode() if kwargs.get("text") else data


def install_subprocess_patches():
    builder.asyncio.create_subprocess_exec = fake_create_subprocess_exec
    builder.subprocess.check_output = fake_check_output


# ---------------------------------------------------------------------------
# Fixture: a minimal Shellcode Loader happy-path parameter dict.
# Every parameter name the builder reads during the Shellcode Loader flow
# must be present here with a plausible value.
# ---------------------------------------------------------------------------

def shellcode_loader_fixture() -> dict:
    return {
        # Phase 1 - shellcode source
        "0.0 Main Payload Type": "Loader",
        "0.0a Enable Custom Shellcode": False,
        "0.0b Custom Shellcode File": None,
        "0.1 Loader Type": "Shellcode Loader",
        "0.2 Loader Format": "exe",
        "0.2a Loader Architecture": "x64",
        "0.3 Loader Build Configuration": "release",
        "0.4 Shellcode Loader - Injection Type": 3,

        # Phase 3 - Shellcrypt obfuscation
        "2.0 Compression Type": "NONE",
        "2.1 Encryption Type": "XOR",
        "2.2 Encryption Key": "NONE",
        "2.3 Encoding Type": "NONE",
        "2.4 Shellcode Format": "C",

        # Phase 4 - loader config
        "0.5 Shellcode Loader - Target Process": "C:\\\\Windows\\\\System32\\\\notepad.exe",
        "0.13 Decoy File Inclusion": False,

        # Guardrails (Shellcode Loader path, 0.5* namespace)
        "0.5a Enable Guardrails": False,
        "0.5b Check IsDebuggerPresent": False,
        "0.5c Check Remote Debugger": False,
        "0.5d Check Debugger Processes": False,
        "0.5e Check Hardware Breakpoints": False,
        "0.5f Check Timing Anomalies": False,
        "0.5f1 Check Sandbox Environment": False,
        "0.5g Hostname Whitelist": "",
        "0.5h Block Analysis Hostnames": "",
        "0.5i Block Analysis Usernames": "",
        "0.5j IP Whitelist": "",
        "0.5k IP Blacklist": "",
        "0.5l Domain Whitelist": "",

        # Codesign off
        "0.11 Codesign": "Disabled",

        # MalDoc off
        "0.9 Create MalDoc": "None",
        "0.8 Output Extension Source": "Trigger",

        # Trigger + container (minimal): BAT is pure-Python (no host-only
        # deps like pylnk3/pycdlib), so it completes on the host harness
        # without needing optional packages installed.
        "0.9 Trigger Type": "BAT",
        "0.9a Trigger Binary": "",
        "0.9b Trigger Command": "/c start /min erebus.exe",
        "3.0 Container Type": "Zip",
        "3.1 Compression Level": "5",
        "3.2 Archive Password": "",
    }


# ---------------------------------------------------------------------------
# FakeWrapper - subclass that short-circuits the real Mythic wiring
# ---------------------------------------------------------------------------

class FakeWrapper(builder.ErebusWrapper):
    """Test double that supplies parameters from a fixture dict.

    Avoids the Mythic lifecycle entirely - we instantiate directly and set
    self.wrapped_payload, self._params, self.uuid as plain attributes.
    """

    def __init__(self, params: dict, wrapped_payload: bytes = b""):
        # Bypass PayloadType.__init__ and avoid running the class-level
        # build_parameters inspector, which the real Mythic framework
        # would call.
        self.uuid = "test-uuid-0000"
        self.wrapped_payload = wrapped_payload
        self._params = params
        # agent_code_path is resolved from builder.__file__ inside build(),
        # so the real agent_code tree gets copied. Nothing to set here.

    def get_parameter(self, name: str):
        return self._params.get(name)


# ---------------------------------------------------------------------------
# Harness runner
# ---------------------------------------------------------------------------

def capture_artifacts(agent_build_path: str) -> dict:
    """Snapshot the build-tree files that matter for regression checking."""
    artifacts = {}
    root = Path(agent_build_path)
    config_hpp = root / "Erebus.Loaders" / "Erebus.Loader" / "include" / "config.hpp"
    if config_hpp.exists():
        content = config_hpp.read_bytes()
        artifacts["config_hpp_size"] = len(content)
        # Strip the random XOR key so the hash is stable across runs.
        # (config.hpp gets a fresh per-build key injected by
        # build_guardrail_encryption; we want the structural hash, not the
        # nonce-bearing one.)
        import re
        stripped = re.sub(
            rb"g_gr_xor_key\[GR_XOR_KEYLEN\] = \{ [^}]+\}",
            b"g_gr_xor_key[GR_XOR_KEYLEN] = { <STRIPPED> }",
            content,
        )
        artifacts["config_hpp_stable_sha256"] = hashlib.sha256(stripped).hexdigest()
    return artifacts


def summarize_subprocess_log(log: list) -> list:
    """Return a stable summary of subprocess calls suitable for diffing.

    We strip tmp paths (always unique per run) and the EREBUS_HASH_SEED
    argument (randomized per build).
    """
    import re
    tmp_re = re.compile(r"/tmp/[^/]+")
    out = []
    for entry in log:
        cmd = entry["cmd"]
        stable = []
        for arg in cmd:
            a = tmp_re.sub("/tmp/<TMP>", str(arg))
            if a.startswith("EREBUS_HASH_SEED="):
                a = "EREBUS_HASH_SEED=<RAND>"
            stable.append(a)
        out.append({"kind": entry["kind"], "cmd": stable})
    return out


async def run_shellcode_loader_smoke() -> dict:
    """Execute build() end-to-end for the Shellcode Loader happy path.

    Returns a dict of captured artifacts + RPC call summaries, which the
    caller diffs against a golden file.
    """
    mythic_stub.reset_stub_state()
    subprocess_log.clear()
    install_subprocess_patches()

    wrapper = FakeWrapper(shellcode_loader_fixture(), wrapped_payload=b"\x90" * 128)

    # Run build(). It creates its own tempdir from builder.tempfile; we
    # capture the agent_build_path by hooking into the temp-dir name so we
    # can snapshot artifacts after build() returns.
    captured_path = {}
    orig_tempdir = builder.tempfile.TemporaryDirectory
    def wrapper_tempdir(*args, **kwargs):
        td = orig_tempdir(*args, **kwargs)
        captured_path["path"] = td.name
        return td
    builder.tempfile.TemporaryDirectory = wrapper_tempdir
    try:
        response = await wrapper.build()
    finally:
        builder.tempfile.TemporaryDirectory = orig_tempdir

    agent_build_path = captured_path.get("path", "")
    artifacts = capture_artifacts(agent_build_path)

    result = {
        "response_status": str(getattr(response.status, "value", response.status)),
        "response_build_message": response.build_message,
        "response_build_stderr_head": response.build_stderr[:500],
        "artifacts": artifacts,
        "subprocess": summarize_subprocess_log(subprocess_log),
        "rpc_step_names": [e["StepName"] for e in mythic_stub.rpc_log if e["kind"] == "build_step"],
    }
    return result


def maldoc_command_execution_fixture() -> dict:
    """Shellcode Loader + MalDoc command-execution mode fixture.

    Exercises the R3a code path: builder.py calls the auto-discovered
    `generate_command_execution_vba` function registered by the maldocs
    plugin, instead of the inline `PayloadMalDocsPlugin()` class
    instantiation that existed pre-R3a. Captures the rendered VBA blob
    as an additional artifact.
    """
    params = shellcode_loader_fixture()
    params["0.8 Output Extension Source"] = "MalDoc"
    params["0.9 Create MalDoc"] = "Generate New"
    params["0.9a MalDoc Type"] = "Generate New"
    params["0.9c VBA Execution Trigger"] = "AutoOpen"
    params["0.9d Excel Document Name"] = "Invoice.xlsm"
    params["0.9e Obfuscate VBA"] = False
    params["0.9f MalDoc Injection Type"] = "Command Execution"
    params["0.9f1 MalDoc Trigger Binary"] = "cmd.exe"
    params["0.9f2 MalDoc Trigger Command"] = "/c start /min erebus.exe"
    return params


async def run_maldoc_smoke() -> dict:
    """Run build() with the MalDoc command-execution fixture.

    The harness primarily verifies that the R3a refactor (which replaced
    the inline `PayloadMalDocsPlugin()` instantiation with a direct call
    through the plugin-registry globals) actually dispatches to the
    plugin function without raising. The full MalDoc build path touches
    the excel file generation which would need openpyxl at runtime -
    that still raises, so we expect the build to fail at the Excel step
    but AFTER successfully generating the VBA code, which is the R3a
    surface we're validating.
    """
    mythic_stub.reset_stub_state()
    subprocess_log.clear()
    install_subprocess_patches()
    wrapper = FakeWrapper(maldoc_command_execution_fixture(), wrapped_payload=b"\x90" * 128)
    orig_tempdir = builder.tempfile.TemporaryDirectory
    captured_path = {}
    def wrapper_tempdir(*args, **kwargs):
        td = orig_tempdir(*args, **kwargs)
        captured_path["path"] = td.name
        return td
    builder.tempfile.TemporaryDirectory = wrapper_tempdir
    try:
        response = await wrapper.build()
    finally:
        builder.tempfile.TemporaryDirectory = orig_tempdir

    return {
        "response_status": str(getattr(response.status, "value", response.status)),
        "response_build_message_head": response.build_message[:200],
        "rpc_step_names": [e["StepName"] for e in mythic_stub.rpc_log if e["kind"] == "build_step"],
    }


GOLDEN_PATH = HERE / "golden_shellcode_loader.json"
MALDOC_GOLDEN_PATH = HERE / "golden_maldoc_command_exec.json"


def _run_and_compare(runner, golden_path, label, update: bool) -> int:
    try:
        result = asyncio.run(runner())
    except Exception:
        traceback.print_exc()
        print(f"[FAIL] {label} harness crashed")
        return 2

    result_json = json.dumps(result, indent=2, sort_keys=True)
    if update or not golden_path.exists():
        golden_path.write_text(result_json + "\n")
        print(f"[ok] wrote golden: {golden_path.name}")
        return 0

    golden = golden_path.read_text()
    if result_json + "\n" == golden:
        print(f"[ok] {label} matches golden ({golden_path.name})")
        return 0

    print(f"[FAIL] {label} DIFFERS from golden!")
    import difflib
    for line in difflib.unified_diff(
        golden.splitlines(keepends=True),
        (result_json + "\n").splitlines(keepends=True),
        fromfile=str(golden_path),
        tofile="<current>",
    ):
        sys.stdout.write(line)
    return 1


def main():
    argv = sys.argv[1:]
    update = "--update-golden" in argv

    rc_sc = _run_and_compare(run_shellcode_loader_smoke, GOLDEN_PATH, "shellcode_loader", update)
    rc_md = _run_and_compare(run_maldoc_smoke, MALDOC_GOLDEN_PATH, "maldoc_command_exec", update)
    return max(rc_sc, rc_md)


if __name__ == "__main__":
    sys.exit(main())
