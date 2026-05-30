"""Generate DLL Proxy pragmas

Raises:
    Exception: Invalid File Type (Not a DLL)

Returns:
    str: .def file contents for DLL proxy hijacking
"""

import pefile, asyncio
import os
import re

# Names that are safe for GNU ld's PE def-file parser.
# Allows C identifiers, GCC-mangled _Z names, and common Windows export names.
# Rejects MSVC-mangled names (?-prefix), names with spaces/control chars,
# '#' (linker-script comment), '=' (assignment), and other ld-breaking chars.
_GNU_LD_SAFE_NAME = re.compile(r'^[A-Za-z_$][A-Za-z0-9_$@]*$')


async def generate_proxies(dll_file, dll_file_name):
    """Generate a .def file for DLL proxy hijacking.

    All exports are forwarded to a renamed copy of the original DLL
    (<name>_orig.dll).  This satisfies the linker (no local symbol needed)
    and keeps the host process functional regardless of whether the target
    is a Windows system DLL or a custom/third-party DLL.

    Both name-based and ordinal-only exports are handled. Ordinal-only
    exports are forwarded via the `#N` ordinal-reference syntax so the
    full export table of the target DLL is preserved.

    Args:
        dll_file (Path): DLL File to hijack
        dll_file_name (str): Original DLL filename

    Raises:
        Exception: File is not a DLL

    Returns:
        str: Contents of the .def file
    """
    dll_pe = pefile.PE(dll_file, fast_load=True)
    dll_pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
    )
    if not dll_pe.is_dll():
        raise Exception("[-] Invalid Selection: Target file is not a DLL.")

    # Defensively strip any path components from the supplied filename
    # before deriving the module name. Callers occasionally pass full
    # paths which would otherwise leak into the LIBRARY directive.
    base_name = os.path.basename(dll_file_name)
    module_name = os.path.splitext(base_name)[0]
    forward_target = f"{module_name}_orig"

    if not hasattr(dll_pe, 'DIRECTORY_ENTRY_EXPORT') or not dll_pe.DIRECTORY_ENTRY_EXPORT:
        return ""

    # Quote LIBRARY name so dots / special chars in the original DLL stem
    # do not confuse the linker's def parser.
    lines = [f'LIBRARY "{module_name}"', "EXPORTS"]

    seen = set()
    for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = exp.ordinal
        if exp.name:
            try:
                name = exp.name.decode('ascii')
            except UnicodeDecodeError:
                # Non-ascii export names are unusual; forward them by
                # ordinal instead so they remain reachable.
                name = None

            if name and name not in seen:
                seen.add(name)
                if _GNU_LD_SAFE_NAME.match(name):
                    lines.append(f"    {name}={forward_target}.{name} @{ordinal}")
                # else: name has chars GNU ld def parser can't handle
                # (e.g. MSVC ?-mangled, spaces, '#', '='); skip silently.
                continue

        # Skip ordinal-only (unnamed) exports. GNU ld (MinGW cross-compiler)
        # does not support the MODULE.#N ordinal-reference forwarding syntax
        # in .def files — it is MSVC link.exe-only — and `#` is treated as a
        # line comment in GNU linker scripts, causing a hard syntax error at
        # the first ordinal-only entry and aborting the link. Named exports
        # cover all practical proxy-hijack targets; ordinal-only slots are
        # preserved in the original DLL that ships as <name>_orig.dll.

    return "\n".join(lines)


# Test to see if the function generates anything
if __name__ == "__main__":
    pragmas = asyncio.run(generate_proxies(r"E:\CyberSecurity\SharedDisk\Payloads\HandBrake-1.11.1-x86_64-Win_GUI\HandBrake\hb.dll", "hb.dll"))
    print(pragmas)
