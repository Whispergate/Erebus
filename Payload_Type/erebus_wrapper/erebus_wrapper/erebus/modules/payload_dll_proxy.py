"""Generate DLL Proxy pragmas

Raises:
    Exception: Invalid File Type (Not a DLL)

Returns:
    str: DLL Pragmas in C format
"""

import pefile, asyncio

async def generate_proxies(dllfile):
    """Generate Pragma Linkers for DLL Hijacking

    Args:
        dllfile (bytes): DLL File to hijack

    Raises:
        Exception: File is not a DLL

    Returns:
        str: Linker Pragmas
    """
    if pefile.PE(dllfile).is_dll:
        dll_pe = pefile.PE(dllfile)
    else:
        raise Exception("[-] Invalid Selection: Target file is not a DLL.")

    if hasattr(dll_pe, 'DIRECTORY_ENTRY_EXPORT') and dll_pe.DIRECTORY_ENTRY_EXPORT:
        lines = ["EXPORTS"]
        for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                lines.append(f"{exp.name.decode()} @{exp.ordinal}")
        return "\n".join(lines)

# Test to see if the function generates anything
if __name__ == "__main__":
    pragmas = asyncio.run(generate_proxies("C:\\Windows\\System32\\winhttp.dll"))
    print(pragmas)