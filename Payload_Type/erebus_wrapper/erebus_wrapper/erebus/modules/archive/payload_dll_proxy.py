"""Generate DLL Proxy pragmas

Raises:
    Exception: Invalid File Type (Not a DLL)

Returns:
    str: .def file contents for DLL proxy hijacking
"""

import pefile, asyncio
import os


async def generate_proxies(dll_file, dll_file_name):
    """Generate a .def file for DLL proxy hijacking.

    All exports are forwarded to a renamed copy of the original DLL
    (<name>_orig.dll).  This satisfies the linker (no local symbol needed)
    and keeps the host process functional regardless of whether the target
    is a Windows system DLL or a custom/third-party DLL.

    Args:
        dll_file (Path): DLL File to hijack
        dll_file_name (str): Original DLL filename

    Raises:
        Exception: File is not a DLL

    Returns:
        str: Contents of the .def file
    """
    if pefile.PE(dll_file).is_dll:
        dll_pe = pefile.PE(dll_file)
    else:
        raise Exception("[-] Invalid Selection: Target file is not a DLL.")

    module_name = os.path.splitext(dll_file_name)[0]
    forward_target = f"{module_name}_orig"

    if not hasattr(dll_pe, 'DIRECTORY_ENTRY_EXPORT') or not dll_pe.DIRECTORY_ENTRY_EXPORT:
        return ""

    lines = [f"LIBRARY {module_name}", "EXPORTS"]

    for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            name = exp.name.decode()
            lines.append(f"    {name}={forward_target}.{name} @{exp.ordinal}")
        else:
            lines.append(f"    @{exp.ordinal} NONAME")

    return "\n".join(lines)


# Test to see if the function generates anything
if __name__ == "__main__":
    pragmas = asyncio.run(generate_proxies(r"F:\Program Files\KeePass Password Safe 2\KeePassLibN.a64.dll", "KeePassLibN.a64.dll"))
    print(pragmas)
