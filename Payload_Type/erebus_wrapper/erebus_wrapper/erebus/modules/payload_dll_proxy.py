"""Generate DLL Proxy pragmas

Raises:
    Exception: Invalid File Type (Not a DLL)

Returns:
    str: DLL Pragmas in C format
"""

import pefile

def generate_proxies(dllfile):
    if pefile.PE(dllfile).is_dll:
        dll_pe = pefile.PE(dllfile)
    else:
        raise Exception("[-] Invalid Selection: Target file is not a DLL.")

    pragmas = ""
    if hasattr(dll_pe, 'DIRECTORY_ENTRY_EXPORT') and dll_pe.DIRECTORY_ENTRY_EXPORT:
        for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                pragmas += f'#pragma comment(linker, "/export:{exp.name.decode()}={exp.name.decode()}@{exp.ordinal}")\n'

    return pragmas

# Test to see if the function generates anything
if __name__ == "__main__":
    pragmas = generate_proxies(r"C:\Windows\System32\winhttp.dll")
    print(pragmas)
