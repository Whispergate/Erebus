"""
Erebus VBA Compiler
Compiles VBA source code into a valid vbaProject.bin OLE compound file
that can be injected into XLSX/XLSM archives.

Based on the MS-OVBA specification (MS-OVBA v14.0).
Uses ms-ovba-compression for VBA stream compression when available,
with a built-in fallback compressor.
"""

from .compiler import compile_vba_project, compile_vba_project_to_file

__all__ = ["compile_vba_project", "compile_vba_project_to_file"]
