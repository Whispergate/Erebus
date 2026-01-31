"""
Erebus Plugin - Code Signer
Author: Whispergate
Description: Signs payloads with self-signed or legitimate certificates

This plugin provides code signing capabilities including certificate scraping,
self-signing with custom certificates, and signing with provided certificate files.
Uses cryptography library and osslsigncode for PE file signing.
"""

import pathlib
import subprocess
from typing import Dict, Callable, Optional

try:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class CodeSignerPlugin(ErebusPlugin):
    """
    Plugin for code signing operations on Windows PE files.
    
    This plugin provides multiple signing strategies:
    - Certificate detail scraping from HTTPS endpoints
    - Self-signing with auto-generated certificates
    - Signing with provided PFX/P12 certificate files
    
    Signing payloads with valid-looking certificates can help evade
    security controls that check for unsigned binaries.
    """
    
    def __init__(self):
        """Initialize the code signer plugin"""
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"
        self.PAYLOAD_DIR = self.AGENT_CODE / "payload"
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="codesigner",
            version="1.0.0",
            author="Whispergate",
            description="Signs payloads with self-signed or legitimate certificates",
            category=PluginCategory.CODESIGNER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "get_remote_cert_details": self.get_remote_cert_details,
            "self_sign_payload": self.self_sign_payload,
            "sign_with_provided_cert": self.sign_with_provided_cert,
        }
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate that osslsigncode is available"""
        try:
            subprocess.check_output(["osslsigncode", "--version"], stderr=subprocess.DEVNULL)
            return (True, None)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return (False, "osslsigncode not found. Please install osslsigncode for code signing.")
    
    def on_load(self):
        """Called when plugin is loaded"""
        print(f"[Plugin] Code Signer plugin loaded - Supporting PE file signing operations")
    
    def _get_codesigner(self):
        """Lazy import for archive.codesigner"""
        try:
            from .archive import codesigner
        except ImportError:
            from archive import codesigner
        return codesigner
    # ==================== Plugin Functions ====================
    
    def get_remote_cert_details(self, url: str) -> dict:
        """
        Scrapes detailed X.509 certificate attributes from a remote URL.
        
        Connects to an HTTPS endpoint and extracts certificate information
        that can be used for certificate spoofing/cloning attacks.
        
        Args:
            url: URL to scrape certificate from (e.g., "https://microsoft.com")
        
        Returns:
            dict: Certificate attributes with keys: C, ST, L, O, OU, CN
                - C: Country
                - ST: State/Province
                - L: Locality
                - O: Organization
                - OU: Organizational Unit
                - CN: Common Name
        
        Raises:
            RuntimeError: If certificate scraping fails
            
        Example:
            >>> cert_info = plugin.get_remote_cert_details("https://microsoft.com")
            >>> print(cert_info['O'])
            'Microsoft Corporation'
        """
        codesigner = self._get_codesigner()
        try:
            return codesigner.get_remote_cert_details(url)
        except Exception as e:
            raise RuntimeError(f"Failed to get remote certificate details: {e}")
    
    def self_sign_payload(
        self,
        payload_path: pathlib.Path,
        subject_cn: str = "Microsoft Corporation",
        org_name: str = "Microsoft Corporation",
        full_details: Optional[dict] = None
    ) -> None:
        """
        Signs a payload with a self-signed certificate.
        
        Generates an RSA-2048 key pair and creates a self-signed certificate
        to sign the specified PE file. Can use either basic details (CN/Org)
        or full certificate details from a scraped certificate.
        
        Args:
            payload_path: Path to the PE file to sign
            subject_cn: Common Name for the certificate (default: "Microsoft Corporation")
            org_name: Organization name for the certificate (default: "Microsoft Corporation")
            full_details: Optional dict with full cert details from get_remote_cert_details()
                         If provided, overrides subject_cn and org_name
        
        Returns:
            None: The payload is signed in-place
        
        Raises:
            FileNotFoundError: If payload file doesn't exist
            RuntimeError: If signing operation fails
            
        Example:
            >>> # Basic self-signing
            >>> plugin.self_sign_payload(
            ...     pathlib.Path("payload.exe"),
            ...     subject_cn="Contoso Ltd",
            ...     org_name="Contoso Ltd"
            ... )
            
            >>> # Sign with scraped certificate details
            >>> cert_info = plugin.get_remote_cert_details("https://microsoft.com")
            >>> plugin.self_sign_payload(
            ...     pathlib.Path("payload.exe"),
            ...     full_details=cert_info
            ... )
        """
        try:
            if not payload_path.exists():
                raise FileNotFoundError(f"Payload not found: {payload_path}")
            
            codesigner = self._get_codesigner()
            return codesigner.self_sign_payload(
                payload_path=payload_path,
                subject_cn=subject_cn,
                org_name=org_name,
                full_details=full_details
            )
            
        except Exception as e:
            raise RuntimeError(f"Failed to self-sign payload: {e}")
    
    def sign_with_provided_cert(
        self,
        payload_path: pathlib.Path,
        cert_path: pathlib.Path,
        cert_password: Optional[str] = None
    ) -> None:
        """
        Signs a payload using an external PFX/P12 certificate file.
        
        Uses a legitimate or stolen certificate file to sign the payload.
        This is the most realistic signing method if you have access to
        valid code signing certificates.
        
        Args:
            payload_path: Path to the PE file to sign
            cert_path: Path to the PFX/P12 certificate file
            cert_password: Optional password for the certificate file
        
        Returns:
            None: The payload is signed in-place
        
        Raises:
            FileNotFoundError: If payload or certificate file doesn't exist
            RuntimeError: If signing operation fails (wrong password, invalid cert, etc.)
            
        Example:
            >>> plugin.sign_with_provided_cert(
            ...     pathlib.Path("payload.exe"),
            ...     pathlib.Path("stolen_cert.pfx"),
            ...     cert_password="P@ssw0rd"
            ... )
        """
        try:
            if not payload_path.exists():
                raise FileNotFoundError(f"Payload not found: {payload_path}")
            
            if not cert_path.exists():
                raise FileNotFoundError(f"Certificate file not found: {cert_path}")
            
            codesigner = self._get_codesigner()
            return codesigner.sign_with_provided_cert(
                payload_path=payload_path,
                cert_path=cert_path,
                cert_password=cert_password
            )
            
        except Exception as e:
            raise RuntimeError(f"Failed to sign with provided certificate: {e}")


# Testing code
if __name__ == "__main__":
    print("Testing Code Signer Plugin...")
    
    plugin = CodeSignerPlugin()
    
    metadata = plugin.get_metadata()
    print(f"Plugin: {metadata.name} v{metadata.version}")
    print(f"Category: {metadata.category.value}")
    print(f"Description: {metadata.description}")
    
    is_valid, error = plugin.validate()
    if is_valid:
        print("✓ Plugin validation passed - osslsigncode available")
    else:
        print(f"✗ Plugin validation failed: {error}")
    
    print("\nRegistered functions:")
    for func_name in plugin.register().keys():
        print(f"  - {func_name}")
    
    print("\nTesting complete!")
