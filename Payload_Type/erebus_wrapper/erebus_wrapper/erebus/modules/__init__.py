"""
Erebus Modules Plugin System Initialization
Author: Whispergate
Description: Plugin discovery and validation utilities for Erebus

This module:
1. Discovers all plugins in the modules directory
2. Runs validation tests on each plugin (on-demand)
3. Reports results via Mythic RPC (if available)
4. Provides plugin management utilities
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

# Try to import mythic RPC for reporting
try:
    from mythic_container.MythicRPC import SendMythicRPCOperationEventLogCreate
    from mythic_container.MythicGoRPC.send_mythic_rpc_operationeventlog_create import (
        MythicRPCOperationEventLogCreateMessage
    )
    MYTHIC_RPC_AVAILABLE = True
except ImportError:
    MYTHIC_RPC_AVAILABLE = False


class PluginValidator:
    """Manages plugin discovery and validation"""
    
    def __init__(self):
        self.plugins_dir = Path(__file__).parent
        self.validated_plugins = {}
        self.failed_plugins = {}
        self.plugin_instances = {}
    
    def discover_plugins(self) -> List[str]:
        """
        Discover all plugin files in the modules directory.
        
        Returns:
            List[str]: List of plugin file names
        """
        plugins = []
        for file in self.plugins_dir.glob("plugin_*.py"):
            if file.name not in ["plugin_base.py", "plugin_loader.py"]:
                plugins.append(file.name)
        return sorted(plugins)
    
    def validate_plugins(self) -> Tuple[bool, Dict]:
        """
        Validate all discovered plugins by running them directly.
        
        This method runs each plugin file directly to capture:
        - Plugin metadata (name, version, category, description)
        - Registered functions
        - Validation status
        
        Returns:
            Tuple[bool, Dict]: (all_passed, results_dict)
                - all_passed: True if all plugins validated successfully
                - results_dict: {
                    'passed': [list of plugin names],
                    'failed': {plugin_name: error_message}
                  }
        """
        plugins = self.discover_plugins()
        passed = []
        failed = {}
        
        for plugin_file in plugins:
            plugin_path = self.plugins_dir / plugin_file
            plugin_name = plugin_file.replace(".py", "")
            
            try:
                # Run the plugin directly with Python
                result = subprocess.run(
                    [sys.executable, str(plugin_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(self.plugins_dir)
                )
                
                # Check if validation passed by looking for [+] marker
                if "[+] Validation passed" in result.stdout:
                    passed.append(plugin_name)
                    self.validated_plugins[plugin_name] = {
                        "status": "PASS",
                        "output": result.stdout
                    }
                elif "[-] Validation failed" in result.stdout or result.returncode != 0:
                    # Extract error message if present
                    error_msg = "Validation failed"
                    for line in result.stdout.split("\n"):
                        if "[-] Validation failed:" in line:
                            error_msg = line.replace("[-] Validation failed: ", "").strip()
                            break
                    
                    failed[plugin_name] = error_msg
                    self.failed_plugins[plugin_name] = error_msg
                else:
                    failed[plugin_name] = "Unknown validation result"
                    self.failed_plugins[plugin_name] = "Unknown validation result"
                    
            except subprocess.TimeoutExpired:
                error_msg = "Validation timeout (>30s)"
                failed[plugin_name] = error_msg
                self.failed_plugins[plugin_name] = error_msg
            except Exception as e:
                error_msg = f"Failed to run validation: {str(e)}"
                failed[plugin_name] = error_msg
                self.failed_plugins[plugin_name] = error_msg
        
        all_passed = len(failed) == 0
        return all_passed, {
            "passed": passed,
            "failed": failed,
            "total": len(plugins),
            "passed_count": len(passed),
            "failed_count": len(failed)
        }
    
    def get_summary_message(self, results: Dict) -> str:
        """
        Generate a human-readable summary message.
        
        Args:
            results: Results dictionary from validate_plugins()
            
        Returns:
            str: Summary message
        """
        passed_count = results["passed_count"]
        failed_count = results["failed_count"]
        total = results["total"]
        
        if failed_count == 0:
            return f"✓ All {total} plugins validated successfully"
        else:
            failed_names = ", ".join(results["failed"].keys())
            return f"✗ Plugin validation failed: {failed_count}/{total} plugins failed - {failed_names}"
    
    async def send_mythic_rpc_report(self, results: Dict, operation_id: int = None):
        """
        Send validation results to Mythic via RPC.
        
        Args:
            results: Results dictionary from validate_plugins()
            operation_id: Optional operation ID for Mythic context
        """
        if not MYTHIC_RPC_AVAILABLE:
            print("[!] Mythic RPC not available - skipping remote reporting")
            return
        
        try:
            passed_count = results["passed_count"]
            failed_count = results["failed_count"]
            total = results["total"]
            
            if failed_count == 0:
                message = f"✓ Erebus Plugin System: All {total} plugins validated successfully"
                level = "info"
            else:
                failed_names = ", ".join(results["failed"].keys())
                error_details = "\n".join([
                    f"  - {name}: {error}"
                    for name, error in results["failed"].items()
                ])
                message = f"✗ Erebus Plugin Validation Failed ({failed_count}/{total}):\n{error_details}"
                level = "warning"
            
            # Create RPC message
            rpc_msg = MythicRPCOperationEventLogCreateMessage(
                OperationId=operation_id,
                Message=message,
                MessageLevel=level
            )
            
            # Send RPC call
            response = await SendMythicRPCOperationEventLogCreate(rpc_msg)
            
            if response.Success:
                print(f"[+] Mythic RPC report sent successfully")
            else:
                print(f"[-] Mythic RPC report failed: {response.Error}")
                
        except Exception as e:
            print(f"[!] Error sending Mythic RPC report: {str(e)}")


# Create global validator instance
_validator = PluginValidator()


# Run validation on module import
def _initialize_plugins():
    """Initialize and validate plugins on module import"""
    print("[*] Initializing Erebus Plugin System...")
    
    all_passed, results = _validator.validate_plugins()
    
    # Print local results
    print(f"[*] Plugin Validation: {results['passed_count']}/{results['total']} passed")
    
    if results["passed"]:
        for plugin_name in sorted(results["passed"]):
            print(f"    [+] {plugin_name}")
    
    if results["failed"]:
        for plugin_name, error in sorted(results["failed"].items()):
            print(f"    [-] {plugin_name}: {error}")
    
    if all_passed:
        print("[+] All plugins validated successfully!")
    else:
        print(f"[!] Warning: {results['failed_count']} plugin(s) failed validation")
    
    return results


# Initialization results are generated on-demand
_initialization_results = None


# Public API
def get_plugin_instance(plugin_name: str):
    """
    Get a plugin instance by name.
    
    Args:
        plugin_name: Name of the plugin (e.g., 'plugin_archive_container')
        
    Returns:
        Plugin instance or None if not found
    """
    return _validator.plugin_instances.get(plugin_name)


def get_validated_plugins() -> Dict:
    """
    Get all validated plugins.
    
    Returns:
        Dictionary of validated plugins
    """
    return _validator.validated_plugins


def get_failed_plugins() -> Dict:
    """
    Get all failed plugins with error messages.
    
    Returns:
        Dictionary of failed plugins and their errors
    """
    return _validator.failed_plugins


def get_initialization_results() -> Dict:
    """
    Get the plugin initialization results.
    
    Returns:
        Dictionary with initialization results
    """
    return _initialization_results


def run_plugin_validation() -> Dict:
    """
    Run plugin validation and cache results.

    Returns:
        Dictionary with validation results
    """
    global _initialization_results
    _initialization_results = _initialize_plugins()
    return _initialization_results


async def report_validation_results(operation_id: int = None):
    """
    Send plugin validation results to Mythic via RPC.
    
    This function creates an Operation Event Log entry in Mythic showing the
    plugin validation status. It should be called from within the payload
    builder context where Mythic RPC is available.
    
    Args:
        operation_id: Optional Mythic operation ID for context
        
    Example usage in builder.py:
    ============================
    from erebus.modules import report_validation_results
    
    # At some point in the build process:
    try:
        await report_validation_results(operation_id=input.OperationID)
    except Exception as e:
        print(f"[!] Could not report plugin status: {e}")
    """
    global _initialization_results
    if _initialization_results is None:
        _initialization_results = _initialize_plugins()
    await _validator.send_mythic_rpc_report(_initialization_results, operation_id)


__all__ = [
    "PluginValidator",
    "get_plugin_instance",
    "get_validated_plugins",
    "get_failed_plugins",
    "get_initialization_results",
    "run_plugin_validation",
    "report_validation_results",
]


if __name__ == "__main__":
    """Test block for validating plugins and reporting results"""
    import asyncio
    
    # Print validation results
    print("\n" + "="*60)
    print("Erebus Plugin System Validation Report")
    print("="*60)
    
    results = run_plugin_validation()
    print(_validator.get_summary_message(results))
    print(f"\nTotal Plugins: {results['total']}")
    print(f"Passed: {results['passed_count']}")
    print(f"Failed: {results['failed_count']}")
    
    if results["failed"]:
        print("\nFailed Plugins:")
        for plugin_name, error in sorted(results["failed"].items()):
            print(f"  - {plugin_name}: {error}")
    
    # Optionally test Mythic RPC reporting (async)
    if MYTHIC_RPC_AVAILABLE:
        print("\n[*] Attempting to send Mythic RPC report...")
        print("[!] Note: RPC call requires active Mythic broker connection")
        
        async def test_rpc_report():
            await report_validation_results(operation_id=None)
        
        try:
            asyncio.run(test_rpc_report())
        except Exception as e:
            print(f"[!] RPC reporting not available: {str(e)}")
    else:
        print("\n[!] Mythic RPC not available - skipping remote reporting")
    
    print("="*60)
