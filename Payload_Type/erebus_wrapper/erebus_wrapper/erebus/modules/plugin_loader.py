"""
Erebus Plugin Loader System
Author: Whispergate
Description: Automatic plugin discovery and loading system for Erebus
"""

import os
import sys
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Callable, Type
from .plugin_base import (
    ErebusPlugin, 
    PluginMetadata, 
    PluginCategory,
    PluginLoadError,
    PluginValidationError,
    PluginDependencyError
)


class PluginLoader:
    """
    Discovers, loads, and manages Erebus plugins.
    
    This class automatically scans the modules directory for plugins,
    loads them, validates them, and makes their functions available
    to the builder system.
    """
    
    def __init__(self, plugin_directory: Optional[Path] = None):
        """
        Initialize the plugin loader.
        
        Args:
            plugin_directory: Path to the directory containing plugins.
                            If None, uses the directory containing this file.
        """
        if plugin_directory is None:
            plugin_directory = Path(__file__).parent
        
        self.plugin_directory = plugin_directory
        self.plugins: Dict[str, ErebusPlugin] = {}
        self.functions: Dict[str, Callable] = {}
        self.metadata: Dict[str, PluginMetadata] = {}
        self._load_errors: List[tuple[str, Exception]] = []
    
    def discover_plugins(self) -> List[str]:
        """
        Discover all Python files in the plugin directory that could contain plugins.
        
        Returns:
            List[str]: List of module names (without .py extension)
        """
        plugin_files = []
        
        # Ignore these files
        ignore_files = {
            '__init__.py',
            'plugin_base.py',
            'plugin_loader.py',
            '_paths.py'
        }
        
        for file in self.plugin_directory.glob('*.py'):
            if file.name not in ignore_files and not file.name.endswith('.template'):
                module_name = file.stem
                plugin_files.append(module_name)
        
        return plugin_files
    
    def load_plugin(self, module_name: str) -> Optional[ErebusPlugin]:
        """
        Load a single plugin from a module.
        
        Args:
            module_name: Name of the module to load (without .py)
            
        Returns:
            Optional[ErebusPlugin]: The loaded plugin instance, or None if loading failed
        """
        try:
            # Import the module
            full_module_name = f"erebus_wrapper.erebus.modules.{module_name}"
            
            # Reload if already imported (useful for development)
            if full_module_name in sys.modules:
                module = importlib.reload(sys.modules[full_module_name])
            else:
                module = importlib.import_module(full_module_name)
            
            # Find all classes that inherit from ErebusPlugin
            plugin_classes = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, ErebusPlugin) and 
                    obj is not ErebusPlugin and
                    obj.__module__ == full_module_name):
                    plugin_classes.append(obj)
            
            if not plugin_classes:
                # Not a plugin module, skip silently
                return None
            
            if len(plugin_classes) > 1:
                raise PluginLoadError(
                    f"Module {module_name} contains multiple plugin classes. "
                    "Each module should contain only one plugin class."
                )
            
            # Instantiate the plugin
            plugin_class = plugin_classes[0]
            plugin = plugin_class()
            
            # Get metadata
            metadata = plugin.get_metadata()
            
            # Check if plugin is enabled
            if not metadata.enabled:
                print(f"[Plugin] Skipping disabled plugin: {metadata.name}")
                return None
            
            # Validate the plugin
            is_valid, error_msg = plugin.validate()
            if not is_valid:
                raise PluginValidationError(
                    f"Plugin {metadata.name} validation failed: {error_msg}"
                )
            
            # Call on_load hook
            plugin.on_load()
            
            return plugin
            
        except Exception as e:
            self._load_errors.append((module_name, e))
            print(f"[Plugin] Error loading plugin from {module_name}: {e}")
            return None
    
    def load_all_plugins(self) -> int:
        """
        Discover and load all plugins from the plugin directory.
        
        Returns:
            int: Number of successfully loaded plugins
        """
        print(f"[Plugin] Discovering plugins in: {self.plugin_directory}")
        
        module_names = self.discover_plugins()
        print(f"[Plugin] Found {len(module_names)} potential plugin modules")
        
        loaded_count = 0
        
        for module_name in module_names:
            plugin = self.load_plugin(module_name)
            if plugin:
                metadata = plugin.get_metadata()
                
                # Check for duplicate plugin names
                if metadata.name in self.plugins:
                    print(f"[Plugin] Warning: Duplicate plugin name '{metadata.name}' in {module_name}, skipping")
                    continue
                
                # Store the plugin
                self.plugins[metadata.name] = plugin
                self.metadata[metadata.name] = metadata
                
                # Register the plugin's functions
                registered_functions = plugin.register()
                for func_name, func in registered_functions.items():
                    if func_name in self.functions:
                        print(f"[Plugin] Warning: Function '{func_name}' already registered by another plugin")
                    self.functions[func_name] = func
                
                loaded_count += 1
                print(f"[Plugin] ✓ Loaded: {metadata.name} v{metadata.version} ({metadata.category.value}) - {len(registered_functions)} functions")
        
        # Check dependencies
        self._check_dependencies()
        
        print(f"[Plugin] Successfully loaded {loaded_count} plugins")
        
        if self._load_errors:
            print(f"[Plugin] {len(self._load_errors)} plugin(s) failed to load")
        
        return loaded_count
    
    def _check_dependencies(self):
        """Check that all plugin dependencies are satisfied"""
        for plugin_name, plugin in self.plugins.items():
            dependencies = plugin.get_dependencies()
            for dep in dependencies:
                if dep not in self.plugins:
                    raise PluginDependencyError(
                        f"Plugin '{plugin_name}' requires plugin '{dep}' which is not loaded"
                    )
    
    def get_plugin(self, name: str) -> Optional[ErebusPlugin]:
        """
        Get a plugin by name.
        
        Args:
            name: Name of the plugin
            
        Returns:
            Optional[ErebusPlugin]: The plugin instance, or None if not found
        """
        return self.plugins.get(name)
    
    def get_function(self, name: str) -> Optional[Callable]:
        """
        Get a registered function by name.
        
        Args:
            name: Name of the function
            
        Returns:
            Optional[Callable]: The function, or None if not found
        """
        return self.functions.get(name)
    
    def get_functions_by_category(self, category: PluginCategory) -> Dict[str, Callable]:
        """
        Get all functions from plugins of a specific category.
        
        Args:
            category: The plugin category to filter by
            
        Returns:
            Dict[str, Callable]: Dictionary of function name to function
        """
        result = {}
        for plugin_name, metadata in self.metadata.items():
            if metadata.category == category:
                plugin = self.plugins[plugin_name]
                result.update(plugin.register())
        return result
    
    def list_plugins(self) -> List[PluginMetadata]:
        """
        Get a list of all loaded plugin metadata.
        
        Returns:
            List[PluginMetadata]: List of plugin metadata objects
        """
        return list(self.metadata.values())
    
    def get_load_errors(self) -> List[tuple[str, Exception]]:
        """
        Get a list of plugins that failed to load.
        
        Returns:
            List[tuple[str, Exception]]: List of (module_name, exception) tuples
        """
        return self._load_errors.copy()
    
    def unload_all_plugins(self):
        """Unload all plugins and call their on_unload hooks"""
        for plugin in self.plugins.values():
            try:
                plugin.on_unload()
            except Exception as e:
                print(f"[Plugin] Error unloading plugin: {e}")
        
        self.plugins.clear()
        self.functions.clear()
        self.metadata.clear()
        self._load_errors.clear()


# Global plugin loader instance
_global_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    """
    Get the global plugin loader instance.
    Creates it if it doesn't exist.
    
    Returns:
        PluginLoader: The global plugin loader
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = PluginLoader()
        _global_loader.load_all_plugins()
    return _global_loader


def reload_plugins():
    """Reload all plugins (useful for development)"""
    global _global_loader
    if _global_loader is not None:
        _global_loader.unload_all_plugins()
    _global_loader = None
    return get_plugin_loader()
