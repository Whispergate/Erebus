"""
Erebus Plugin Base System
Author: Whispergate
Description: Base classes and interfaces for Erebus plugin architecture
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable
from enum import Enum


class PluginCategory(Enum):
    """Defines the category of plugin functionality"""
    TRIGGER = "trigger"          # Creates execution triggers (LNK, BAT, etc.)
    CONTAINER = "container"      # Packages payloads (ZIP, MSI, ISO, etc.)
    PAYLOAD = "payload"          # Payload manipulation (DLL proxy, signing, etc.)
    CODESIGNER = "codesigner"    # Code signing functionality
    OTHER = "other"              # Other utilities


class PluginMetadata:
    """Metadata about a plugin"""
    
    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        category: PluginCategory,
        enabled: bool = True
    ):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.category = category
        self.enabled = enabled
        
    def __repr__(self):
        return f"<Plugin: {self.name} v{self.version} ({self.category.value})>"


class ErebusPlugin(ABC):
    """
    Abstract base class for all Erebus plugins.
    
    All plugins must inherit from this class and implement the required methods.
    The plugin system will automatically discover and load all plugins that inherit
    from this class and are placed in the modules directory.
    """
    
    def __init__(self):
        """Initialize the plugin. Override this to set up your plugin."""
        pass
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """
        Return metadata about this plugin.
        
        Returns:
            PluginMetadata: Information about this plugin
        """
        pass
    
    @abstractmethod
    def register(self) -> Dict[str, Callable]:
        """
        Register the plugin's functions that should be exposed to the builder.
        
        Returns:
            Dict[str, Callable]: A dictionary mapping function names to callable functions.
                                 Example: {"build_iso": self.build_iso, "create_iso": self.create_iso}
        """
        pass
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validate that the plugin is properly configured and can run.
        Override this to add custom validation logic.
        
        Returns:
            tuple[bool, Optional[str]]: (is_valid, error_message)
                                        If valid, returns (True, None)
                                        If invalid, returns (False, "error message")
        """
        return (True, None)
    
    def on_load(self):
        """
        Called when the plugin is loaded by the plugin system.
        Override this to perform initialization tasks.
        """
        pass
    
    def on_unload(self):
        """
        Called when the plugin is unloaded.
        Override this to perform cleanup tasks.
        """
        pass
    
    def get_dependencies(self) -> List[str]:
        """
        Return a list of other plugins this plugin depends on.
        
        Returns:
            List[str]: List of plugin names this plugin requires
        """
        return []
    
    def get_config_schema(self) -> Optional[Dict[str, Any]]:
        """
        Return a JSON schema defining the configuration options for this plugin.
        Override this if your plugin requires configuration.
        
        Returns:
            Optional[Dict[str, Any]]: JSON schema for plugin configuration, or None
        """
        return None


class PluginException(Exception):
    """Base exception for plugin-related errors"""
    pass


class PluginLoadError(PluginException):
    """Raised when a plugin fails to load"""
    pass


class PluginValidationError(PluginException):
    """Raised when a plugin fails validation"""
    pass


class PluginDependencyError(PluginException):
    """Raised when a plugin's dependencies are not met"""
    pass
