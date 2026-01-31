"""
Erebus Plugin - ClickOnce Trigger
Author: Whispergate
Description: Creates ClickOnce deployment triggers for payload execution

This plugin creates ClickOnce application deployments that leverage the attack vector from:
https://specterops.io/blog/2023/06/07/less-smartscreen-more-caffeine-abusing-clickonce-for-trusted-code-execution/

ClickOnce triggers leverage trusted execution model to deliver and execute payloads
while potentially bypassing SmartScreen warnings.
"""

from typing import Dict, Callable

try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from .archive.trigger_clickonce import (
        create_clickonce_trigger,
        _calculate_file_hash,
        _create_application_manifest,
        _create_deployment_manifest
    )
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
    from archive.trigger_clickonce import (
        create_clickonce_trigger,
        _calculate_file_hash,
        _create_application_manifest,
        _create_deployment_manifest
    )


class ClickOnceTriggerPlugin(ErebusPlugin):
    """
    Plugin for creating ClickOnce deployment triggers.
    
    ClickOnce applications leverage Windows' trusted execution model to execute
    payloads through the ClickOnce deployment framework. This plugin generates
    the necessary application and deployment manifests to create a complete
    ClickOnce deployment package.
    """
    
    def __init__(self):
        """Initialize the ClickOnce trigger plugin"""
        super().__init__()
    
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="clickonce_trigger",
            version="1.0.0",
            author="Whispergate",
            description="Creates ClickOnce deployment triggers for payload execution",
            category=PluginCategory.TRIGGER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        """Register the functions this plugin provides"""
        return {
            "create_clickonce_trigger": create_clickonce_trigger,
        }

    def validate(self) -> tuple[bool, str]:
        """Validate that required dependencies are available"""
        try:
            import asyncio
            import hashlib
            import xml.etree.ElementTree as ET
            if not callable(create_clickonce_trigger):
                return (False, "create_clickonce_trigger is not callable")
            return (True, None)
        except Exception as e:
            return (False, f"Validation error: {e}")
