+++
title = "Plugin Development"
chapter = false
weight = 25
pre = "<b>4. </b>"
+++

## Plugin Development Guide

### Creating a New Plugin

#### Step 1: Copy the Template

```bash
cd erebus_wrapper/Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules
cp plugin_example.py.template plugin_your_feature.py
```

#### Step 2: Update Plugin Metadata

```python
class YourFeaturePlugin(ErebusPlugin):
    """Your plugin description"""
    
    metadata = PluginMetadata(
        name="your_feature",
        version="1.0.0",
        category=PluginCategory.PAYLOAD,  # or CONTAINER, TRIGGER, CODESIGNER
        description="What your plugin does",
        author="Your Name",
        enabled=True
    )
```

#### Step 3: Implement Required Methods

```python
def get_metadata(self) -> PluginMetadata:
    """Return plugin metadata"""
    return self.metadata

def register(self) -> Dict[str, Callable]:
    """Register all public functions"""
    return {
        "function_1": self.function_1,
        "function_2": self.function_2,
    }

def validate(self) -> Tuple[bool, str]:
    """Validate plugin dependencies"""
    try:
        import required_library
        return (True, None)
    except ImportError:
        return (False, "required_library not found")
```

#### Step 4: Implement Plugin Functions

```python
def function_1(self, param1: str, param2: int) -> str:
    """Your implementation here"""
    return result
```

#### Step 5: Test Your Plugin

```bash
# Test individual plugin
python plugin_your_feature.py

# Expected output:
# [*] your_feature v1.0.0
# [*] Category: payload
# [*] Description: What your plugin does
# 
# [*] Registered functions (2):
#     - function_1
#     - function_2
# 
# [+] Validation passed
```

## Plugin Validation System

The Erebus plugin system automatically validates all plugins during initialization. Each plugin must implement three core methods:

### Validation Output Example

```
[*] Initializing Erebus Plugin System...
[*] Plugin Validation: 10/11 passed
    [+] plugin_container_clickonce
    [+] plugin_payload_dll_proxy
    [-] plugin_payload_maldocs: openpyxl not found
```

### View Validation Report

```bash
cd erebus_wrapper/Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules
python __init__.py
```

## Plugin Testing Best Practices

### Implement Robust Validation

```python
def validate(self) -> Tuple[bool, str]:
    """Validate all dependencies gracefully"""
    try:
        import optional_dependency
        if not hasattr(optional_dependency, 'required_function'):
            return (False, "optional_dependency missing required_function")
    except ImportError as e:
        return (False, f"optional_dependency not found: {e}")
    
    # Check external tools
    try:
        result = subprocess.run(['tool', '--version'], capture_output=True)
        if result.returncode != 0:
            return (False, "External tool 'tool' not found or not working")
    except FileNotFoundError:
        return (False, "External tool 'tool' not found in PATH")
    
    return (True, None)
```

### Use Lazy Imports for Optional Dependencies

```python
def get_optional_libs(self):
    """Lazy load optional libraries to avoid import errors"""
    try:
        import numpy
        import scipy
        return {'numpy': numpy, 'scipy': scipy}
    except ImportError as e:
        raise ImportError(f"Optional dependencies not available: {e}")
```

## Mythic RPC Integration

Plugin validation can be automatically reported to Mythic's operation event log.

### Python RPC Call Example

Equivalent to the Go example from Mythic documentation:

```go
// Go version
mythicrpc.SendMythicRPCOperationEventLogCreate(mythicrpc.MythicRPCOperationEventLogCreateMessage{
    OperationId:  &input.OperationID,
    Message:      "Your message here",
    MessageLevel: mythicrpc.MESSAGE_LEVEL_WARNING,
})
```

Python equivalent:

```python
from erebus_wrapper.erebus.modules import report_validation_results

# In an async context within builder:
await report_validation_results(operation_id=input.OperationID)
```

### Using the Plugin Validation API

```python
from erebus_wrapper.erebus.modules import (
    get_initialization_results,
    get_validated_plugins,
    get_failed_plugins,
    report_validation_results
)

# Get validation results
results = get_initialization_results()
passed_plugins = get_validated_plugins()
failed_plugins = get_failed_plugins()

# Report to Mythic
await report_validation_results(operation_id=1234)
```

### Integration Example in builder.py

```python
import asyncio
from mythic_container.PayloadBuilder import *
from erebus_wrapper.erebus.modules import report_validation_results

class ErebusBuilder(PayloadBuilder):
    async def build(self) -> PayloadBuildStatus:
        try:
            # ... build logic ...
            
            # Report plugin health to Mythic
            await report_validation_results(operation_id=self.operation_id)
            
            return PayloadBuildStatus(success=True, payload=output)
        except Exception as e:
            return PayloadBuildStatus(success=False, error=str(e))
```

### Mythic Event Log Output

This creates operation event log entries showing:
- ✅ **INFO Level**: All plugins validated successfully
- ⚠️ **WARNING Level**: Plugin validation failed
  - Lists each failed plugin with error reason

## Plugin Categories

Choose the appropriate category when creating your plugin:

| Category | Purpose | Examples |
|----------|---------|----------|
| **PAYLOAD** | Manipulate or transform payloads | DLL Proxy, MalDocs, Obfuscation |
| **CONTAINER** | Package payloads in delivery formats | ISO, 7z, ZIP, MSI |
| **TRIGGER** | Create execution triggers | LNK, BAT, MSI, ClickOnce |
| **CODESIGNER** | Code signing functionality | Certificate generation/spoofing |
| **OTHER** | Utility plugins | Helper functions |

## Documentation Standards

Document your plugin thoroughly:

1. **Docstrings** - Use Google-style docstrings with clear descriptions
2. **Examples** - Include usage examples in docstrings
3. **Update plugins.md** - Add your plugin to the documentation
4. **Error messages** - Use clear, actionable error messages

### Example Documented Function

```python
def your_function(self, param1: str, param2: int) -> str:
    """
    Brief description of what this function does.
    
    Longer description explaining functionality, use cases,
    and any important notes about behavior or compatibility.
    
    Args:
        param1 (str): Description of param1
        param2 (int): Description of param2
        
    Returns:
        str: Description of return value
        
    Raises:
        ValueError: When input validation fails
        RuntimeError: When execution fails
        
    Example:
        >>> result = plugin.your_function("test", 42)
        >>> print(result)
        "processed result"
    """
    if param2 < 0:
        raise ValueError("param2 must be positive")
    # Implementation...
```

## Testing Your Plugin

### Manual Testing

```bash
# Test individual plugin
python plugin_your_feature.py

# Test entire plugin system
python __init__.py

# Test with validation script
python test_validation.py
```

### Integration Testing

To test your plugin within the build system:

1. Create a test build in Mythic
2. Select your plugin's functionality in the options
3. Monitor the build output for validation messages
4. Check the operation event log for validation status

## Common Issues and Solutions

### Plugin Fails to Load

**Error**: `Plugin module does not have _plugin instance`

**Solution**: Ensure your module has:
```python
_plugin = YourPluginClass()

def validate():
    return _plugin.validate()
```

### Validation Returns False

**Error**: `[-] Validation failed: missing_dependency not found`

**Solution**: Check that all required dependencies are installed:
```bash
pip install missing_dependency
```

### Function Not Registered

**Error**: Function shows in test but not available in builder

**Solution**: Ensure function is registered in `register()` method:
```python
def register(self) -> Dict[str, Callable]:
    return {
        "your_function": self.your_function,  # Must be here!
    }
```

## References

- **Plugin Base Classes**: `modules/plugin_base.py`
- **Plugin Loader**: `modules/plugin_loader.py`
- **Example Plugin**: `modules/plugin_example.py.template`
- **Mythic Documentation**: https://docs.mythic-c2.net/
- **Mythic RPC Docs**: https://docs.mythic-c2.net/customizing/hooking-features/alerts
- **Event Feed**: https://docs.mythic-c2.net/operational-pieces/event-feed
