+++
title = "Plugins"
chapter = false
weight = 15
pre = "<b>3. </b>"
+++

## Overview

Erebus uses an extensible plugin system that automatically discovers and loads modules. This architecture allows developers to easily add new functionality without modifying the core builder code. All plugins are stored in the `modules/` directory and are automatically loaded when the builder starts.

## Plugin Architecture

### How It Works

The plugin system consists of three main components:

1. **Plugin Base** (`plugin_base.py`) - Defines the abstract interface all plugins must implement
2. **Plugin Loader** (`plugin_loader.py`) - Automatically discovers, validates, and loads plugins
3. **Your Plugins** (`plugin_*.py`) - Individual plugin modules providing specific functionality

When the builder starts:
- The plugin loader scans the `modules/` directory for files matching `plugin_*.py`
- Each plugin is imported, validated, and initialized
- Plugin functions are registered and made available to the builder
- Dependencies between plugins are resolved automatically

### Plugin Categories

Plugins are organized into five categories:

#### 🎯 Trigger Plugins
Create execution triggers for payloads:
- **LNK Triggers** - Windows shortcut files (.lnk)
- **BAT Triggers** - Batch script files (.bat)
- **MSI Triggers** - MSI installer triggers
- **ClickOnce Triggers** - ClickOnce application triggers

#### 📦 Container Plugins  
Package payloads into container formats:
- **Archive Containers** - 7z and ZIP archives with password protection
- **ISO Containers** - ISO disk images with autorun support
- **MSI Containers** - Windows Installer packages
- **ClickOnce Containers** - ClickOnce deployment packages

#### 🛠️ Payload Plugins
Manipulate or generate payloads:
- **DLL Proxy** - Generate DLL proxy/hijack code
- **Obfuscation** - Payload obfuscation techniques
- **Format Conversion** - Convert between payload formats

#### ✍️ CodeSigner Plugins
Code signing functionality:
- **Self-Signing** - Generate and apply self-signed certificates
- **Certificate Cloning** - Clone certificates from remote URLs
- **Custom Certificates** - Sign with provided certificates

#### 🔧 Other Plugins
Utility functions that don't fit other categories

## Available Plugins

### Trigger Plugins

#### LNK Trigger Plugin
Creates Windows shortcut (.lnk) files that execute payloads.

**Functions:**
- `create_payload_trigger()` - Create LNK trigger with decoy file support
- `create_lnk_trigger()` - Create basic LNK trigger
- `set_file_hidden()` - Hide files on Windows/Linux

**Example Usage:**
```python
trigger_path = create_payload_trigger(
    target_bin="cmd.exe",
    args="/c start erebus.exe",
    icon_src=r"C:\Windows\System32\imageres.dll",
    icon_index=0,
    description="Invoice",
    payload_dir=Path("./payload"),
    decoy_file=Path("./decoy.pdf")
)
```

#### BAT Trigger Plugin
Creates batch script (.bat) files for payload execution.

**Functions:**
- `create_bat_payload_trigger()` - Generate BAT trigger with payload execution

#### MSI Trigger Plugin
Creates MSI-based triggers for payload execution.

**Functions:**
- `create_msi_payload_trigger()` - Generate MSI trigger package

#### ClickOnce Trigger Plugin
Creates ClickOnce application triggers.

**Functions:**
- `create_clickonce_trigger()` - Generate ClickOnce deployment trigger

### Container Plugins

#### Archive Container Plugin
Creates password-protected 7z and ZIP archives.

**Functions:**
- `build_7z()` - Create 7z archive with LZMA2 compression
- `build_zip()` - Create ZIP archive with optional encryption

**Features:**
- Configurable compression levels (0-9)
- Optional password protection
- File attribute manipulation (hide non-trigger files)
- Header encryption for 7z

**Example Usage:**
```python
archive = build_7z(
    compression="9",
    password="secret123",
    build_path=Path("./build"),
    visible_extension=".lnk"
)
```

#### ISO Container Plugin
Creates ISO disk images for payload delivery.

**Functions:**
- `build_iso()` - Generate ISO with autorun support

**Features:**
- Custom volume labels
- Autorun.inf generation
- File hiding (Joliet extension)
- Backdoor existing ISOs

**Example Usage:**
```python
iso = build_iso(
    volume_id="SYSTEM_UPDATE",
    enable_autorun=True,
    build_path=Path("./build"),
    visible_extension=".lnk"
)
```

#### MSI Container Plugin
Creates Windows Installer (MSI) packages.

**Functions:**
- `build_msi()` - Create custom MSI package
- `hijack_msi()` - Backdoor existing MSI
- `add_multiple_files_to_msi()` - Add files to MSI

**Features:**
- Custom actions and scripts
- File hijacking
- Multi-file support
- Installer toolkit integration

#### ClickOnce Container Plugin
Creates ClickOnce deployment packages.

**Functions:**
- `build_clickonce()` - Generate ClickOnce application package

### Payload Plugins

#### DLL Proxy Plugin
Generates DLL proxy/hijack code for DLL sideloading.

**Functions:**
- `generate_proxies()` - Generate proxy functions for DLL hijacking

**Features:**
- Automatic export parsing
- C/C++ proxy generation
- Function forwarding

### CodeSigner Plugins

#### CodeSigner Plugin
Provides code signing capabilities.

**Functions:**
- `self_sign_payload()` - Generate and apply self-signed certificate
- `get_remote_cert_details()` - Extract certificate info from URL
- `sign_with_provided_cert()` - Sign with custom certificate

**Features:**
- Self-signed certificate generation
- Certificate cloning from remote hosts
- Custom certificate support (.pfx/.p12)
- Full X.509 attribute support

**Example Usage:**
```python
# Self-sign a payload
self_sign_payload(
    payload_path=Path("erebus.exe"),
    subject_cn="Microsoft Corporation",
    org_name="Microsoft"
)

# Clone certificate from URL
cert_details = get_remote_cert_details("https://example.com")
self_sign_payload(
    payload_path=Path("erebus.exe"),
    subject_cn=cert_details["CN"],
    org_name=cert_details["O"],
    full_details=cert_details
)
```

## Creating Custom Plugins

### Quick Start

1. **Copy the template:**
   ```bash
   cd modules/
   cp plugin_example.py.template plugin_my_feature.py
   ```

2. **Edit the plugin:**
   - Update class name and metadata
   - Implement your functions
   - Register functions in `register()` method

3. **Test and deploy:**
   - Run `python plugin_my_feature.py` to test
   - Save in `modules/` directory - it's automatically discovered!

### Plugin Template Structure

```python
try:
    from .plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory

class MyFeaturePlugin(ErebusPlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_feature",
            version="1.0.0",
            author="Your Name",
            description="Description of functionality",
            category=PluginCategory.CONTAINER,
            enabled=True
        )
    
    def register(self) -> Dict[str, Callable]:
        return {
            "my_function": self.my_function,
        }
    
    def validate(self) -> tuple[bool, Optional[str]]:
        # Check dependencies
        return (True, None)
    
    def my_function(self, param1, param2):
        # Implementation
        pass
```

### Required Methods

Every plugin must implement:

- **`get_metadata()`** - Return plugin information
- **`register()`** - Register callable functions

### Optional Methods

Plugins can optionally implement:

- **`validate()`** - Validate dependencies and configuration
- **`on_load()`** - Initialization when plugin loads
- **`on_unload()`** - Cleanup when plugin unloads
- **`get_dependencies()`** - List required plugins
- **`get_config_schema()`** - Define configuration options

## Plugin Development Best Practices

### 1. Clear Naming
Use descriptive names for plugins and functions:
- ✅ `plugin_iso_container.py` → `IsoContainerPlugin` → `build_iso()`
- ❌ `plugin1.py` → `Plugin` → `do_stuff()`

### 2. Comprehensive Documentation
Document all functions with docstrings:
```python
def build_archive(self, payload_path: Path, compression: int = 9) -> Path:
    """
    Create a compressed archive.
    
    Args:
        payload_path: Path to payload file
        compression: Compression level 0-9 (default: 9)
        
    Returns:
        Path to created archive
        
    Raises:
        RuntimeError: If archive creation fails
    """
```

### 3. Error Handling
Provide clear error messages:
```python
try:
    result = self._process(input_path)
    if not result.exists():
        raise RuntimeError("Processing failed")
    return result
except Exception as e:
    raise RuntimeError(f"Failed to process {input_path.name}: {e}")
```

### 4. Path Management
Use configurable paths with sensible defaults:
```python
def __init__(self):
    super().__init__()
    self.REPO_ROOT = Path(__file__).resolve().parents[2]
    self.AGENT_CODE = self.REPO_ROOT / "agent_code"

def process(self, build_path: Optional[Path] = None):
    root = build_path if build_path else self.AGENT_CODE
    output = root / "results"
    output.mkdir(parents=True, exist_ok=True)
```

### 5. Validation
Check dependencies in `validate()`:
```python
def validate(self) -> tuple[bool, Optional[str]]:
    try:
        import required_package
        if not (self.AGENT_CODE / "required_file").exists():
            return (False, "Missing required file")
        return (True, None)
    except ImportError as e:
        return (False, f"Missing dependency: {e}")
```

## Plugin Loading Process

1. **Discovery** - Scan `modules/` for `plugin_*.py` files
2. **Import** - Import each plugin module
3. **Instantiate** - Create plugin instance
4. **Validate** - Run `validate()` check
5. **Dependencies** - Resolve plugin dependencies
6. **Register** - Make functions available
7. **Initialize** - Call `on_load()` hook

## Troubleshooting

### Plugin Not Loading

**Symptoms:** Plugin doesn't appear in loaded plugins list

**Solutions:**
- Ensure filename matches `plugin_*.py` pattern
- Verify class inherits from `ErebusPlugin`
- Check `enabled=True` in metadata
- Review console for error messages
- Verify `validate()` returns `(True, None)`

### Function Not Found

**Symptoms:** `AttributeError` when calling plugin function

**Solutions:**
- Check function is registered in `register()` method
- Verify function name spelling
- Ensure plugin loaded successfully

### Import Errors

**Symptoms:** `ImportError` or `ModuleNotFoundError`

**Solutions:**
- Use relative imports: `from .plugin_base import ...`
- Verify dependencies are installed
- Implement `validate()` to check dependencies

## Advanced Topics

### Plugin Dependencies

Plugins can depend on other plugins:

```python
def get_dependencies(self) -> List[str]:
    return ["codesigner"]  # Requires codesigner plugin
```

### Plugin Configuration

Define configuration schema:

```python
def get_config_schema(self) -> Optional[Dict[str, Any]]:
    return {
        "type": "object",
        "properties": {
            "max_size": {
                "type": "integer",
                "description": "Maximum file size in bytes"
            }
        }
    }
```

### Testing Plugins

Test plugins standalone:

```bash
python modules/plugin_my_feature.py
```

Or programmatically:

```python
if __name__ == "__main__":
    plugin = MyFeaturePlugin()
    metadata = plugin.get_metadata()
    print(f"Testing {metadata.name}...")
    
    is_valid, error = plugin.validate()
    assert is_valid, f"Validation failed: {error}"
    
    result = plugin.my_function(test_input)
    assert result.exists(), "Output not created"
    
    print("✓ All tests passed!")
```

## Additional Resources

- **Plugin Template:** `modules/plugin_example.py.template`
- **Example Plugin:** `modules/plugin_archive_container.py`
- **Development Guide:** `modules/PLUGIN_DEVELOPMENT.md`
- **Plugin Base:** `modules/plugin_base.py`
- **Plugin Loader:** `modules/plugin_loader.py`

## Summary

The Erebus plugin system provides:
- ✅ Automatic plugin discovery and loading
- ✅ Clean separation of concerns
- ✅ Easy extensibility without core modifications
- ✅ Dependency management
- ✅ Validation and error handling
- ✅ Comprehensive documentation and examples

To create a new plugin, simply copy the template, implement your functionality, and save it in the `modules/` directory.