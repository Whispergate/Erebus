# Archive - Legacy Modules

This folder contains the original module files before they were converted to the plugin system.

## Why These Files Are Archived

As of the plugin system implementation, all modules have been converted to use the plugin architecture. The old modules in this folder are kept for:
- Reference purposes
- Backward compatibility verification
- Migration documentation

## Current Plugin Equivalents

| Original Module | Plugin Equivalent | Description |
|----------------|------------------|-------------|
| `trigger_lnk.py` | `plugin_trigger_lnk.py` | LNK shortcut triggers |
| `trigger_bat.py` | `plugin_trigger_bat.py` | Batch script triggers |
| `trigger_msi.py` | `plugin_trigger_msi.py` | MSI installer triggers |
| `trigger_clickonce.py` | `plugin_trigger_clickonce.py` | ClickOnce triggers |
| `container_archive.py` | `plugin_archive_container.py` | 7z/ZIP containers |
| `container_iso.py` | `plugin_container_iso.py` | ISO disk image containers |
| `container_msi.py` | `plugin_container_msi.py` | MSI installer containers |
| `container_clickonce.py` | `plugin_container_clickonce.py` | ClickOnce containers |
| `codesigner.py` | `plugin_codesigner.py` | Code signing functionality |
| `payload_dll_proxy.py` | `plugin_payload_dll_proxy.py` | DLL proxy generation |

## Using the New Plugin System

All functionality from these modules is now available through the plugin system:

```python
from erebus_wrapper.erebus.modules.plugin_loader import get_plugin_loader

# Get the plugin loader
loader = get_plugin_loader()

# Access any function from any plugin
build_7z = loader.get_function("build_7z")
create_payload_trigger = loader.get_function("create_payload_trigger")

# Or get a specific plugin
lnk_plugin = loader.get_plugin("lnk_trigger")
```

## Migration Notes

The plugins provide the same functionality as these original modules with the following improvements:
- ✅ Automatic discovery and loading
- ✅ Dependency management
- ✅ Better error handling
- ✅ Validation support
- ✅ Consistent interface
- ✅ Easier testing and maintenance

## Do Not Modify

These files are archived and should not be modified. All new development should be done in the plugin system.

---

*Archived on: January 31, 2026*
*Plugin System Version: 1.0.0*
