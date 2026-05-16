+++
title = "Plugin Development"
chapter = false
weight = 3
pre = "<b>3. </b>"
+++

## Overview

Plugins extend Erebus without touching the core `builder.py`. The plugin loader scans `erebus/modules/plugin_*.py` at startup, imports each file, instantiates its `ErebusPlugin` subclass, runs `validate()`, and registers the callables returned by `register()` into the builder's global namespace.

**When to write a plugin** - you want to add a new trigger, container, payload transform, or signer, and the implementation is self-contained (doesn't require changes to shellcrypt, the C++ loader source, or the core build pipeline ordering). Anything else is a `builder.py` edit.

**When NOT to write a plugin** - you need to change how shellcode is obfuscated (that's shellcrypt), add a new loader injection method (that's C++ source in `agent_code/Erebus.Loaders/`), or reorder build steps (that's `builder.py`).

This page is the developer-facing guide. For the catalog of shipped plugins and their parameters, see [Plugins]({{% relref "plugins.md" %}}). For the full BuildParameter reference, see [Development]({{% relref "development.md" %}}).

## The plugin contract

### ErebusPlugin base class

Every plugin inherits from `ErebusPlugin` in [plugin_base.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_base.py). The abstract contract is:

| Method | Required? | Purpose |
|---|---|---|
| `get_metadata() → PluginMetadata` | **Yes** | Plugin name, version, author, description, category, enabled flag |
| `register() → Dict[str, Callable]` | **Yes** | Map of function names → callables exposed to the builder |
| `validate() → tuple[bool, Optional[str]]` | No (default `True`) | Dependency / configuration check run at load time |
| `on_load()` | No | Initialization hook called after successful validation |
| `on_unload()` | No | Cleanup hook |
| `get_dependencies() → List[str]` | No (default `[]`) | List of other plugin names this plugin requires |
| `get_config_schema() → Optional[Dict]` | No (default `None`) | JSON schema for plugin configuration |

### Plugin categories

`PluginCategory` is an `Enum` defining where each plugin fits in the build pipeline:

| Value | Usage |
|---|---|
| `TRIGGER` | Victim-clickable artefacts (LNK, BAT, MSC, HTML, …) |
| `CONTAINER` | Distribution wrappers (ISO, 7z, Zip, MSI, Electron, …) |
| `PAYLOAD` | Loader-adjacent transforms (DLL proxy, MalDoc, …) |
| `CODESIGNER` | AuthentiCode signing |
| `OTHER` | Utility plugins that don't fit the above |

### Metadata

`PluginMetadata` is a plain data class:

```python
PluginMetadata(
    name="my_feature",            # short identifier (snake_case)
    version="1.0.0",              # semver
    author="Your Name",           # or an alias / org
    description="One-line summary shown in validation reports",
    category=PluginCategory.CONTAINER,
    enabled=True,                 # set False to disable the plugin without deleting it
)
```

## Writing a plugin - step by step

### Step 1 - Scaffold from the template

```bash
cd Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules
cp plugin_example.py.template plugin_my_feature.py
```

Rename the class and update the metadata:

```python
try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class MyFeaturePlugin(ErebusPlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_feature",
            version="1.0.0",
            author="Your Name",
            description="What this plugin does in one line",
            category=PluginCategory.CONTAINER,
            enabled=True,
        )
```

The dual-import pattern lets the file run both as a package member (`erebus_wrapper.erebus.modules...`) and as a standalone script (`python plugin_my_feature.py`) - every shipped plugin uses it.

### Step 2 - Implement `register()`

Return a dict mapping the function name the builder will see to the plugin's method:

```python
def register(self) -> Dict[str, Callable]:
    return {
        "build_my_container": self.build_my_container,
    }
```

Function names must be unique across *all* plugins - the loader injects them directly into `builder.py`'s global namespace, so collisions silently shadow each other.

### Step 3 - Implement `validate()`

Return `(True, None)` if the plugin can run; return `(False, "<reason>")` otherwise. Runs once at loader startup, so it must be cheap.

```python
def validate(self) -> tuple[bool, Optional[str]]:
    try:
        import required_package  # noqa: F401
    except ImportError as e:
        return (False, f"Missing dependency: {e}")

    if not (self.AGENT_CODE / "templates" / "my_template.j2").exists():
        return (False, "my_template.j2 missing")

    return (True, None)
```

Keep expensive checks (compiler availability, network reachability) out of `validate()` - move those to the function that actually needs them so `builder.py` load time stays fast.

### Step 4 - Implement the actual feature

Put the real work inside the methods you registered. Use standard path anchoring (all shipped plugins do this) so the plugin works whether it's imported as a package or run standalone:

```python
import pathlib

class MyFeaturePlugin(ErebusPlugin):
    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"

    def build_my_container(
        self,
        build_path: pathlib.Path,
        param1: str = "default",
    ) -> pathlib.Path:
        """
        Build an example container.

        Args:
            build_path: active Mythic build temp dir (contains ``payload/``)
            param1: operator-supplied option (from a BuildParameter)

        Returns:
            pathlib.Path: path to the produced file in ``payload/``
        """
        payload_dir = build_path / "payload"
        output = payload_dir / "my_output.bin"
        output.write_bytes(b"...")
        return output
```

Use **lazy imports** for optional heavy dependencies - defer them to the call site rather than the top of the file so a missing package only breaks the one plugin that needs it:

```python
def build_my_container(self, build_path, ...):
    try:
        import pycdlib  # only needed by this plugin
    except ImportError as e:
        raise RuntimeError(f"pycdlib required for this feature: {e}") from e
    ...
```

### Step 5 - Register the function in `_PLUGIN_FUNCTIONS`

`builder.py` has an explicit list at the top of the file naming every plugin-provided function that will be imported into its global namespace:

```python
# builder.py
_PLUGIN_FUNCTIONS = [
    "generate_proxies",
    "build_clickonce",
    "build_msi",
    ...
    "build_my_container",   # <-- add yours here
]
```

**Without this step, your plugin loads and validates but `builder.py` can't call it.** This is the single most common "my plugin isn't working" failure.

### Step 6 - Add the standalone test block

Every shipped plugin carries this block so `python plugin_my_feature.py` exercises metadata, registration, and validation in isolation:

```python
if __name__ == "__main__":
    _plugin = MyFeaturePlugin()
    _metadata = _plugin.get_metadata()
    print(f"[*] {_metadata.name} v{_metadata.version}")
    print(f"[*] Category: {_metadata.category.value}")
    print(f"[*] Description: {_metadata.description}")

    registered = _plugin.register()
    print(f"[*] Registered functions ({len(registered)}):")
    for func_name in sorted(registered):
        print(f"    - {func_name}")

    is_valid, error = _plugin.validate()
    print(f"[+] Validation passed" if is_valid else f"[-] Validation failed: {error}")
```

### Step 7 - Test standalone + at system level

```bash
# Standalone: just this plugin
python plugin_my_feature.py

# System-level: every plugin at once, with the full validation report
python __init__.py
```

System-level output looks like:

```
[*] Initializing Erebus Plugin System...
[*] Plugin Validation: 15/16 passed
    [+] plugin_archive_container
    [+] plugin_container_clickonce
    [+] plugin_container_electron
    ...
    [-] plugin_payload_maldocs: openpyxl not found - required for advanced Excel manipulation
[!] Warning: 1 plugin(s) failed validation
```

## Plugin lifecycle

The loader performs each step in order at Erebus startup:

1. **Discovery** - scan `erebus/modules/` for files matching `plugin_*.py`.
2. **Import** - `importlib.import_module` each candidate; import failures are logged and the plugin is skipped.
3. **Instantiate** - look for a subclass of `ErebusPlugin` in the module and call its constructor.
4. **Validate** - run `validate()`; on `(False, msg)` the plugin is marked failed and its functions are not registered.
5. **Resolve dependencies** - read `get_dependencies()` and ensure listed plugins are themselves loaded + valid.
6. **Register** - pull the dict from `register()` and stash callables for `builder.py` to inject.
7. **on_load** - call the `on_load()` hook for any initialization that should happen once per startup.

## Validation framework

### What `validate()` should check

- **Imports** of optional dependencies - wrap the import in `try/except ImportError` and return `(False, str(e))` on failure.
- **Filesystem assets** that the plugin needs at runtime (templates, binaries, icons). Use `self.AGENT_CODE` or a path relative to `__file__`.
- **Configuration invariants** - e.g. a BuildParameter that must exist in the builder's parameter list.

### What `validate()` should NOT check

- Network reachability or external services - defer to call time.
- Compiler / toolchain availability unless your plugin's very existence depends on it - again, defer.
- Expensive filesystem scans - the loader runs `validate()` synchronously at Erebus startup and blocks on it.

### Reporting validation results to Mythic

The plugin system exposes a handful of helpers in [erebus/modules/\_\_init\_\_.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/__init__.py) that the builder uses to surface plugin health in Mythic's operation event log:

```python
from erebus_wrapper.erebus.modules import (
    get_initialization_results,   # dict: {passed, passed_count, failed, failed_count, total}
    get_validated_plugins,        # list of plugins that passed
    get_failed_plugins,           # list of plugins that failed + their error messages
    report_validation_results,    # async: post the above to Mythic as an event log
)
```

`builder.py` calls `report_validation_results(operation_id=self.operation_id)` once per build so the operator sees every plugin's status in the operation log without opening the Mythic container console. Mirror this pattern if you're adding plugin-system integration to another entry point.

## Testing and debugging

### Manual standalone test

Every plugin ships the standardised test block from Step 6 above. Run it whenever you change the plugin:

```bash
cd Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules
python plugin_my_feature.py
```

### Integration test

Full-system test runs every plugin in discovery order and prints a consolidated report:

```bash
cd Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules
python __init__.py
```

### Common failures

**"Plugin doesn't appear in loaded plugins list"**
- Filename must match `plugin_*.py`.
- The module must contain a subclass of `ErebusPlugin` with `enabled=True` in metadata.
- `validate()` must return `(True, None)`.
- Check for an import error at module load time - run `python plugin_my_feature.py` directly; exceptions will surface immediately.

**"AttributeError when calling plugin function from `builder.py`"**
- The function name must be listed in `_PLUGIN_FUNCTIONS` at the top of `builder.py`.
- The name in `register()` must match exactly (case-sensitive).
- The plugin must have validated successfully; a failed plugin's functions are never registered.

**"ImportError / ModuleNotFoundError at plugin load time"**
- Use the dual-import pattern for the base class (`erebus_wrapper.erebus.modules.plugin_base` with `plugin_base` fallback).
- Wrap optional dependencies in `validate()` and lazy-load them in the methods that actually need them.

**"validate() returns (False, ...) but I can't see why"**
- The validation message is displayed verbatim in both the standalone test output and the system-level report - run `python __init__.py` and look at the failed-plugin list.

## Best practices

- **Keep naming predictable.** `plugin_trigger_<name>.py` → `<Name>TriggerPlugin` → `create_<name>_trigger()`. Follow the convention every shipped plugin uses; it makes the plugin's category + intent obvious from the filename alone.
- **Document every public function** with a docstring covering args, return value, and exceptions. The plugin code is the source of truth for the builder, so docstrings carry operational weight.
- **Use absolute pathing** via `pathlib.Path(__file__).resolve().parents[N]` rather than relative paths - the builder invokes plugins from arbitrary working directories.
- **Raise descriptive `RuntimeError`s** when a plugin function fails mid-build; the builder catches these and surfaces them as Mythic build-step errors.
- **Treat `validate()` as a contract with the loader** - never perform side effects in it.

## References

- **Base class:** [plugin_base.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_base.py)
- **Loader:** [plugin_loader.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_loader.py)
- **Template:** `erebus/modules/plugin_example.py.template`
- **Example plugin** (short): [plugin_trigger_bat.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_trigger_bat.py)
- **Example plugin** (long): [plugin_container_electron.py](Payload_Type/erebus_wrapper/erebus_wrapper/erebus/modules/plugin_container_electron.py)
- **Catalog of shipped plugins:** [Plugins]({{% relref "plugins.md" %}})
- **Build pipeline that invokes your plugin:** [Development]({{% relref "development.md" %}})
