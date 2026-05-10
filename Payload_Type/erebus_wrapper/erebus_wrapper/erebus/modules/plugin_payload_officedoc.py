# Re-export shim — all implementation has moved to plugin_payload_maldocs.py.
# Kept to avoid breaking the test suite and any external tooling that imports by name.
# The imported class's __module__ remains plugin_payload_maldocs, so the plugin
# loader's single-class-per-module check will not register this file as a plugin.
try:
    from erebus_wrapper.erebus.modules.plugin_payload_maldocs import PayloadMalDocsPlugin as PayloadOfficeDocPlugin  # noqa: F401
except ImportError:
    from plugin_payload_maldocs import PayloadMalDocsPlugin as PayloadOfficeDocPlugin  # noqa: F401

__all__ = ["PayloadOfficeDocPlugin"]
