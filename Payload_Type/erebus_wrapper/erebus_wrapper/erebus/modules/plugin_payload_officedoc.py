# Re-export shim — all implementation has moved to plugin_payload_maldocs.py.
# Kept to avoid breaking the test suite and any external tooling that imports by name.
from plugin_payload_maldocs import PayloadMalDocsPlugin as PayloadOfficeDocPlugin  # noqa: F401

__all__ = ["PayloadOfficeDocPlugin"]
