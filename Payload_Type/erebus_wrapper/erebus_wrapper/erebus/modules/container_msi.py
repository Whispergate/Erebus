"""Generates an MSI Container using MSILib

Returns:
    File: MSI File
"""

import json, msilib, uuid, os, shutil, pathlib

REPO_ROOT     = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE    = REPO_ROOT / "agent_code"
CONTAINER_DIR = AGENT_CODE / "container"
PAYLOAD_DIR   = AGENT_CODE / "payload"
STAGING       = CONTAINER_DIR / "_stage"
SPEC_FILE     = CONTAINER_DIR / "spec.json"
CAB_FILE      = "erebus.cab"

def build_msi(spec_name: str = "spec.json",
                  out_dir_name: str = "msi") -> pathlib.Path:
    with open(SPEC_FILE) as f:
        spec = json.load(f)

    shutil.rmtree(STAGING, ignore_errors=True)
    os.makedirs(STAGING, exist_ok=True)

    spec_path = CONTAINER_DIR / spec_name
    with open(spec_path) as f:
        spec = json.load(f)

    out_dir = CONTAINER_DIR / out_dir_name
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir()

    for dst, src in spec["files"].items():
        src_path = AGENT_CODE / src
        shutil.copy2(src_path, out_dir / dst)
    
    shutil.copy2(PAYLOAD_DIR / spec["payload_name"], out_dir / spec["payload_name"])

    db = msilib.init_database(
        str(spec["msi_name"]),
        schema=msilib.schema,
        ProductName=spec["name"],
        ProductVersion=spec["version"],
        ProductCode=str(uuid.uuid4()),
        Manufacturer=spec["author"])

    msilib.add_data(db, "Directory",
        [("TARGETDIR",   None, "SourceDir"),
         ("ProgramFilesFolder", "TARGETDIR",   "."),
         ("INSTALLFOLDER", "ProgramFilesFolder", spec["name"])])

    msilib.add_data(db, "Feature",
        [("DefaultFeature", None, None, 1, 1, "", "")])

    msilib.add_data(db, "Media", [(1, 1, CAB_FILE, None, None)])

    cab = msilib.CAB(CAB_FILE)
    cab.append_staged_files(str(STAGING))
    for f in spec["files"]:
        msilib.add_data(db, "File",
            [(f, "INSTALLFOLDER", f, 0)])

    msilib.sequence.StandardInstallSequence(db)
    db.Commit()
    shutil.rmtree(STAGING, ignore_errors=True)
    return CONTAINER_DIR / "msi" / spec["msi_name"]

if __name__ == "__main__":
    print("MSI created at:", build_msi())
