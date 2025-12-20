"""Generates an MSI Container using MSILib

Returns:
    File: MSI File
"""

import json, pathlib, uuid, shutil, subprocess, tempfile

REPO_ROOT     = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE    = REPO_ROOT / "agent_code"
CONTAINER_DIR = AGENT_CODE / "container"
PAYLOAD_DIR   = AGENT_CODE / "payload"

def build_msi(spec_name: str = "spec.json", out_dir_name: str = "msi") -> pathlib.Path:
    """Generates an MSI Container

    Args:
        spec_name (str, optional): Specification File Name. Defaults to "spec.json".
        out_dir_name (str, optional): Output Directory. Defaults to "msi".

    Returns:
        pathlib.Path: Returns Container Path
    """
    spec_path = CONTAINER_DIR / spec_name
    with open(spec_path) as f:
        spec = json.load(f)

    out_dir = CONTAINER_DIR / out_dir_name
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir()

    for dst, src in spec["files"].items():
        shutil.copy2(AGENT_CODE / src, out_dir / dst)
    shutil.copy2(PAYLOAD_DIR / spec["payload_name"], out_dir / spec["payload_name"])

    wix_json = {
        "name": spec["name"],
        "version": spec["version"],
        "manufacturer": spec["author"],
        "upgrade_code": str(uuid.uuid4()),
        "files": [{"source": str(out_dir / f), "name": f} for f in spec["files"]] +
                  [{"source": str(out_dir / spec["payload_name"]), "name": spec["payload_name"]}]
    }

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(wix_json, tmp); tmp.close()
    msi_path = CONTAINER_DIR / spec["msi_name"]
    subprocess.check_call(["wixl", "-o", str(msi_path), tmp.name])
    pathlib.Path(tmp.name).unlink()
    return msi_path
