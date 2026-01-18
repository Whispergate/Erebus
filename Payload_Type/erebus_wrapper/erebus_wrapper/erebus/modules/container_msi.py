"""Generates an MSI Container using msitools

Returns:
    pathlib.Path: path to the finished MSI
"""
import json, pathlib, uuid, shutil, subprocess, tempfile

REPO_ROOT     = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE    = REPO_ROOT / "agent_code"
CONTAINER_DIR = AGENT_CODE / "container"
PAYLOAD_DIR   = AGENT_CODE / "payload"

def build_msi(spec_name: str = "spec.json", out_dir_name: str = "msi") -> pathlib.Path:
    """Generates an MSI Container

    Args:
        spec_name (str): JSON spec inside container/ (default: spec.json)
        out_dir_name (str): temp staging dir name (default: msi)

    Returns:
        pathlib.Path: absolute path to the new .msi file
    """
    spec_path = CONTAINER_DIR / spec_name
    with open(spec_path) as f:
        spec = json.load(f)

    stage = CONTAINER_DIR / out_dir_name
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir()

    for dst, src in spec["files"].items():
        shutil.copy2(AGENT_CODE / src, stage / dst)
    shutil.copy2(PAYLOAD_DIR / spec["payload_name"], stage / spec["payload_name"])

    files = [p for p in PAYLOAD_DIR.iterdir() if p.is_file() and p.suffix != ".msi"]
    if not files:
        raise ValueError("No files found in payload/ to pack")

    wix_json = {
        "name": spec["name"],
        "version": spec["version"],
        "manufacturer": spec["author"],
        "upgrade_code": str(uuid.uuid4()),
        "files": [{"source": str(f), "name": f.name} for f in files],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(wix_json, tmp)
        tmp_name = tmp.name

    msi_path = CONTAINER_DIR / spec["msi_name"]

    try:
        subprocess.check_call(["wixl", "-o", str(msi_path), tmp_name])
    finally:
        pathlib.Path(tmp_name).unlink(missing_ok=True)

    return msi_path
