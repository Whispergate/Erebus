import json
import pathlib
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
CONTAINER_DIR = AGENT_CODE / "container"
PAYLOAD_DIR = AGENT_CODE / "payload"

def build_7z(spec_name: str = "spec.json",
             out_dir_name: str = "7z",
             compression: str = "9",
             password: str = None) -> pathlib.Path:
    """
    Generates a standard 7z Container.
    
    Args:
        spec_name (str): Specification File Name. Defaults to "spec.json".
        out_dir_name (str): Output Directory. Defaults to "7z".
        compression (str): Compression level (0-9).
        password (str): Optional password for the archive.

    Returns:
        pathlib.Path: Returns Path to the generated archive.
    """
    if Path(spec_name).is_absolute():
        spec_path = Path(spec_name)
    else:
        spec_path = CONTAINER_DIR / spec_name
    
    if not spec_path.exists():
        raise FileNotFoundError(f"Spec file not found at: {spec_path}")
    
    with open(spec_path) as f:
        spec = json.load(f)
    
    staging_dir = CONTAINER_DIR / f"_{out_dir_name}_stage"
    shutil.rmtree(staging_dir, ignore_errors=True)
    staging_dir.mkdir()
    
    try:
        for dst, src in spec.get("files", {}).items():
            src_path = AGENT_CODE / src
            dst_path = staging_dir / dst
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
            else:
                if Path(src).is_absolute() and Path(src).exists():
                     shutil.copy2(src, dst_path)
                else:
                    print(f"Warning: Source file {src} not found, skipping.")
        
        if "payload_name" in spec:
            payload_src = PAYLOAD_DIR / spec["payload_name"]
            if payload_src.exists():
                shutil.copy2(payload_src, staging_dir / spec["payload_name"])
        
        archive_name = spec.get("archive_name", "payload.7z")
        archive_path = CONTAINER_DIR / out_dir_name / archive_name
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "7z", "a",
            "-t7z",
            f"-mx={compression}",
            "-mfb=273",
            "-md=31m",
            "-ms=on",
            "-y",
        ]
        
        if password:
            cmd.append(f"-p{password}")
            cmd.append("-mhe=on")
        
        cmd.append(str(archive_path))
        cmd.append(str(staging_dir) + "/*")
        
        subprocess.check_call(
            cmd, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
        return archive_path
    
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"7z creation failed: {e}")
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)