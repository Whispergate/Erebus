import json
import pathlib
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "agent_code"

def build_7z(spec_name: str = "spec.json",
             out_dir_name: str = "7z",
             compression: str = "9",
             password: str = None,
             build_path: pathlib.Path = None) -> pathlib.Path:
    
    root_dir = build_path if build_path else DEFAULT_ROOT
    container_dir = root_dir / "container"
    
    if Path(spec_name).is_absolute():
        spec_path = Path(spec_name)
    else:
        spec_path = container_dir / spec_name

    if not spec_path.exists():
        raise FileNotFoundError(f"Spec file not found at: {spec_path}")

    with open(spec_path) as f:
        spec = json.load(f)

    staging_dir = container_dir / f"_{out_dir_name}_stage"
    shutil.rmtree(staging_dir, ignore_errors=True)
    staging_dir.mkdir(parents=True, exist_ok=True)

    try:
        for dst, src in spec.get("files", {}).items():
            src_path = root_dir / src
            dst_path = staging_dir / dst
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
            else:
                print(f"Warning: File {src} missing in {root_dir}")

        if "payload_name" in spec:
            payload_src = root_dir / "payload" / spec["payload_name"]
            if payload_src.exists():
                shutil.copy2(payload_src, staging_dir / spec["payload_name"])
            else:
                print(f"Warning: Payload {spec['payload_name']} missing in {root_dir}/payload")

        archive_name = spec.get("archive_name", "payload.7z")
        archive_path = container_dir / out_dir_name / archive_name
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "7z", "a", "-t7z", f"-mx={compression}", 
            "-mfb=273", "-md=31m", "-ms=on", "-y"
        ]
        
        if password:
            cmd.extend([f"-p{password}", "-mhe=on"])
        
        cmd.append(str(archive_path))
        cmd.append(str(staging_dir) + "/*")
        
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return archive_path

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"7z creation failed: {e}")
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
