import pathlib
import shutil
import subprocess
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "agent_code"

VISIBLE_EXTENSIONS = {'.lnk'}

def build_7z(compression: str = "9",
             password: str = None,
             build_path: pathlib.Path = None) -> pathlib.Path:
    root_dir = build_path if build_path else DEFAULT_ROOT
    container_dir = root_dir / "container"
    payload_dir = root_dir / "payload"
    decoy_dir = root_dir / "decoys"

    try:
        for item in decoy_dir.rglob('*'):
            if item.is_file() and not item.name.startswith('.'):
                relative_path = item.relative_to(decoy_dir)
                target = payload_dir / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)

        archive_name = "erebus.7z"
        archive_path = container_dir / "7z" / archive_name
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "7z", "a", "-t7z", f"-mx={compression}",
            "-mfb=273", "-xr!.*", "-md=31m", "-ms=on", "-y"
        ]
        if password:
            cmd.extend([f"-p{password}", "-mhe=on"])
        cmd.append(str(archive_path))
        cmd.append(str(payload_dir) + "/*")
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return archive_path

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"7z creation failed: {e}")

def build_zip(compression: int = 9,
              password: str = None,
              build_path: pathlib.Path = None) -> pathlib.Path:
    root_dir = build_path if build_path else DEFAULT_ROOT
    container_dir = root_dir / "container"
    payload_dir = root_dir / "payload"
    decoy_dir = root_dir / "decoys"

    try:
        for item in decoy_dir.rglob('*'):
            if item.is_file() and not item.name.startswith('.'):
                tgt = payload_dir / item.relative_to(decoy_dir)
                tgt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, tgt)

        container_dir.mkdir(parents=True, exist_ok=True)
        zip_path = container_dir / "zip" / "erebus.zip"
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        
        compress_type = zipfile.ZIP_DEFLATED if int(compression) > 0 else zipfile.ZIP_STORED

        with zipfile.ZipFile(zip_path, 'w', compression=compress_type) as zf:
            if password:
                zf.setpassword(password.encode())

            for item in payload_dir.rglob('*'):
                if item.is_file() and not item.name.startswith('.'):
                    arcname = item.relative_to(payload_dir)
                    zinfo = zipfile.ZipInfo.from_file(item, arcname)
                    zinfo.create_system = 0 
                    attr = 0x20 
                    
                    if item.suffix.lower() not in VISIBLE_EXTENSIONS:
                        attr |= 0x02
                        
                    zinfo.external_attr = (attr & 0xFF)
                    
                    with open(item, "rb") as f:
                        zf.writestr(zinfo, f.read())

        return zip_path

    except Exception as e:
        raise RuntimeError(f"Zip creation failed: {e}")
