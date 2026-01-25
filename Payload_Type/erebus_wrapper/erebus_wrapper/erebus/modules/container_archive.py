import pathlib
import shutil
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "agent_code"

def build_7z(compression: str = "9",
             password: str = None,
             build_path: pathlib.Path = None) -> pathlib.Path:
    """
    Generates a 7z container

    :param compression: Compression level (0-9).
    :type compression: str
    :param password:  Optional password for the archive.
    :type password: str
    :param build_path: The build path of the current build process.
    :type build_path: pathlib.Path
    :return: Returns Path to the generated archive.
    :rtype: Path
    """
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
    """
    Generates a password-protected PKZIP container.

    :param compression: 0–9 (0=store, 9=best).  Default 9.
    :param password:  Optional archive password.
    :param build_path:  Build root (defaults to agent_code).
    :return:            Path to the generated .zip file.
    """
    root_dir     = build_path if build_path else DEFAULT_ROOT
    container_dir= root_dir / "container"
    payload_dir  = root_dir / "payload"
    decoy_dir    = root_dir / "decoys"

    try:
        for item in decoy_dir.rglob('*'):
            if item.is_file() and not item.name.startswith('.'):
                tgt = payload_dir / item.relative_to(decoy_dir)
                tgt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, tgt)

        container_dir.mkdir(parents=True, exist_ok=True)
        zip_path = container_dir / "zip" / "erebus.zip"
        zip_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["zip", "-r", f"-{compression}", "-y", "-q", str(zip_path), "."]
        if password:
            cmd.extend(["--encrypt", password])
        subprocess.check_call(cmd, cwd=payload_dir,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return zip_path
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Zip creation failed: {e}")
