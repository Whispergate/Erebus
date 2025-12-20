import pathlib, asyncio

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
SHELLCRYPT = AGENT_CODE / "shellcrypt" / "shellcrypt.py"
SHELLCODE_DIR = AGENT_CODE / "shellcode"

ENCRYPTION = {
    "AES128_CBC":  "aes",
    "AES256_CBC":  "aes",
    "AES256_ECB":  "aes",
    "CHACHA20":    "chacha20",
    "RC4":         "rc4",
    "SALSA20":     "salsa20",
    "XOR":         "xor",
    "XOR_COMPLEX": "xor",
}

COMPRESSION = {
    "LZNT1": "lznt",
    "RLE":   "rle",
}

ENCODING = {
    "ALPHA32":  "alpha",
    "ASCII85":  "ascii85",
    "BASE64":   "base64",
    "WORDS256": "words",
}

FORMAT = {
    "C"          :  "c",
    "CSharp"     :  "csharp",
    "Nim"        :  "nim",
    "Go"         :  "go",
    "Python"     :  "py",
    "Powershell" :  "ps1",
    "VBA"        :  "vba",
    "VBScript"   :  "vbs",
    "Rust"       :  "rust",
    "JavaScript" :  "js",
    "Zig"        :  "zig",
    "Raw"        :  "raw",
}

async def obfuscate_shellcode(encryption: str,
                        encryption_key: str,
                        encoding: str,
                        compression: str,
                        shellcode: str,
                        format: str) -> bytes:
    """
    Compress -> Encrypt -> Encode raw shellcode via Shellcrypt.
    Returns the final obfuscated bytes.
    """
    cmd = [
        "python3",
        str(SHELLCRYPT),
        "-i", shellcode,
        "-e", ENCRYPTION[encryption],
        "-f", FORMAT[format],
        "-a", "shellcode"
    ]
    if compression != "NONE":
        cmd += ["-c", COMPRESSION[compression]]

    if encoding != "NONE":
        cmd += ["-d", ENCODING[encoding]]

    # key handling
    if encryption_key:
        cmd += ["-k", encryption_key]
    else:
        cmd += ["-k", ""]

    cmd += ["-o", f"{SHELLCODE_DIR / 'obfuscated.bin'}"]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        raise Exception(f"Shellcrypt failed: {stderr.decode()}")

    if format == "Raw":
        return stdout
    return stdout.strip()

if __name__ == "__main__":
    obfuscated = obfuscate_shellcode("XOR", "4141", encoding="ASCII85", compression="LZNT1", shellcode=f"{SHELLCODE_DIR / 'win-exec-calc-shellcode.bin'}", format="C")
    print(asyncio.run(obfuscated))