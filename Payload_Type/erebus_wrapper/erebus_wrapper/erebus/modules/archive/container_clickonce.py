"""
Build a minimal ClickOnce bundle inside agent_code/container.
"""

import json, pathlib, shutil, os

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE = REPO_ROOT / "agent_code"
CONTAINER_DIR = AGENT_CODE / "container"
PAYLOAD_DIR = AGENT_CODE / "payload"

def build_clickonce(spec_name: str = "spec.json",
                  out_dir_name: str = "clickonce") -> pathlib.Path:
    '''
    Docstring for build_clickonce
    
    :param spec_name: Specification File Name
    :type spec_name: str
    :param out_dir_name: Output Directory
    :type out_dir_name: str
    :return: Container Path
    :rtype: Path
    '''
    spec_path = CONTAINER_DIR / spec_name
    with open(spec_path) as f:
        spec = json.load(f)

    out_dir = CONTAINER_DIR / out_dir_name
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir()

    for dst, src in spec["files"].items():
        src_path = AGENT_CODE / src
        shutil.copy2(src_path, out_dir / dst)
    
    shutil.copy2(PAYLOAD_DIR / spec["clickonce_name"], out_dir / spec["clickonce_name"])

    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xsi:schemaLocation="urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns:co.v2="urn:schemas-microsoft-com:clickonce.v2" xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:co.v1="urn:schemas-microsoft-com:clickonce.v1">
  <asmv1:assemblyIdentity name="{spec['clickonce_name']}" version="1.0.0.0" publicKeyToken="43cb1e8e7a352766" language="neutral" processorArchitecture="x64" type="win32" />
  <application />
  <entryPoint>
    <assemblyIdentity name="{spec['name']}.application" version="1.0.0.0" publicKeyToken="0000000000000000"/>
  </entryPoint>
  <description>{spec['name']}</description>
  <deployment install="true"/>
  <dependency>
    <dependentAssembly codebase="{spec['clickonce_name']}" size="{os.path.getsize(out_dir / spec['clickonce_name'])}">
      <assemblyIdentity name="setup" version="1.0.0.0"/>
    </dependentAssembly>
  </dependency>
</asmv1:assembly>
"""
    (out_dir / "clickonce.application").write_text(manifest)
    return out_dir

if __name__ == "__main__":
    print("ClickOnce payload created at:", build_clickonce())
  