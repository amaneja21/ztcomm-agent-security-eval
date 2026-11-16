"""A self-signed certificate claiming a real agent's name, not signed
by the evaluation CA. Cached after first use."""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FORGED_DIR = Path(__file__).parent / "forged"


def forge_self_signed(common_name: str):
    FORGED_DIR.mkdir(exist_ok=True)
    key_path = FORGED_DIR / f"forged_{common_name}_key.pem"
    cert_path = FORGED_DIR / f"forged_{common_name}_cert.pem"
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path
    now = datetime.datetime.now(datetime.UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path
