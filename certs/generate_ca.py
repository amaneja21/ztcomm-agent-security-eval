"""
Step 1, part A: build a tiny local Certificate Authority and issue one
certificate to each agent. This stands in for a real PKI, real enough
that mutual TLS actually happens, small enough to run on a laptop in
under a second.

Usage:
    python3 generate_ca.py agent_a
    python3 generate_ca.py agent_b
    python3 generate_ca.py attacker      # for later attack scripts
"""

import sys
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).parent
CA_KEY_PATH = CERT_DIR / "ca_key.pem"
CA_CERT_PATH = CERT_DIR / "ca_cert.pem"


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ensure_ca():
    """Create the CA key/cert once; reuse on later calls."""
    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    ca_key = _new_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ZT-COMM Local Test CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_key, ca_cert


def issue_cert(common_name: str):
    """Issue a cert+key for one agent, signed by the local CA."""
    ca_key, ca_cert = ensure_ca()

    key = _new_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_path = CERT_DIR / f"{common_name}_key.pem"
    cert_path = CERT_DIR / f"{common_name}_cert.pem"

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Issued {common_name}: {cert_path.name}, {key_path.name}")
    return key_path, cert_path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate_ca.py <agent_name>")
        sys.exit(1)
    ensure_ca()
    issue_cert(sys.argv[1])
