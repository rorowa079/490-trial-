"""Device identity and TLS (NIST SP 800-53 IA-3, SC-8, SC-13).

Each device gets its own P-384 key and X.509 certificate at provisioning. They
are used for two things:

* **Serving the dashboard over HTTPS** (TLS 1.3 only).
* **Authenticating the device to the agency's hotlist server** with mutual
  TLS: the server sees this device's certificate, and the device accepts only a
  server certificate signed by the pinned CA. No shared passwords or API keys.

Provisioning writes three files under ``<data_dir>/identity``:

``device.key``  the private key (PEM, mode 0600)
``device.csr``  a signing request to hand to your certificate authority
``device.crt``  a self-signed certificate so HTTPS works immediately; replace it
                with the CA-signed one (same file name) when you have it

Limit, stated plainly: the key is a file. On the deployed device it should be
generated inside the TPM so it cannot be copied ("hardware-backed"); that needs
the tpm2 OpenSSL provider and has not been built or tested here. Disk
encryption sealed to the TPM is the interim protection.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .. import crypto

SELF_SIGNED_DAYS = 397


def identity_dir(cfg: dict) -> Path:
    return Path(cfg["data_dir"]) / "identity"


def _names(cfg: dict) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for host in dict.fromkeys([*(cfg["api"]["tls"].get("hostnames") or []), "localhost", "127.0.0.1"]):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return names


def ensure_identity(cfg: dict) -> dict[str, Path]:
    """Create the device key, CSR and a self-signed certificate if they do not exist yet."""
    directory = identity_dir(cfg)
    paths = {name: directory / f"device.{name}" for name in ("key", "csr", "crt")}
    if paths["key"].exists() and paths["crt"].exists():
        return paths
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    key = ec.generate_private_key(crypto.CURVE)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, cfg.get("organization") or "Unnamed agency"),
        x509.NameAttribute(NameOID.COMMON_NAME, cfg["camera_id"]),
    ])
    san = x509.SubjectAlternativeName(_names(cfg))
    usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])

    fd = os.open(paths["key"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
           .add_extension(san, critical=False).add_extension(usage, critical=False)
           .sign(key, hashes.SHA384()))
    paths["csr"].write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=SELF_SIGNED_DAYS))
            .add_extension(san, critical=False).add_extension(usage, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA384()))
    paths["crt"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return paths


def tls_files(cfg: dict) -> tuple[str, str]:
    """(certificate, key) for the API: the configured pair, or the device identity."""
    tls = cfg["api"]["tls"]
    if tls.get("cert_file") and tls.get("key_file"):
        return tls["cert_file"], tls["key_file"]
    paths = ensure_identity(cfg)
    return str(paths["crt"]), str(paths["key"])


def certificate_info(cfg: dict) -> dict | None:
    path = identity_dir(cfg) / "device.crt"
    if not path.exists():
        return None
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return {"subject": cert.subject.rfc4514_string(), "self_signed": cert.issuer == cert.subject,
            "not_after": cert.not_valid_after_utc.timestamp(),
            "sha256": cert.fingerprint(hashes.SHA256()).hex()}


def client_context(cfg: dict, ca_file: str) -> ssl.SSLContext:
    """TLS 1.3 client context for device-to-server calls: pinned CA, device certificate presented."""
    if not ca_file or not Path(ca_file).exists():
        raise ValueError("a CA file for the remote server is required (the system trust store is not used)")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca_file)
    cert, key = tls_files(cfg)
    context.load_cert_chain(cert, key)
    return context
