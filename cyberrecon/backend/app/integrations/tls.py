"""TLS certificate inspection through the guarded connection path (resolves, validates, then connects)."""
from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from app.security.ip_policy import IPPolicy
from app.security.safe_net import BlockedTargetError, ResolutionError, open_guarded_tls, system_resolver


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _key_info(key) -> dict:
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": f"EC ({key.curve.name})", "bits": key.curve.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 256}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 456}
    if isinstance(key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": key.key_size}
    return {"type": type(key).__name__, "bits": None}


def parse_certificate(der: bytes, hostname: str) -> dict:
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    names = san or ([_name_attr(cert.subject, NameOID.COMMON_NAME)] if _name_attr(cert.subject, NameOID.COMMON_NAME) else [])
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig = None
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _name_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "issuer_country": _name_attr(cert.issuer, NameOID.COUNTRY_NAME),
        "not_before": nb.isoformat(timespec="seconds"),
        "not_after": na.isoformat(timespec="seconds"),
        "days_remaining": (na - now).days,
        "expired": na < now,
        "not_yet_valid": nb > now,
        "san": sorted(san)[:100],
        "san_count": len(san),
        "serial": format(cert.serial_number, "x"),
        "signature_hash": sig,
        "public_key": _key_info(cert.public_key()),
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "self_signed": cert.subject == cert.issuer,
        "hostname_match": hostname_matches(hostname, names),
    }


class TlsProbe:
    name = "TLS handshake (direct connection)"

    def __init__(self, settings, *, resolver=None, policy: IPPolicy | None = None):
        self.timeout = settings.http_connect_timeout + 3
        self.resolver = resolver or system_resolver
        self.policy = policy or IPPolicy()

    async def probe(self, hostname: str, port: int = 443) -> dict:
        verification = {"ok": False, "error": None}
        reader = writer = None
        ip = None
        try:
            try:
                reader, writer, ip = await open_guarded_tls(hostname, port, resolver=self.resolver, policy=self.policy, verify=True, timeout=self.timeout)
                verification["ok"] = True
            except ssl.SSLCertVerificationError as exc:
                verification["error"] = exc.verify_message or str(exc)
                reader, writer, ip = await open_guarded_tls(hostname, port, resolver=self.resolver, policy=self.policy, verify=False, timeout=self.timeout)
            sslobj = writer.get_extra_info("ssl_object")
            der = sslobj.getpeercert(binary_form=True)
            cert = parse_certificate(der, hostname)
            cipher = sslobj.cipher()
            return {"status": "ok", "port": port, "connected_ip": ip, "verification": verification, "protocol": sslobj.version(),
                    "cipher": cipher[0] if cipher else None, **cert}
        except (BlockedTargetError, ResolutionError) as exc:
            return {"status": "unavailable", "port": port, "error": str(exc)}
        except ssl.SSLError as exc:
            return {"status": "error", "port": port, "error": f"TLS handshake failed: {exc.reason or exc}"}
        except (OSError, asyncio.TimeoutError) as exc:
            return {"status": "error", "port": port, "error": f"Could not connect on port {port}: {type(exc).__name__}"}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
