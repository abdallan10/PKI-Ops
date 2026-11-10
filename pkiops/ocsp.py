"""Offline OCSP response construction and verification for the lab.

This is not an HTTP OCSP responder. The issuer signs status assertions locally.
"""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp


def make_response(cert: x509.Certificate, issuer: x509.Certificate, issuer_key,
                  revoked_serials=(), now=None):
    """Create a signed single-certificate OCSP response."""
    now = now or datetime.now(timezone.utc)
    revoked = cert.serial_number in set(revoked_serials)
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert,
        issuer=issuer,
        algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
        this_update=now,
        next_update=now + timedelta(hours=1),
        revocation_time=now if revoked else None,
        revocation_reason=x509.ReasonFlags.unspecified if revoked else None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def verify_response(response: ocsp.OCSPResponse, cert: x509.Certificate,
                    issuer: x509.Certificate, now=None):
    """Check issuer signature, certificate identity, validity and GOOD status.

    The issuer certificate is a trusted input, not discovered from the response.
    """
    now = now or datetime.now(timezone.utc)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return False
    if response.serial_number != cert.serial_number:
        return False
    if response.issuer_name_hash != ocsp.OCSPRequestBuilder().add_certificate(
        cert, issuer, response.hash_algorithm).build().issuer_name_hash:
        return False
    if response.issuer_key_hash != ocsp.OCSPRequestBuilder().add_certificate(
        cert, issuer, response.hash_algorithm).build().issuer_key_hash:
        return False
    if response.certificate_status != ocsp.OCSPCertStatus.GOOD:
        return False
    if not response.this_update_utc <= now <= response.next_update_utc:
        return False
    try:
        issuer.public_key().verify(
            response.signature,
            response.tbs_response_bytes,
            padding.PKCS1v15(),
            response.signature_hash_algorithm,
        )
    except Exception:
        return False
    return True
