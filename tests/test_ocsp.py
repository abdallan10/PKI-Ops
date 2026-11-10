"""OCSP lab tests: good, revoked, wrong issuer, wrong certificate and expiry."""
from datetime import datetime, timedelta, timezone

from pkiops.core import create_root, create_intermediate, issue, keypair, make_csr
from pkiops.ocsp import make_response, verify_response

POLICY = {'allowed_dns_suffix': '.lab.test', 'max_days': 90,
          'min_rsa_bits': 2048, 'allowed_algorithms': ['RSA', 'EC']}


def chain():
    root_key, issuer_key = keypair(), keypair()
    root = create_root(root_key)
    issuer = create_intermediate(root, root_key, issuer_key)
    cert = issue(make_csr(keypair(), 'server.lab.test'), 30, issuer, issuer_key, POLICY)
    return issuer, issuer_key, cert


def test_ocsp_good_and_wrong_certificate():
    issuer, key, cert = chain()
    response = make_response(cert, issuer, key)
    assert verify_response(response, cert, issuer)
    other = issue(make_csr(keypair(), 'other.lab.test'), 30, issuer, key, POLICY)
    assert not verify_response(response, other, issuer)


def test_ocsp_revoked_and_expired():
    issuer, key, cert = chain()
    revoked = make_response(cert, issuer, key, {cert.serial_number})
    assert not verify_response(revoked, cert, issuer)
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    expired = make_response(cert, issuer, key, now=old)
    assert not verify_response(expired, cert, issuer)


def test_ocsp_wrong_issuer_and_forged_signer():
    issuer, key, cert = chain()
    other_issuer, _, _ = chain()
    response = make_response(cert, issuer, key)
    assert not verify_response(response, cert, other_issuer)
    forged = make_response(cert, issuer, keypair())
    assert not verify_response(forged, cert, issuer)
