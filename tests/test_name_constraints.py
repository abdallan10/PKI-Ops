"""Security regression: a wrongly issued leaf must still fail Name Constraints."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from pkiops.core import (
    create_intermediate, create_root, keypair, make_csr, subject, verify_chain,
)


def _unrestricted_issue(inter, key, dns):
    """Simulate a buggy/malicious issuer bypassing the policy gate."""
    now = datetime.now(timezone.utc)
    csr = make_csr(keypair(), dns)
    return (x509.CertificateBuilder()
            .subject_name(subject(dns)).issuer_name(inter.subject)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
            .sign(key, hashes.SHA256()))


def test_name_constraints_enforced_independently_of_agent():
    root_key, inter_key = keypair(), keypair()
    root = create_root(root_key)
    inter = create_intermediate(root, root_key, inter_key)
    assert verify_chain(_unrestricted_issue(inter, inter_key, "service.lab.test"), inter, root)
    for forbidden in ("service.attacker.test", "lab.test", "service.lab.test.evil"):
        assert not verify_chain(_unrestricted_issue(inter, inter_key, forbidden), inter, root)


def test_name_constraints_missing_fail_closed():
    # The chain verifier must not silently accept an intermediate without
    # the expected constraints; this laboratory requires DNS constraints.
    root_key, inter_key = keypair(), keypair()
    root = create_root(root_key)
    now = datetime.now(timezone.utc)
    inter = (x509.CertificateBuilder()
             .subject_name(subject("Unconstrained intermediate"))
             .issuer_name(root.subject).public_key(inter_key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(minutes=1))
             .not_valid_after(now + timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
             .sign(root_key, hashes.SHA256()))
    assert not verify_chain(_unrestricted_issue(inter, inter_key, "service.lab.test"), inter, root)
