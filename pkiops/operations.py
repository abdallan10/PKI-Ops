"""Deterministic operations for revocation, renewal and local TLS verification."""
from __future__ import annotations
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .core import issue, make_csr, verify_chain

def renewal_due(cert: x509.Certificate, *, now=None, within_days=7) -> bool:
    if within_days < 0:
        raise ValueError('within_days must be non-negative')
    now = now or datetime.now(timezone.utc)
    return cert.not_valid_after_utc <= now + timedelta(days=within_days)

def renew_leaf(old_cert, old_key, intermediate, intermediate_key, policy, *, days=30, now=None):
    names = old_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if len(names) != 1:
        raise ValueError('one DNS SAN required')
    csr = make_csr(old_key, names[0])
    return issue(csr, days, intermediate, intermediate_key, policy, now=now)

def verify_revocation(crl_obj, cert, issuer_cert):
    now = datetime.now(timezone.utc)
    if crl_obj.issuer != issuer_cert.subject or not crl_obj.last_update_utc <= now <= crl_obj.next_update_utc:
        return False
    try:
        issuer_cert.public_key().verify(crl_obj.signature, crl_obj.tbs_certlist_bytes,
                                        crl_obj.signature_algorithm_parameters, crl_obj.signature_hash_algorithm)
    except Exception:
        return False
    return crl_obj.get_revoked_certificate_by_serial_number(cert.serial_number) is None

def mtls_roundtrip(folder, root_cert, intermediate_cert, server_cert, server_key, client_cert, client_key, *, revoked=()):
    """Two loopback TLS peers with explicit revocation preflight; not OCSP."""
    if not verify_chain(server_cert, intermediate_cert, root_cert, revoked):
        return False
    if not verify_chain(client_cert, intermediate_cert, root_cert, revoked):
        return False
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    def pem(cert): return cert.public_bytes(serialization.Encoding.PEM)
    (folder/'ca.pem').write_bytes(pem(intermediate_cert)+pem(root_cert))
    (folder/'server.pem').write_bytes(pem(server_cert)+pem(intermediate_cert))
    (folder/'client.pem').write_bytes(pem(client_cert)+pem(intermediate_cert))
    for name,key in [('server',server_key),('client',client_key)]:
        (folder/f'{name}.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
        (folder/f'{name}.key').chmod(0o600)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(folder/'server.pem'),str(folder/'server.key'))
    server_ctx.load_verify_locations(cafile=str(folder/'ca.pem'))
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(folder/'ca.pem'))
    client_ctx.load_cert_chain(str(folder/'client.pem'),str(folder/'client.key'))
    client_ctx.check_hostname = True
    outcome = []
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
        port=listener.getsockname()[1]
        def serve():
            try:
                with listener.accept()[0] as sock:
                    sock.settimeout(5)
                    with server_ctx.wrap_socket(sock,server_side=True) as tls:
                        outcome.append(tls.recv(4)==b'ping')
                        tls.sendall(b'pong')
            except Exception:
                outcome.append(False)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=5) as sock:
                with client_ctx.wrap_socket(sock,server_hostname='server.lab.test') as tls:
                    tls.sendall(b'ping');response=tls.recv(4)
        finally:
            thread.join(timeout=6)
    return response==b'pong' and outcome==[True]
