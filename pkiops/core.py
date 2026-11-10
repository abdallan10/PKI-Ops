"""Deterministic crypto tools. Never expose or publish private keys."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

UTC = timezone.utc

def utcnow(): return datetime.now(UTC)
def keypair(bits=2048): return rsa.generate_private_key(public_exponent=65537,key_size=bits)
def subject(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
def save_private(key,path,password):
    if not password: raise ValueError('Private keys must be encrypted at rest')
    data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode()))
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data); os.chmod(p,0o600)
def load_private(path,password):
    return serialization.load_pem_private_key(Path(path).read_bytes(),password=password.encode())
def save_cert(cert,path):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
def load_cert(path): return x509.load_pem_x509_certificate(Path(path).read_bytes())
def create_root(key,now=None):
    now=now or utcnow(); name=subject('PKI-Ops Lab Root')
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
      .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
      .not_valid_after(now+timedelta(days=365))
      .add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False)
      .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
      .sign(key,hashes.SHA256()))
def create_intermediate(root_cert,root_key,inter_key,now=None):
    """Explicit human root signing is enforced by CLI, not by this low-level tool."""
    now=now or utcnow()
    return (x509.CertificateBuilder().subject_name(subject('PKI-Ops Lab Intermediate')).issuer_name(root_cert.subject)
      .public_key(inter_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=180))
      .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()),critical=False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),critical=False)
      .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName('.lab.test')],excluded_subtrees=None),critical=True)
      .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
      .sign(root_key,hashes.SHA256()))
def make_csr(key,dns):
    return (x509.CertificateSigningRequestBuilder().subject_name(subject(dns))
      .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]),critical=False).sign(key,hashes.SHA256()))
def validate_csr(csr,days,policy):
    try: sans=csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: return False,'missing SAN'
    if not csr.is_signature_valid: return False,'invalid CSR signature'
    if len(sans)!=1: return False,'exactly one DNS SAN required'
    dns=sans[0].lower()
    if not dns.endswith(policy['allowed_dns_suffix']) or dns==policy['allowed_dns_suffix'][1:]: return False,'DNS name outside policy'
    if any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in dns) or '..' in dns: return False,'invalid DNS name'
    if not isinstance(days,int) or isinstance(days,bool) or not 1<=days<=policy['max_days']: return False,'invalid duration'
    pub=csr.public_key()
    if isinstance(pub,rsa.RSAPublicKey):
        if 'RSA' not in policy['allowed_algorithms'] or pub.key_size<policy['min_rsa_bits']: return False,'weak or disallowed RSA'
    elif isinstance(pub,ec.EllipticCurvePublicKey):
        if 'EC' not in policy['allowed_algorithms'] or pub.key_size<256: return False,'weak or disallowed EC'
    else: return False,'unsupported key'
    return True,'approved'
def issue(csr,days,inter_cert,inter_key,policy,now=None):
    ok,reason=validate_csr(csr,days,policy)
    if not ok: raise ValueError(reason)
    now=now or utcnow()
    if now+timedelta(days=days)>inter_cert.not_valid_after_utc: raise ValueError('intermediate expires before leaf')
    return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(inter_cert.subject)
      .public_key(csr.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=days))
      .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),critical=False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),critical=False)
      .add_extension(x509.SubjectAlternativeName(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),critical=False)
      .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
      .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
      .sign(inter_key,hashes.SHA256()))
def crl(inter_cert,inter_key,serials,now=None):
    now=now or utcnow()
    b=(x509.CertificateRevocationListBuilder().issuer_name(inter_cert.subject)
       .last_update(now-timedelta(minutes=1)).next_update(now+timedelta(days=1)))
    for serial in sorted(set(serials)):
        b=b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build())
    return b.sign(inter_key,hashes.SHA256())
def verify_chain(leaf,inter,root,revoked=()):
    now=utcnow()
    if leaf.serial_number in revoked: return False
    for cert in (leaf,inter,root):
        if not cert.not_valid_before_utc<=now<=cert.not_valid_after_utc: return False
    if leaf.issuer!=inter.subject or inter.issuer!=root.subject or root.issuer!=root.subject: return False
    try:
        root.public_key().verify(root.signature,root.tbs_certificate_bytes,root.signature_algorithm_parameters,root.signature_hash_algorithm)
        root.public_key().verify(inter.signature,inter.tbs_certificate_bytes,inter.signature_algorithm_parameters,inter.signature_hash_algorithm)
        inter.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,leaf.signature_algorithm_parameters,leaf.signature_hash_algorithm)
        if not inter.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: return False
        if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: return False
        names=leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        if not names or any(not n.lower().endswith('.lab.test') for n in names): return False
        return True
    except Exception: return False

def append_ledger(path,event,signer):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    lines=p.read_text().splitlines() if p.exists() else []
    previous=json.loads(lines[-1])['digest'] if lines else '0'*64
    payload={'index':len(lines),'previous':previous,'event':event}
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    sig=signer.sign(bytes.fromhex(digest),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    record={**payload,'digest':digest,'signature':base64.b64encode(sig).decode()}
    with p.open('a') as f:f.write(json.dumps(record,sort_keys=True)+'\n')
    return record

def verify_ledger(path,public_key):
    previous='0'*64
    for i,line in enumerate(Path(path).read_text().splitlines()):
        r=json.loads(line); payload={k:r[k] for k in ('index','previous','event')}
        digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if r['index']!=i or r['previous']!=previous or r['digest']!=digest:return False
        try:public_key.verify(base64.b64decode(r['signature']),bytes.fromhex(digest),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
        except Exception:return False
        previous=digest
    return True
