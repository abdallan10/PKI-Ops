import json
import pytest
from pkiops.core import *
from pkiops.agents import Orchestrator,AgentError
from pkiops.cli import init_lab

@pytest.fixture
def lab(tmp_path):
    rk=keypair();ik=keypair();rc=create_root(rk);ic=create_intermediate(rc,rk,ik)
    policy={'allowed_dns_suffix':'.lab.test','max_days':90,'min_rsa_bits':2048,'allowed_algorithms':['RSA','EC']}
    return tmp_path,rk,ik,rc,ic,policy

def test_chain(lab):
    _,_,ik,rc,ic,p=lab
    leaf=issue(make_csr(keypair(),'web.lab.test'),30,ic,ik,p)
    assert verify_chain(leaf,ic,rc)
    assert not verify_chain(leaf,ic,rc,[leaf.serial_number])

def test_invalid_names_and_duration(lab):
    _,_,ik,rc,ic,p=lab
    for dns,days in [('web.evil.test',30),('web.lab.test',91),('lab.test',30),('web.lab.test',0)]:
        csr=make_csr(keypair(),dns)
        assert not validate_csr(csr,days,p)[0]
        with pytest.raises(ValueError):issue(csr,days,ic,ik,p)

def test_weak_key(lab):
    *_,p=lab
    assert not validate_csr(make_csr(keypair(1024),'web.lab.test'),30,p)[0]

def test_ledger_detects_tampering(lab):
    folder,_,ik,_,_,_=lab
    path=folder/'ledger.jsonl'
    append_ledger(path,{'action':'issue','serial':'12'},ik)
    append_ledger(path,{'action':'revoke','serial':'12'},ik)
    assert verify_ledger(path,ik.public_key())
    path.write_text(path.read_text().replace('revoke','issue'))
    assert not verify_ledger(path,ik.public_key())

def test_agents_and_revocation(lab):
    folder,_,ik,rc,ic,p=lab
    a=Orchestrator(p,ic,ik,rc,folder/'ledger',folder/'traces')
    accepted=a.request(make_csr(keypair(),'client.lab.test'),30)
    assert accepted['accepted'] and a.audit(accepted['serial'])
    rejected=a.request(make_csr(keypair(),'client.attacker.test'),30)
    assert not rejected['accepted']
    result=a.revoke(accepted['serial'])
    assert len(result)==1 and not a.audit(accepted['serial'])
    assert verify_ledger(folder/'ledger',ik.public_key())
    with pytest.raises(ValueError):a.revoke(123)
    with pytest.raises(AgentError):a.log('guichet','emettre_certificat','ok')

def test_root_approval_and_encryption(tmp_path):
    with pytest.raises(PermissionError):init_lab(tmp_path/'lab','password',False)
    init_lab(tmp_path/'lab','password',True)
    assert b'ENCRYPTED PRIVATE KEY' in (tmp_path/'lab/root.key').read_bytes()
    with pytest.raises(FileExistsError):init_lab(tmp_path/'lab','password',True)

def test_csr_signature(lab):
    *_,p=lab
    csr=make_csr(keypair(),'web.lab.test')
    assert csr.is_signature_valid
    assert validate_csr(csr,30,p)[0]

def test_crl(lab):
    _,_,ik,_,ic,_=lab
    revoked=crl(ic,ik,[123,456,123])
    assert len(revoked)==2
    assert revoked.get_revoked_certificate_by_serial_number(123) is not None

def test_campaign_injection_cases(tmp_path, monkeypatch):
    from pkiops.cli import campaign, init_lab
    monkeypatch.setenv('PKIOPS_PASSWORD', 'testing-only-password')
    init_lab(tmp_path/'lab', 'testing-only-password', True)
    metrics = campaign(tmp_path/'lab', tmp_path/'results'/'campaign.json')
    rows = json.loads((tmp_path/'results'/'campaign.json').read_text())
    attacks = [r for r in rows if r['injection']]
    assert len(attacks) == 10
    assert len({r['injection'] for r in attacks}) == 10
    assert metrics['injection_attempts_accepted'] == 0
    assert metrics['legitimate_accepted'] == 30
    assert metrics['illegitimate_issued'] == 0

def test_certificate_rejects_other_ca(lab):
    _, _, ik, rc, ic, policy = lab
    other_root_key = keypair()
    other_root = create_root(other_root_key)
    leaf = issue(make_csr(keypair(), 'web.lab.test'), 30, ic, ik, policy)
    assert not verify_chain(leaf, ic, other_root)

def test_duration_bool_rejected(lab):
    *_, policy = lab
    assert not validate_csr(make_csr(keypair(), 'web.lab.test'), True, policy)[0]
