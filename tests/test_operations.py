from pkiops.core import keypair, create_root, create_intermediate, make_csr, issue, crl
from pkiops.operations import renewal_due, renew_leaf, verify_revocation, mtls_roundtrip

def setup():
    rk,ik=keypair(),keypair()
    root=create_root(rk);inter=create_intermediate(root,rk,ik)
    policy={'allowed_dns_suffix':'.lab.test','max_days':90,'min_rsa_bits':2048,'allowed_algorithms':['RSA','EC']}
    return root,inter,ik,policy

def test_renewal_and_crl():
    root,inter,ik,p=setup(); key=keypair()
    old=issue(make_csr(key,'server.lab.test'),2,inter,ik,p)
    assert renewal_due(old,within_days=3)
    assert not renewal_due(old,within_days=1)
    new=renew_leaf(old,key,inter,ik,p,days=30)
    assert new.serial_number!=old.serial_number
    assert verify_revocation(crl(inter,ik,[]),new,inter)
    assert not verify_revocation(crl(inter,ik,[new.serial_number]),new,inter)

def test_mtls_and_revocation(tmp_path):
    root,inter,ik,p=setup();sk=keypair();ck=keypair()
    server=issue(make_csr(sk,'server.lab.test'),30,inter,ik,p)
    client=issue(make_csr(ck,'client.lab.test'),30,inter,ik,p)
    assert mtls_roundtrip(tmp_path/'tls',root,inter,server,sk,client,ck)
    assert not mtls_roundtrip(tmp_path/'tls',root,inter,server,sk,client,ck,revoked={client.serial_number})
