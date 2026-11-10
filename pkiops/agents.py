"""Five specialized, allowlisted agents; deterministic baseline (not an LLM)."""
import json
from pathlib import Path
from .core import validate_csr,issue,verify_chain,crl,append_ledger

ALLOWLIST={
 'guichet':('parser_demande','annuaire_lab'),
 'controleur':('lire_csr','verifier_politique'),
 'emetteur':('emettre_certificat',),
 'revocation':('revoquer','publier_crl'),
 'auditeur':('verifier_chaine','expirations'),
}
class AgentError(Exception):pass
class Orchestrator:
    def __init__(self,policy,inter_cert,inter_key,root_cert,ledger_path,trace_path=None):
        self.policy=policy;self.inter_cert=inter_cert;self.inter_key=inter_key;self.root_cert=root_cert
        self.ledger_path=ledger_path;self.trace_path=trace_path;self.revoked=set();self.issued={}
    def log(self,agent,tool,status,detail=''):
        if tool not in ALLOWLIST[agent]:raise AgentError('unauthorized tool')
        if self.trace_path:
            p=Path(self.trace_path);p.parent.mkdir(parents=True,exist_ok=True)
            with p.open('a') as f:f.write(json.dumps({'agent':agent,'tool':tool,'status':status,'detail':str(detail)})+'\n')
    def request(self,csr,days):
        self.log('guichet','parser_demande','ok','CSR input')
        self.log('controleur','lire_csr','ok')
        ok,reason=validate_csr(csr,days,self.policy)
        self.log('controleur','verifier_politique','approved' if ok else 'rejected',reason)
        if not ok:return {'accepted':False,'reason':reason,'serial':None}
        cert=issue(csr,days,self.inter_cert,self.inter_key,self.policy)
        self.issued[cert.serial_number]=cert
        self.log('emetteur','emettre_certificat','ok',cert.serial_number)
        append_ledger(self.ledger_path,{'action':'issue','serial':str(cert.serial_number)},self.inter_key)
        return {'accepted':True,'reason':'approved','serial':cert.serial_number,'certificate':cert}
    def revoke(self,serial):
        if serial not in self.issued:raise ValueError('unknown serial')
        self.revoked.add(serial)
        self.log('revocation','revoquer','ok',serial)
        append_ledger(self.ledger_path,{'action':'revoke','serial':str(serial)},self.inter_key)
        result=crl(self.inter_cert,self.inter_key,self.revoked)
        self.log('revocation','publier_crl','ok')
        return result
    def audit(self,serial):
        cert=self.issued[serial]
        ok=verify_chain(cert,self.inter_cert,self.root_cert,self.revoked)
        self.log('auditeur','verifier_chaine','ok' if ok else 'rejected',serial)
        return ok
