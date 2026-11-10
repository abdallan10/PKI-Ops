"""Offline integration checks for the opt-in agentic PKI workflow."""
import json

from pkiops.agents import Orchestrator
from pkiops.agentic_workflow import AgenticPKIWorkflow
from pkiops.core import create_intermediate, create_root, keypair, make_csr


POLICY = {"allowed_dns_suffix": ".lab.test", "max_days": 90,
          "min_rsa_bits": 2048, "allowed_algorithms": ["RSA", "EC"]}


class ScriptedModel:
    def __init__(self, overrides=None):
        self.roles = []
        self.overrides = overrides or {}

    def decide(self, role, context, allowed_tools):
        self.roles.append(role)
        tools = {"guichet": "parser_demande", "controleur": "verifier_politique",
                 "emetteur": "emettre_certificat", "revocation": "publier_crl",
                 "auditeur": "verifier_chaine"}
        tool = self.overrides.get(role, tools[role])
        return json.dumps({"tool": tool, "arguments": {}, "explanation": "test"})


def setup(tmp_path, model):
    rk, ik = keypair(), keypair()
    root = create_root(rk)
    inter = create_intermediate(root, rk, ik)
    engine = Orchestrator(POLICY, inter, ik, root, tmp_path / "ledger.jsonl")
    return AgenticPKIWorkflow(engine, model=model, trace_path=tmp_path / "trace.jsonl")


def test_valid_request_runs_four_roles_and_signs(tmp_path):
    model = ScriptedModel()
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    assert result["decision"]["accepted"]
    assert model.roles == ["guichet", "controleur", "emetteur", "auditeur"]
    assert workflow.engine.audit(result["decision"]["serial"])
    assert len((tmp_path / "ledger.jsonl").read_text().splitlines()) == 1


def test_invalid_request_never_reaches_issuer(tmp_path):
    model = ScriptedModel()
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "evil.test"), 30)
    assert not result["decision"]["accepted"]
    assert model.roles == ["guichet", "controleur"]
    assert not (tmp_path / "ledger.jsonl").exists()


def test_issuer_tool_mismatch_fails_closed(tmp_path):
    model = ScriptedModel({"emetteur": "verifier_politique"})
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    assert not result["decision"]["accepted"]
    assert not (tmp_path / "ledger.jsonl").exists()


def test_revocation_cannot_be_vetoed_by_model(tmp_path):
    model = ScriptedModel()
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    serial = result["decision"]["serial"]

    class Offline:
        def decide(self, *args):
            raise ConnectionError("offline")

    workflow.model = Offline()
    revoked = workflow.revoke(serial)
    assert revoked["crl"] is not None
    assert not workflow.engine.audit(serial)


def test_audit_after_revocation(tmp_path):
    workflow = setup(tmp_path, ScriptedModel())
    serial = workflow.request(make_csr(keypair(), "node.lab.test"), 30)["decision"]["serial"]
    assert workflow.audit(serial)["valid"]
    workflow.revoke(serial)
    assert not workflow.audit(serial)["valid"]
