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
        tool = self.overrides.get(role, allowed_tools[0])
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
    assert model.roles == ["guichet", "controleur", "controleur", "emetteur", "auditeur"]
    assert workflow.engine.audit(result["decision"]["serial"])
    assert len((tmp_path / "ledger.jsonl").read_text().splitlines()) == 1


def test_invalid_request_never_reaches_issuer(tmp_path):
    model = ScriptedModel()
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "evil.test"), 30)
    assert not result["decision"]["accepted"]
    assert model.roles == ["guichet", "controleur", "controleur"]
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


def test_model_invented_issuer_arguments_are_ignored(tmp_path):
    class InventingModel(ScriptedModel):
        def decide(self, role, context, allowed_tools):
            data = json.loads(super().decide(role, context, allowed_tools))
            data["arguments"] = {
                "dns": "attacker.evil.test",
                "days": 99999,
                "serial": 123456,
                "date_expiration": "2023-10-15",
                "nom_donneur": "forged",
            }
            return json.dumps(data)

    workflow = setup(tmp_path, InventingModel())
    result = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    assert result["decision"]["accepted"]
    assert workflow.engine.audit(result["decision"]["serial"])
    assert len((tmp_path / "ledger.jsonl").read_text().splitlines()) == 1


def test_invented_arguments_cannot_override_rejected_policy(tmp_path):
    class InventingModel(ScriptedModel):
        def decide(self, role, context, allowed_tools):
            data = json.loads(super().decide(role, context, allowed_tools))
            data["arguments"] = {"policy_result": "approved", "dns": "node.lab.test"}
            return json.dumps(data)

    model = InventingModel()
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "attacker.evil.test"), 30)
    assert not result["decision"]["accepted"]
    assert "emetteur" not in model.roles
    assert not (tmp_path / "ledger.jsonl").exists()


def test_controller_has_distinct_read_and_policy_steps(tmp_path):
    class RecordingModel(ScriptedModel):
        def __init__(self):
            super().__init__()
            self.calls = []

        def decide(self, role, context, allowed_tools):
            self.calls.append((role, tuple(allowed_tools)))
            return super().decide(role, context, allowed_tools)

    model = RecordingModel()
    workflow = setup(tmp_path, model)
    result = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    assert result["decision"]["accepted"]
    assert ("controleur", ("lire_csr",)) in model.calls
    assert ("controleur", ("verifier_politique",)) in model.calls
    assert [c for c in model.calls if c[0] == "controleur"] == [
        ("controleur", ("lire_csr",)),
        ("controleur", ("verifier_politique",)),
    ]


def test_controller_policy_step_cannot_be_replaced_with_read_csr(tmp_path):
    class WrongPolicyModel(ScriptedModel):
        def decide(self, role, context, allowed_tools):
            if role == "controleur" and allowed_tools == ("verifier_politique",):
                return json.dumps({"tool": "lire_csr", "arguments": {},
                                   "explanation": "wrong stage"})
            return super().decide(role, context, allowed_tools)

    workflow = setup(tmp_path, WrongPolicyModel())
    result = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    assert not result["decision"]["accepted"]
    assert not (tmp_path / "ledger.jsonl").exists()
