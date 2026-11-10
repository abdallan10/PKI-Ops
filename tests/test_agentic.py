"""Offline tests for the opt-in bounded agentic loop."""
import json

import pytest

from pkiops.agentic import AgenticLoop, AgentDecisionError, ToolRegistry


class Model:
    def __init__(self, *answers):
        self.answers = iter(answers)
        self.calls = []

    def decide(self, role, context, allowed_tools):
        self.calls.append((role, context, allowed_tools))
        answer = next(self.answers)
        if isinstance(answer, Exception):
            raise answer
        return answer


def reply(tool="verifier_politique", arguments=None):
    return json.dumps({"tool": tool, "arguments": arguments or {},
                       "explanation": "Vérifier la politique"})


def test_select_and_execute_allowlisted_tool(tmp_path):
    model = Model(reply())
    loop = AgenticLoop(model, ToolRegistry({"verifier_politique": lambda: "rejected"}),
                       verifier=lambda d, r: r == "rejected",
                       trace_path=tmp_path / "trace.jsonl")
    outcome = loop.run("controleur", {"dns": "bad.evil.test"})
    assert outcome["verified"] and outcome["result"] == "rejected"
    assert model.calls[0][2] == ("lire_csr", "verifier_politique")
    assert "bad.evil.test" not in (tmp_path / "trace.jsonl").read_text()


def test_unauthorized_tool_never_executes():
    calls = []
    model = Model(reply("emettre_certificat"), reply("emettre_certificat"))
    loop = AgenticLoop(model, ToolRegistry({
        "emettre_certificat": lambda: calls.append("signed")
    }))
    with pytest.raises(AgentDecisionError):
        loop.run("guichet", {})
    assert not calls


def test_invalid_json_then_retry():
    model = Model("{invalid", reply())
    loop = AgenticLoop(model, ToolRegistry({"verifier_politique": lambda: True}))
    assert loop.run("controleur", {})["attempts"] == 2
    assert model.calls[1][1]["verification_feedback"] == "JSONDecodeError"


def test_verifier_rejection_fails_closed():
    model = Model(reply(), reply())
    loop = AgenticLoop(model, ToolRegistry({"verifier_politique": lambda: False}),
                       verifier=lambda d, r: r)
    with pytest.raises(AgentDecisionError):
        loop.run("controleur", {})


def test_timeout_retries_and_fails_closed():
    model = Model(TimeoutError(), ConnectionError())
    loop = AgenticLoop(model, ToolRegistry({}))
    with pytest.raises(AgentDecisionError):
        loop.run("controleur", {})
    assert len(model.calls) == 2


def test_invalid_schema_never_executes():
    calls = []
    model = Model({"tool": "verifier_politique", "arguments": {},
                   "explanation": "ok", "extra": "inject"},
                  {"tool": "verifier_politique", "arguments": {},
                   "explanation": "ok", "extra": "inject"})
    loop = AgenticLoop(model, ToolRegistry({
        "verifier_politique": lambda: calls.append(1)
    }))
    with pytest.raises(AgentDecisionError):
        loop.run("controleur", {})
    assert calls == []


def test_unknown_role_rejected():
    loop = AgenticLoop(Model(), ToolRegistry({}))
    with pytest.raises(AgentDecisionError):
        loop.run("root_admin", {})
