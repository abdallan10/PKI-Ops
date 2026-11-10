"""Opt-in five-role tool-selection workflow with deterministic PKI authority.

The model selects a tool for each role. Model-supplied arguments are ignored
and never reach executable PKI operations. Python binds trusted request data to closed, role-specific tools.
The controller and issuer must complete before any certificate is issued.
"""
from __future__ import annotations

from .agentic import AgenticLoop, AgentDecisionError, ToolRegistry
from .core import validate_csr


class AgenticPKIWorkflow:
    def __init__(self, orchestrator, model=None, trace_path=None, max_attempts=2):
        if model is None:
            from .llm import OllamaDecisionModel
            model = OllamaDecisionModel()
        self.engine = orchestrator
        self.model = model
        self.trace_path = trace_path
        self.max_attempts = max_attempts

    def _step(self, role, metadata, tools, required):
        # Model arguments are untrusted hints, never execution parameters.
        # Bind every operation to trusted Python closures; only the expected
        # tool is registered, so an unauthorized choice cannot execute.
        if set(tools) != {required}:
            raise ValueError("exactly the required tool must be registered")

        def trusted_tool(**_untrusted_arguments):
            return tools[required]()

        def verify(decision, _result):
            return decision.tool == required
        loop = AgenticLoop(self.model, ToolRegistry({required: trusted_tool}),
                           verifier=verify,
                           max_attempts=self.max_attempts, trace_path=self.trace_path)
        return loop.run(role, metadata)

    def request(self, csr, days):
        from cryptography import x509
        try:
            names = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            dns = names[0] if len(names) == 1 else "(invalid SAN)"
        except (x509.ExtensionNotFound, ValueError):
            dns = "(missing SAN)"
        metadata = {"dns": dns, "days": days}
        steps = []
        try:
            steps.append(self._step("guichet", metadata, {
                "parser_demande": lambda: {"dns": dns, "days": days},
            }, "parser_demande"))
            valid, reason = validate_csr(csr, days, self.engine.policy)
            steps.append(self._step("controleur", {
                **metadata, "policy_result": "approved" if valid else "rejected",
                "reason": reason,
            }, {"verifier_politique": lambda: {"valid": valid, "reason": reason}},
                "verifier_politique"))
            if not valid:
                return {"decision": {"accepted": False, "reason": reason, "serial": None},
                        "steps": steps, "mode": "ollama_agentic"}
            # The issuer tool is the only entry to signing, and delegates to
            # Orchestrator.request which validates CSR and policy AGAIN.
            steps.append(self._step("emetteur", {
                **metadata, "status": "approved",
            }, {"emettre_certificat": lambda: self.engine.request(csr, days)},
                "emettre_certificat"))
            decision = steps[-1]["result"]
            # Auditing is advisory; never roll back an already issued cert
            # or hide the result because an LLM is unavailable.
            try:
                steps.append(self._step("auditeur", {
                    "action": "issuance", "status": "issued" if decision["accepted"] else "denied",
                }, {"verifier_chaine": lambda: self.engine.audit(decision["serial"])},
                    "verifier_chaine"))
            except (AgentDecisionError, TimeoutError, ConnectionError):
                pass
            return {"decision": decision, "steps": steps, "mode": "ollama_agentic"}
        except (AgentDecisionError, TimeoutError, ConnectionError):
            return {"decision": {"accepted": False, "reason": "agent unavailable or unverified",
                                 "serial": None}, "steps": steps, "mode": "ollama_agentic"}

    def revoke(self, serial):
        # Revocation is security-critical: execute deterministically even when
        # the model is down; a model cannot veto or delay revocation.
        result = self.engine.revoke(serial)
        steps = []
        try:
            steps.append(self._step("revocation", {"action": "revoke", "status": "completed"},
                                    {"publier_crl": lambda: True}, "publier_crl"))
            steps.append(self._step("auditeur", {"action": "revoke", "status": "completed"},
                                    {"verifier_chaine": lambda: not self.engine.audit(serial)},
                                    "verifier_chaine"))
        except (AgentDecisionError, TimeoutError, ConnectionError):
            pass
        return {"crl": result, "steps": steps, "mode": "ollama_agentic"}

    def audit(self, serial):
        valid = self.engine.audit(serial)
        steps = []
        try:
            steps.append(self._step("auditeur", {
                "action": "audit", "status": "valid" if valid else "invalid",
            }, {"verifier_chaine": lambda: valid}, "verifier_chaine"))
        except (AgentDecisionError, TimeoutError, ConnectionError):
            pass
        return {"valid": valid, "steps": steps, "mode": "ollama_agentic"}
