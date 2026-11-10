"""Multi-role AI-assisted PKI workflow.

LLM advice is untrusted. Only the deterministic Orchestrator may issue or
revoke certificates. AI failures fail closed for advisory output, not policy.
"""
from __future__ import annotations

import json
from pathlib import Path

from .core import validate_csr
from .llm import OllamaAdvisor


class AdvisoryWorkflow:
    """Run five specialized Ollama roles across issuance, revocation and audit."""

    def __init__(self, orchestrator, advisor=None, trace_path=None):
        self.orchestrator = orchestrator
        self.advisor = advisor if advisor is not None else OllamaAdvisor()
        self.trace_path = Path(trace_path) if trace_path else None

    def _advise(self, role, data):
        try:
            result = self.advisor.advise(role, data)
            if not isinstance(result, dict) or result.get("authoritative") is not False:
                raise ValueError("Untrusted advisor result")
            advice = result.get("advice")
            if not isinstance(advice, str):
                raise ValueError("Missing advisory text")
            record = {"role": role, "status": "ok", "advice": advice, "authoritative": False}
        except Exception as exc:
            # No secrets or full exception text are written to the trace.
            record = {"role": role, "status": "unavailable",
                      "error_type": type(exc).__name__, "authoritative": False}
        if self.trace_path:
            self.trace_path.parent.mkdir(parents=True, exist_ok=True)
            with self.trace_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def request(self, csr, days):
        names = csr.subject.rfc4514_string()
        try:
            dns = csr.extensions.get_extension_for_class(
                __import__("cryptography").x509.SubjectAlternativeName
            ).value.get_values_for_type(__import__("cryptography").x509.DNSName)
            name = dns[0] if len(dns) == 1 else names
        except Exception:
            name = names
        metadata = {"dns": name, "days": days}
        advice = [self._advise("guichet", metadata)]
        valid, reason = validate_csr(csr, days, self.orchestrator.policy)
        advice.append(self._advise("controleur", {
            **metadata, "policy_result": "approved" if valid else "rejected",
            "reason": reason,
        }))
        # The deterministic policy and signer are the sole authority.
        result = self.orchestrator.request(csr, days)
        advice.append(self._advise("emetteur", {
            **metadata, "status": "issued" if result["accepted"] else "denied",
            "reason": result["reason"],
        }))
        advice.append(self._advise("auditeur", {
            "action": "issuance", "status": "issued" if result["accepted"] else "denied",
        }))
        return {"decision": result, "advisories": advice, "mode": "ollama_advisory"}

    def revoke(self, serial):
        advice = [self._advise("revocation", {"action": "revoke", "status": "requested"})]
        crl = self.orchestrator.revoke(serial)
        advice.append(self._advise("auditeur", {"action": "revoke", "status": "completed"}))
        return {"crl": crl, "advisories": advice, "mode": "ollama_advisory"}

    def audit(self, serial):
        valid = self.orchestrator.audit(serial)
        advice = [self._advise("auditeur", {
            "action": "audit", "status": "valid" if valid else "invalid",
        })]
        return {"valid": valid, "advisories": advice, "mode": "ollama_advisory"}
