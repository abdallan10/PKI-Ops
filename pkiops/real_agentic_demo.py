"""Run a local, disposable PKI-Ops agentic experiment with real Ollama.

Run: python -m pkiops.real_agentic_demo
No private keys are written to disk. Only public certs and sanitized logs
are stored under results/local-agentic-demo (not intended for publication).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .agents import Orchestrator
from .agentic_workflow import AgenticPKIWorkflow
from .core import (create_intermediate, create_root, keypair, make_csr,
                   save_cert, verify_ledger)
from .llm import OllamaDecisionModel


def main():
    output = Path("results/local-agentic-demo")
    output.mkdir(parents=True, exist_ok=True)
    trace = output / "agentic-trace.jsonl"
    ledger = output / "ledger.jsonl"
    # Each run creates a fresh independent root and ledger.
    trace.unlink(missing_ok=True)
    ledger.unlink(missing_ok=True)
    root_key, intermediate_key = keypair(), keypair()
    root = create_root(root_key)
    intermediate = create_intermediate(root, root_key, intermediate_key)
    save_cert(root, output / "root.pem")
    save_cert(intermediate, output / "intermediate.pem")
    policy = {"allowed_dns_suffix": ".lab.test", "max_days": 90,
              "min_rsa_bits": 2048, "allowed_algorithms": ["RSA", "EC"]}
    engine = Orchestrator(policy, intermediate, intermediate_key, root, ledger,
                          trace_path=output / "orchestrator-trace.jsonl")
    workflow = AgenticPKIWorkflow(
        engine, model=OllamaDecisionModel(model="qwen2.5:1.5b"),
        trace_path=trace, max_attempts=2,
    )
    print("Modèle: qwen2.5:1.5b | PKI temporaire | clés en mémoire uniquement",
          flush=True)
    print("1/3 Demande autorisée (node.lab.test)...", flush=True)
    good = workflow.request(make_csr(keypair(), "node.lab.test"), 30)
    issued = bool(good["decision"]["accepted"])
    print("   Certificat émis:", issued, flush=True)
    if issued:
        save_cert(good["decision"]["certificate"], output / "node.pem")
        print("   Chaîne valide:", engine.audit(good["decision"]["serial"]),
              flush=True)

    print("2/3 Demande interdite (attacker.evil.test)...", flush=True)
    bad = workflow.request(make_csr(keypair(), "attacker.evil.test"), 30)
    denied = not bad["decision"]["accepted"]
    print("   Demande refusée:", denied, flush=True)

    revoked = None
    if issued:
        print("3/3 Révocation du certificat émis...", flush=True)
        workflow.revoke(good["decision"]["serial"])
        revoked = not engine.audit(good["decision"]["serial"])
        print("   Certificat refusé après révocation:", revoked, flush=True)
    else:
        print("3/3 Révocation non testée : aucun certificat émis", flush=True)

    ledger_ok = verify_ledger(ledger, intermediate_key.public_key()) if ledger.exists() else None
    print("   Journal signé vérifié:", ledger_ok, flush=True)
    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": "qwen2.5:1.5b",
        "allowed_issued": issued,
        "forbidden_denied": denied,
        "revoked_refused": revoked,
        "ledger_verified": ledger_ok,
        "agentic_trace": str(trace),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("Résultats:", json.dumps(summary, ensure_ascii=False), flush=True)
    print("Traces:", trace, flush=True)
    if not (issued and denied and revoked and ledger_ok):
        raise SystemExit("Expérience incomplète : voir les traces et le résumé")


if __name__ == "__main__":
    main()
