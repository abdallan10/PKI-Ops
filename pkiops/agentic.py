"""Bounded, auditable LLM tool-selection loop.

This is an opt-in agentic component. Tool outputs and model decisions are
untrusted. It never accepts a model-generated authorization to sign.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from .agents import ALLOWLIST


@dataclass(frozen=True)
class Decision:
    role: str
    tool: str
    arguments: dict
    explanation: str


class AgentDecisionError(RuntimeError):
    """A role could not produce a valid, authorized decision."""


class ToolRegistry:
    def __init__(self, implementations: dict[str, Callable]):
        self.implementations = dict(implementations)

    def execute(self, decision: Decision):
        if decision.role not in ALLOWLIST:
            raise AgentDecisionError("unknown role")
        if decision.tool not in ALLOWLIST[decision.role]:
            raise AgentDecisionError("tool not permitted for role")
        function = self.implementations.get(decision.tool)
        if function is None:
            raise AgentDecisionError("tool implementation unavailable")
        # Only pre-registered Python functions execute. No shell/eval/exec.
        return function(**decision.arguments)


class AgenticLoop:
    """Select a tool, validate it, execute, verify; retry at most max_attempts.

    The model is expected to expose decide(role, context, allowed_tools),
    returning JSON text or a decoded dict. An optional verifier is deterministic
    and must return True before an outcome is considered successful.
    """

    def __init__(self, model, registry: ToolRegistry, verifier=None,
                 max_attempts=2, trace_path=None):
        if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 5:
            raise ValueError("max_attempts must be between 1 and 5")
        self.model = model
        self.registry = registry
        self.verifier = verifier or (lambda _decision, _result: True)
        self.max_attempts = max_attempts
        self.trace_path = trace_path

    def _trace(self, event):
        if self.trace_path is None:
            return
        from pathlib import Path
        path = Path(self.trace_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Never log request payloads, tool arguments, secrets or exception text.
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, sort_keys=True) + "\n")

    def run(self, role, context):
        if role not in ALLOWLIST:
            raise AgentDecisionError("unknown role")
        if not isinstance(context, dict):
            raise TypeError("context must be a dictionary")
        tools = tuple(ALLOWLIST[role])
        feedback = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                prompt = dict(context)
                if feedback:
                    prompt["verification_feedback"] = feedback
                raw = self.model.decide(role, prompt, tools)
                data = json.loads(raw) if isinstance(raw, str) else raw
                if not isinstance(data, dict):
                    raise AgentDecisionError("invalid JSON object")
                if set(data) != {"tool", "arguments", "explanation"}:
                    raise AgentDecisionError("invalid decision schema")
                tool, arguments, explanation = (data["tool"], data["arguments"],
                                                data["explanation"])
                if not isinstance(tool, str) or tool not in tools:
                    raise AgentDecisionError("unauthorized tool")
                if not isinstance(arguments, dict) or not all(
                    isinstance(k, str) for k in arguments
                ):
                    raise AgentDecisionError("invalid arguments")
                if not isinstance(explanation, str) or not explanation.strip():
                    raise AgentDecisionError("missing explanation")
                decision = Decision(role, tool, arguments, explanation)
                result = self.registry.execute(decision)
                if self.verifier(decision, result) is not True:
                    raise AgentDecisionError("verification failed")
                self._trace({"role": role, "attempt": attempt, "tool": tool,
                             "status": "verified"})
                return {"decision": decision, "result": result,
                        "attempts": attempt, "verified": True}
            except (ValueError, TypeError, KeyError, AgentDecisionError,
                    TimeoutError, ConnectionError) as exc:
                feedback = type(exc).__name__
                self._trace({"role": role, "attempt": attempt,
                             "status": "retry" if attempt < self.max_attempts else "failed",
                             "error_type": feedback})
        raise AgentDecisionError("agent exhausted attempts; no authorization granted")
