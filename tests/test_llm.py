"""Offline tests for optional LLM advisory mode (no Ollama installation needed)."""
import io
import json
from unittest.mock import patch

import pytest

from pkiops.llm import OllamaAdvisor, ROLES


def test_five_roles_defined():
    assert set(ROLES) == {"guichet", "controleur", "emetteur", "revocation", "auditeur"}


def test_advisor_calls_local_api_and_is_non_authoritative():
    advisor = OllamaAdvisor()
    response = io.BytesIO(json.dumps({"response": "Analyse uniquement"}).encode())
    with patch("pkiops.llm.request.urlopen", return_value=response) as call:
        result = advisor.advise("controleur", {"dns": "node.lab.test", "days": 30, "password": "SECRET"})
    assert result["authoritative"] is False
    assert result["advice"] == "Analyse uniquement"
    payload = json.loads(call.call_args.args[0].data)
    assert payload["stream"] is False
    assert "SECRET" not in payload["prompt"]
    assert "node.lab.test" in payload["prompt"]


def test_reject_unknown_role_without_network():
    with pytest.raises(ValueError, match="Unknown"):
        OllamaAdvisor().advise("admin", {"dns": "node.lab.test"})


def test_reject_non_dict_input_without_network():
    with pytest.raises(TypeError):
        OllamaAdvisor().advise("guichet", "unsafe")
