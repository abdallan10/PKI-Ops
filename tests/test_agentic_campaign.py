"""Offline checks for the live-campaign scenario specification."""
from pkiops.agentic_campaign import scenarios
from pkiops.core import keypair, make_csr, validate_csr
from pkiops.agentic_campaign import POLICY


def test_sixty_cases_match_deterministic_policy():
    cases = scenarios()
    assert len(cases) == 60
    assert sum(c["expected_accepted"] for c in cases) == 30
    assert sum(not c["expected_accepted"] for c in cases) == 30
    assert sum(c["request_note"] is not None for c in cases) == 10
    assert all(not c["expected_accepted"] for c in cases if c["request_note"])
    assert len({c["id"] for c in cases}) == 60
    for case in cases:
        csr = make_csr(keypair(case["bits"]), case["dns"])
        valid, _reason = validate_csr(csr, case["days"], POLICY)
        assert valid is case["expected_accepted"], case["id"]
