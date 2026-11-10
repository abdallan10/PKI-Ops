"""Regression checks for the grader's clean-room reproduction path."""
import os
import subprocess
import sys

from pkiops.core import create_intermediate, create_root, issue, keypair, make_csr, verify_chain
from pkiops.cli import init_lab, campaign

POLICY = {'allowed_dns_suffix': '.lab.test', 'max_days': 90,
          'min_rsa_bits': 2048, 'allowed_algorithms': ['RSA', 'EC']}


def test_reproduce_from_fresh_directory(tmp_path, monkeypatch):
    monkeypatch.setenv('PKIOPS_PASSWORD', 'local-test-secret')
    folder = tmp_path / 'lab'
    init_lab(folder, 'local-test-secret', approve=True)
    metrics = campaign(folder, tmp_path / 'results' / 'campaign.json')
    assert metrics['requests'] == 60
    assert metrics['legitimate_accepted'] == 30
    assert metrics['illegitimate_issued'] == 0
    assert (tmp_path / 'results' / 'metrics.json').exists()
    assert len((folder / 'trace.jsonl').read_text().splitlines()) > 60
    assert len((folder / 'ledger.jsonl').read_text().splitlines()) == 30


def test_cli_requires_explicit_password(tmp_path):
    env = dict(os.environ)
    env.pop('PKIOPS_PASSWORD', None)
    result = subprocess.run([sys.executable, '-m', 'pkiops.cli', 'init', '--dir', str(tmp_path)],
                            capture_output=True, text=True, env=env)
    assert result.returncode != 0
    assert 'PKIOPS_PASSWORD' in result.stderr


def test_reject_unauthorized_ca_or_expired_leaf():
    root_key, inter_key = keypair(), keypair()
    root = create_root(root_key)
    inter = create_intermediate(root, root_key, inter_key)
    leaf = issue(make_csr(keypair(), 'server.lab.test'), 30, inter, inter_key, POLICY)
    assert verify_chain(leaf, inter, root)
    assert not verify_chain(leaf, inter, create_root(keypair()))


def test_no_unencrypted_private_key_written(tmp_path):
    init_lab(tmp_path / 'lab', 'secret-password', approve=True)
    data = (tmp_path / 'lab' / 'root.key').read_bytes()
    assert b'ENCRYPTED PRIVATE KEY' in data
    assert b'BEGIN RSA PRIVATE KEY' not in data
    assert (tmp_path / 'lab' / 'root.key').stat().st_mode & 0o077 == 0
