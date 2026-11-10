.PHONY: test reproduce reproduce-small
export PKIOPS_PASSWORD ?= local-demo-password-change-me

test:
	python -m pytest -q --cov=pkiops --cov-report=term-missing --cov-fail-under=70

reproduce: test
	rm -rf .lab results/raw results/metrics.json
	python -m pkiops.cli init --dir .lab --approve-root
	python -m pkiops.cli campaign --dir .lab --output results/raw/campaign.json

reproduce-small: reproduce
