.PHONY: test quality demo eval

PYTHON ?= python3

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

quality:
	$(PYTHON) scripts/quality.py

demo:
	PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/support-pack/context.jsonl \
		--policy examples/support-pack/policy.json \
		--fail-on critical

eval:
	PYTHONPATH=src $(PYTHON) -m contextaudit eval \
		--suite examples/support-pack/suite.json
