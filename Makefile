.PHONY: test quality demo answer-demo eval

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

answer-demo:
	PYTHONPATH=src $(PYTHON) -m contextaudit audit-answer \
		--context examples/support-pack/context.jsonl \
		--answer examples/support-pack/answer-supported.json \
		--policy examples/support-pack/policy.json \
		--fail-on high

eval:
	PYTHONPATH=src $(PYTHON) -m contextaudit eval \
		--suite examples/support-pack/suite.json
