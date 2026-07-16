.PHONY: test quality demo answer-demo adapter-demo sarif-demo summary-demo eval

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

adapter-demo:
	PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/adapters/markdown \
		--context-format markdown \
		--fail-on critical
	PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/adapters/langchain/documents.jsonl \
		--context-format langchain-jsonl \
		--fail-on critical
	PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/adapters/llamaindex/nodes.json \
		--context-format llamaindex-json \
		--fail-on critical

sarif-demo:
	@PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/support-pack/context.jsonl \
		--policy examples/support-pack/policy.json \
		--format sarif \
		--fail-on critical

summary-demo:
	@PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/support-pack/context.jsonl \
		--policy examples/support-pack/policy.json \
		--format markdown \
		--fail-on critical

eval:
	PYTHONPATH=src $(PYTHON) -m contextaudit eval \
		--suite examples/support-pack/suite.json
