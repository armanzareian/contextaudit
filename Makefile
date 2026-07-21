.PHONY: test quality demo answer-demo adapter-demo extension-demo sarif-demo summary-demo ci-policy-demo eval

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

extension-demo:
	PYTHONPATH=src $(PYTHON) examples/extensions/custom_loader.py

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

ci-policy-demo:
	@PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/support-pack/context.jsonl \
		--policy examples/ci/pass-policy.json \
		--format markdown \
		> /tmp/contextaudit-pass-policy.md
	@if PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/support-pack/context.jsonl \
		--policy examples/ci/fail-policy.json \
		--format markdown \
		> /tmp/contextaudit-fail-policy.md; then \
		echo "expected fail-policy.json to fail"; \
		exit 1; \
	else \
		code=$$?; \
		test $$code -eq 1; \
	fi
	@if PYTHONPATH=src $(PYTHON) -m contextaudit scan \
		--context examples/support-pack/context.jsonl \
		--policy examples/ci/malformed-policy.json \
		--format json \
		> /tmp/contextaudit-malformed-policy.out \
		2> /tmp/contextaudit-malformed-policy.err; then \
		echo "expected malformed-policy.json to exit 2"; \
		exit 1; \
	else \
		code=$$?; \
		test $$code -eq 2; \
	fi

eval:
	PYTHONPATH=src $(PYTHON) -m contextaudit eval \
		--suite examples/support-pack/suite.json
