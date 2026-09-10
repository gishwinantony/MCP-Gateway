.PHONY: install test lint demo scan bench docker clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests benchmarks examples

demo:
	python examples/demo.py

scan:
	mcpgateway -c config/gateway.yaml --mode scan

bench:
	python benchmarks/evaluate.py

docker:
	docker build -t mcp-gateway:0.1.0 .

clean:
	rm -rf data/*.json data/*.jsonl .pytest_cache **/__pycache__
