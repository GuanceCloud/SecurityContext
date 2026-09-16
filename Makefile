PYTHON ?= python3

.PHONY: test test-java test-node test-python schemas

test: test-java test-node test-python

test-java:
	cd java && ./gradlew test --no-daemon

test-node:
	npm --prefix nodejs test

schemas:
	$(PYTHON) tests/sbom/fetch_schemas.py

test-python: schemas
	$(PYTHON) -m pytest python/tests
