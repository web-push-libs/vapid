# Utility Makefile for py_vapid
# (because I'm old and like old tools.)
#

default: build

help:
	@echo "You probably want `make build`"

.PHONY: build
build: ./venv/bin/vapid

.PHONY: install
install: build

.PHONY: dev
dev: ./venv/bin/isort

.PHONY: format
format:
	./venv/bin/isort --sp pyproject.toml py_vapid
	./venv/bin/black --config pyproject.toml --target-version py314 py_vapid

.PHONY: lint
lint:
	./venv/bin/isort --sp pyproject.toml -c py_vapid
	./venv/bin/black --config pyproject.toml --check --target-version py314 py_vapid
	./venv/bin/bandit -r -c pyproject.toml py_vapid

.PHONY: test
test: lint
	./venv/bin/pytest -c pyproject.toml py_vapid

# NOTE: Eventually, this will be replaced by github actions.
.PHONY: publish
publish: test
	venv/bin/pip install --upgrade --group pub "."
	venv/bin/python -m build
	echo venv/bin/twine upload dist/* --repository py_vapid --verbose

.PHONY: convert
convert:
	# Why, yes, this does require pandoc. Not all of these commands are for everyone.
	pandoc --from=markdown --to=rst --output README.rst README.markdown

./venv/bin/vapid:
	python -mvenv venv
	venv/bin/pip install "."

./venv/bin/isort: ./venv/bin/vapid
	venv/bin/pip install --group "dev" -e .


