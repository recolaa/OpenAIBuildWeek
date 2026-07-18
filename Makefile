.PHONY: install backend ui test

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

backend:
	$(PYTHON) -m uvicorn backend:app --host 127.0.0.1 --port 8003 --reload

ui:
	$(PYTHON) -m streamlit run ui.py

test:
	$(PYTHON) -m pytest -q

