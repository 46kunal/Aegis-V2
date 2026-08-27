.PHONY: test test-backend test-frontend build-frontend build-backend lint-backend lint-frontend install-backend install-frontend

BACKEND_DIR := backend
FRONTEND_DIR := frontend
BACKEND_PYTHON := backend/.venv/bin/python

install-backend:
	python3 -m venv $(BACKEND_DIR)/.venv
	$(BACKEND_PYTHON) -m pip install --upgrade pip
	$(BACKEND_PYTHON) -m pip install -r $(BACKEND_DIR)/requirements.txt pytest httpx

install-frontend:
	cd $(FRONTEND_DIR) && npm install

build-backend:
	test -x $(BACKEND_PYTHON) || $(MAKE) install-backend
	cd $(BACKEND_DIR) && .venv/bin/python -m compileall app

build-frontend:
	cd $(FRONTEND_DIR) && npm run build

test-backend:
	test -x $(BACKEND_PYTHON) || $(MAKE) install-backend
	cd $(BACKEND_DIR) && .venv/bin/python -m pytest

test-frontend:
	cd $(FRONTEND_DIR) && npm run test

test: test-backend test-frontend

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down -v
