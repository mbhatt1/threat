.PHONY: help install install-dev test test-coverage lint format clean build deploy docker-build docker-run

# Default target
help:
	@echo "Security Audit Framework - Makefile Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make install       - Install production dependencies"
	@echo "  make install-dev   - Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  make test          - Run all tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-unit     - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint          - Run linting checks"
	@echo "  make format        - Format code with black"
	@echo "  make type-check    - Run mypy type checking"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  make build         - Build all components"
	@echo "  make deploy        - Deploy to AWS (requires AWS credentials)"
	@echo "  make deploy-dev    - Deploy to development environment"
	@echo "  make deploy-prod   - Deploy to production environment"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  - Build all Docker images"
	@echo "  make docker-run    - Run docker-compose stack"
	@echo "  make docker-stop   - Stop docker-compose stack"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Remove build artifacts and cache"

# Installation targets
install:
	pip install -r requirements.txt

install-dev: install
	pip install -e .[dev]

# Testing targets
test:
	python -m pytest tests/ -v

test-coverage:
	python -m pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-unit:
	python -m pytest tests/unit/ -v

test-integration:
	python -m pytest tests/integration/ -v

# Code quality targets
lint:
	flake8 src/ tests/
	pylint src/

format:
	black src/ tests/

type-check:
	mypy src/

# Build targets
build: clean
	python setup.py sdist bdist_wheel
	@echo "Building Lambda deployment packages..."
	./scripts/build-lambdas.sh
	@echo "Building agent Docker images..."
	./scripts/build-agents.sh

# Deployment targets
deploy: build
	./scripts/deploy.sh

deploy-dev:
	CDK_DEPLOY_ACCOUNT=$$(aws sts get-caller-identity --query Account --output text) \
	CDK_DEPLOY_REGION=$${AWS_REGION:-us-east-1} \
	cdk deploy --all --require-approval never --context environment=dev

deploy-prod:
	CDK_DEPLOY_ACCOUNT=$$(aws sts get-caller-identity --query Account --output text) \
	CDK_DEPLOY_REGION=$${AWS_REGION:-us-east-1} \
	cdk deploy --all --require-approval any-change --context environment=prod

# Docker targets
docker-build:
	docker-compose build

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Utility targets
clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} +
	rm -rf build/ dist/ htmlcov/ .coverage .pytest_cache/
	rm -rf cdk.out/

# CDK specific targets
cdk-synth:
	cdk synth --all

cdk-diff:
	cdk diff --all

cdk-bootstrap:
	cdk bootstrap

# Development server
run-local:
	cd src/api && uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Documentation
docs:
	cd docs && mkdocs build

docs-serve:
	cd docs && mkdocs serve

# Security scanning
security-scan:
	bandit -r src/
	safety check
	pip-audit

# Database migrations (if needed)
db-migrate:
	alembic upgrade head

db-rollback:
	alembic downgrade -1

# Environment setup
setup-env:
	cp .env.example .env
	@echo "Please edit .env file with your configuration"