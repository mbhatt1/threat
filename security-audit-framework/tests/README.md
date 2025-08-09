# Security Audit Framework - Test Suite

## Overview

This test suite provides comprehensive testing for the Security Audit Framework, including unit tests and integration tests for all components.

## Test Structure

```
tests/
├── unit/                      # Unit tests for individual components
│   ├── test_strands.py       # Tests for Strands protocol
│   ├── test_hashiru.py       # Tests for HASHIRU framework
│   ├── test_lambda_ceo_agent.py     # Tests for CEO Agent Lambda
│   ├── test_lambda_aggregator.py    # Tests for Aggregator Lambda
│   ├── test_lambda_report_generator.py # Tests for Report Generator
│   └── test_agent_sast.py    # Tests for SAST agent (example)
├── integration/              # Integration tests
│   └── test_end_to_end.py   # End-to-end workflow tests
├── requirements.txt          # Test dependencies
└── README.md                # This file
```

## Running Tests

### Prerequisites

```bash
# Install test dependencies
pip install -r tests/requirements.txt
```

### Running Tests

```bash
# Run all unit tests
./scripts/run-tests.sh

# Run integration tests (requires AWS mock setup)
./scripts/run-tests.sh --integration

# Run all tests with coverage report
./scripts/run-tests.sh --all

# Run specific test file
./scripts/run-tests.sh --file tests/unit/test_strands.py

# Run tests directly with pytest
pytest tests/unit -v
pytest tests/integration -v
pytest tests/ -v --cov=src --cov-report=html
```

## Test Categories

### Unit Tests

Unit tests cover individual components in isolation:

1. **Strands Protocol Tests** (`test_strands.py`)
   - Message creation and validation
   - Serialization/deserialization
   - Security finding models
   - Task context validation

2. **HASHIRU Framework Tests** (`test_hashiru.py`)
   - AWS pricing client
   - Spot pricing optimization
   - Repository analysis
   - Execution planning

3. **Lambda Function Tests**
   - CEO Agent: Scan initiation, repository analysis
   - Aggregator: Finding aggregation, deduplication
   - Report Generator: HTML/JSON report generation

4. **Security Agent Tests**
   - SAST Agent: Semgrep integration, finding parsing
   - Similar patterns for other agents

### Integration Tests

Integration tests cover end-to-end workflows:

1. **Complete Scan Workflow**
   - API Gateway initiation
   - Step Functions orchestration
   - Multi-agent execution
   - Report generation

2. **Error Handling**
   - Agent failure recovery
   - Partial scan completion
   - Timeout handling

3. **Performance Testing**
   - Large repository handling
   - Concurrent scan execution
   - Resource optimization

## Test Coverage

The test suite aims for >80% code coverage across all components:

- Core frameworks (Strands, HASHIRU): >90%
- Lambda functions: >85%
- Security agents: >80%
- CDK infrastructure: Validated through deployment

## Mocking Strategy

Tests use various mocking strategies:

- **AWS Services**: `moto` library for S3, DynamoDB, Lambda
- **External Tools**: Mock subprocess calls for Semgrep, OWASP, etc.
- **Network Calls**: `requests-mock` for API calls

## Writing New Tests

When adding new features:

1. Write unit tests first (TDD approach)
2. Mock external dependencies
3. Test both success and failure cases
4. Add integration tests for workflows
5. Update coverage requirements if needed

## CI/CD Integration

Tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    pip install -r tests/requirements.txt
    pytest tests/ -v --cov=src --cov-fail-under=80
```

## Troubleshooting

Common issues:

1. **Import Errors**: Ensure `PYTHONPATH` includes the `src` directory
2. **AWS Mock Issues**: Check `moto` version compatibility
3. **Test Isolation**: Ensure tests don't share state
4. **Slow Tests**: Use pytest markers to skip slow tests in development

## Future Improvements

- Add performance benchmarks
- Implement load testing for concurrent scans
- Add mutation testing
- Create test data generators
- Add visual regression tests for reports