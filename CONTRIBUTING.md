# Contributing to Agent-Airlock

First off, thank you for considering contributing to Agent-Airlock! It's people like you that make Agent-Airlock such a great tool for securing AI agents.

## Code of Conduct

This project and everyone participating in it is governed by our commitment to providing a welcoming and inclusive environment. By participating, you are expected to uphold this standard.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find that the issue has already been reported. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (code snippets, configuration)
- **Describe the behavior you observed and expected**
- **Include your environment details** (Python version, OS, package versions)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the proposed feature**
- **Explain why this enhancement would be useful**
- **List any alternatives you've considered**

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code follows the project's style guidelines
6. Issue that pull request!

## Development Setup

### Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/agent-airlock.git
cd agent-airlock

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev,all]"

# Verify installation
pytest tests/ -v
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=agent_airlock --cov-report=html

# Run specific test file
pytest tests/test_core.py -v

# Run tests matching a pattern
pytest tests/ -k "test_ghost" -v
```

### Code Quality

```bash
# Type checking (strict mode)
mypy src/

# Linting
ruff check src/ tests/

# Auto-format
ruff format src/ tests/

# Security scan
bandit -r src/agent_airlock/
```

## Style Guidelines

### Python Style

- Follow [PEP 8](https://pep8.org/) with a line length of 100 characters
- Use type hints for all function signatures
- Use `ruff` for formatting and linting

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Example:
```
feat: add rate limiting to policy engine

- Implement token bucket algorithm for rate limits
- Add time-based restrictions
- Include comprehensive tests

Fixes #123
```

### Documentation

- Use docstrings for all public modules, functions, classes, and methods
- Follow [Google style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for docstrings
- Update README.md if you change functionality
- Add examples for new features

## Project Structure

```
agent-airlock/
├── src/agent_airlock/     # Main package
│   ├── core.py            # @Airlock decorator
│   ├── validator.py       # Ghost arg detection + Pydantic validation
│   ├── policy.py          # RBAC and rate limiting
│   ├── sanitizer.py       # PII/secret masking
│   ├── sandbox.py         # E2B integration
│   └── mcp.py             # FastMCP integration
├── tests/                 # Test suite
├── examples/              # Usage examples
└── docs/                  # Documentation
```

## Testing Guidelines

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_*.py`
- Name test functions `test_*`
- Use descriptive test names that explain the scenario
- Include both positive and negative test cases
- Mock external services (E2B, etc.)

### Test Structure

```python
def test_ghost_arguments_stripped_in_permissive_mode():
    """Ghost arguments should be stripped, not rejected, in permissive mode."""
    # Arrange
    @Airlock(config=AirlockConfig(strict_mode=False))
    def my_func(x: int) -> int:
        return x * 2

    # Act
    result = my_func(x=5, ghost_param="ignored")

    # Assert
    assert result == 10
```

## Security

If you discover a security vulnerability, please do NOT open a public issue. Instead, email security concerns privately. See [SECURITY.md](docs/SECURITY.md) for our security policy.

## Questions?

Feel free to open an issue with the "question" label if you have questions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
