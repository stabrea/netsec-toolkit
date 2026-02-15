# Contributing to netsec-toolkit

Thank you for your interest in contributing. This guide covers setting up the development environment, running tests, and submitting changes.

## Ethical Use Reminder

This toolkit is for **authorized security testing and educational purposes only**. All contributions must follow responsible disclosure practices. Never include code that targets specific real-world systems without authorization.

## Development Setup

### Prerequisites

- Python 3.10 or later
- pip package manager
- Git

### Clone and Install

```bash
git clone https://github.com/stabrea/netsec-toolkit.git
cd netsec-toolkit

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Install the package in editable mode
pip install -e .
```

### Verify Setup

```bash
python main.py --version
```

## Running Tests

Tests live in the `tests/` directory and use `pytest`.

```bash
# Install test dependencies
pip install pytest

# Run the full test suite
pytest tests/ -v

# Run a specific test file
pytest tests/test_port_scanner.py -v

# Run with verbose output and full tracebacks
pytest tests/ -v --tb=long
```

**Important**: Tests should use `localhost` (127.0.0.1) or mock targets only. Never write tests that scan external hosts.

All tests must pass before submitting a pull request.

## Code Style

- **Type hints**: All functions must have complete type annotations. Use `from __future__ import annotations` for modern syntax.
- **Docstrings**: Every public class and method needs a docstring explaining what it does, its arguments, and return values.
- **Dataclasses**: Use `@dataclass` for structured results. Include a `to_dict()` method for JSON serialization.
- **Imports**: Group imports in standard order -- stdlib, third-party, local -- separated by blank lines.
- **Minimal dependencies**: Core scanning modules must use only Python standard library (`socket`, `ssl`, `ipaddress`, `struct`, `http.client`). Only `rich` is allowed as an external dependency for terminal formatting.
- **Thread safety**: Concurrent scanning code must not share mutable state between threads without synchronization.
- **No `Any` types**: Avoid `typing.Any`. Use specific types or generics.

## Submitting Changes

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** in small, focused commits. Each commit should do one thing.

3. **Run the test suite** and confirm all tests pass:
   ```bash
   pytest tests/ -v
   ```

4. **Test manually** against `localhost` or an authorized target to verify behavior:
   ```bash
   python main.py scan 127.0.0.1 -p 22,80,443
   ```

5. **Push** your branch and open a pull request against `main`.

6. In your PR description, explain:
   - What the change does
   - Why it is needed
   - How you tested it (include which targets you tested against)

## Project Structure

```
netsec_toolkit/
    __init__.py              # Package init, public API
    port_scanner.py          # TCP connect scanner + banner grabbing
    network_mapper.py        # Subnet discovery + OS fingerprinting
    vuln_checker.py          # Security misconfiguration checks
    report_generator.py      # JSON + HTML report generation
    cli.py                   # argparse CLI with subcommands
tests/
    test_port_scanner.py
    test_network_mapper.py
    test_vuln_checker.py
    test_report_generator.py
```

## Areas for Contribution

- UDP scanning support
- SNMP enumeration module
- Nmap NSE script-style plugin system
- Improved OS fingerprinting heuristics
- Rate limiting and stealth scanning options
- Additional vulnerability check signatures
- Integration tests with containerized target services

## Questions

Open an issue if you have questions or want to discuss a feature before starting work.
