# Contributing to AgentShield

Thanks for your interest in making AI agents safer! Here's how to contribute.

## Quick Start

```bash
git clone https://github.com/augustyatuhsexpeimentation/agentshield.git
cd agentshield
pip install -e ".[dev]"
pytest tests/unit/ -v
```

## Ways to Contribute

- **Report bugs** — open an issue with reproduction steps
- **Add detection patterns** — new prompt injection / command injection patterns
- **Write tests** — especially for edge cases and attack scenarios
- **Add integrations** — new agent frameworks (AutoGPT, Semantic Kernel, etc.)
- **Improve docs** — tutorials, examples, translations
- **Build custom detectors** — share detectors for specific use cases

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest tests/unit/ -v`
5. Run linting: `ruff check agentshield/ tests/`
6. Commit with a descriptive message
7. Push and open a Pull Request

## Code Guidelines

- Python 3.11+ with type hints
- Format with `ruff format`
- All detectors must extend `BaseDetector` from `agentshield.detectors.base`
- Every new feature needs tests
- Keep dependencies minimal — stdlib where possible

## Adding a New Detector

```python
# agentshield/detectors/my_detector.py
from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel

class MyDetector(BaseDetector):
    name = "my_detector"

    def scan_input(self, tool_name, arguments, context):
        # Your detection logic here
        return []
```

Then register it in `agentshield/detectors/base.py` → `DetectorPipeline.from_config()`.

## Reporting Security Vulnerabilities

See [SECURITY.md](SECURITY.md). Do **not** open a public issue for security vulnerabilities.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be kind, be constructive.