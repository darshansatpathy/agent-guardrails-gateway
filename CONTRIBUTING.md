# Contributing

Thanks for taking the time to improve this project.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,llm]"
make check        # lint, format check, strict types, tests with coverage
aggw eval         # attack-scenario evaluation
```

## What a change needs

- **Tests.** New behaviour comes with tests; bug fixes come with a test that failed
  before the fix. Coverage must stay at or above 85%.
- **Security-relevant changes come with a scenario.** If a change affects what the
  gateway allows or denies, add or update a scenario in `evals/scenarios.yaml`.
  An attack scenario for what must stay blocked, a benign one for what must stay allowed.
- **Design decisions are recorded.** A change to how a control works gets an ADR in
  `docs/adr/`, numbered after the last one.
- **Changelog.** Add a line under "Unreleased" in `CHANGELOG.md`.

## Pull requests

Keep them focused, describe the behaviour change and how you tested it, and make sure
CI is green. Security issues go through private reporting, see [SECURITY.md](SECURITY.md).
