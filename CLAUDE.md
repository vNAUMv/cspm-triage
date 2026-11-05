# CSPM Triage Tool

## Project purpose
A Python CLI tool that parses Prowler scan results (JSON, OCSF format), filters and prioritizes findings, compares two scans (new / resolved / persisting), generates a report, and optionally creates Jira tickets for critical and high findings.

## Tech stack
- Python 3.11+
- pytest for tests
- ruff for linting and formatting
- bandit for security static analysis
- Standard library first; add a dependency only when it clearly saves effort, and explain why

## Project structure
```
cspm_triage/
  parser.py      # load and normalize Prowler OCSF findings
  models.py      # data models for findings
  triage.py      # filtering, prioritization, accepted-risk exceptions
  diff.py        # compare two scans
  report.py      # Markdown/HTML report generation
  jira_client.py # Jira ticket creation (optional)
  cli.py         # command-line entry point
tests/
  fixtures/      # sanitized sample Prowler output (no real account IDs or ARNs)
config/
  exceptions.example.toml # sample accepted risks (fake data); copy to exceptions.toml, which is gitignored
scripts/
  sanitize_fixture.py # build a sanitized test fixture from a real scan (input stays outside the repo)
```

## Rules
- Never hardcode secrets, tokens, account IDs, or URLs of real systems. Read credentials only from environment variables.
- Never commit real scan output. Test fixtures must be sanitized.
- Write or update tests for every function you add or change. Run `pytest` before saying a task is done.
- Keep functions small and typed (type hints everywhere).
- Do not invent fields of the Prowler OCSF format or Jira API parameters. If unsure, say so and ask me to check the documentation or a real sample.
- Work in small steps: propose a plan first for any task that touches more than one file, and wait for my approval.
- Do not run commands that modify anything outside this repository.
- Real scans live outside the repo. Read them only when I ask. Never print resource IDs, ARNs, account IDs or usernames from real data; print counts and check names only.

## Commands
- Tests: `pytest -q`
- Lint: `ruff check . && ruff format --check .`
- Security scan: `bandit -r cspm_triage scripts`
