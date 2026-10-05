# Contributing to OPTISEC Recon Pro

Thanks for your interest in improving OPTISEC. This document covers local
setup, running the tests, commit conventions, and the contribution terms.

> **Security vulnerabilities:** do **not** open a public issue or pull
> request. Report them privately as described in [SECURITY.md](SECURITY.md).

## Local Development Setup

Copied from the [Installation](README.md#installation) section of the README.

Prerequisites:

- Python 3.12+
- Nmap 7.x (`apt install nmap` / `brew install nmap`)
- Git

```bash
# 1. Clone the repository
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — set JWT_SECRET and optionally GROQ_API_KEY

# 5. Launch the dashboard
python main.py web --port 8000
# — or use the bundled startup script, which also handles the venv/deps for you —
./start.sh web

# Dashboard: http://localhost:8000
# API Docs:  http://localhost:8000/docs
# ReDoc:     http://localhost:8000/redoc
# Demo:      http://localhost:8000/demo  (one-click demo account)
```

For hot-reload during development, the README's Contributing section uses
`python main.py web --reload` instead of step 5. See the README for
Docker Compose and deployment.

## Running the Tests

`pytest` is **not** listed in `requirements.txt`, so install it into your venv
first.

The configuration is fail-closed: outside an explicit dev/test environment the
app refuses to start without `OPTISEC_LICENSE_SECRET`, so the suite fails at
import time unless you provide a throwaway value and opt into test mode with
`GROQ_ENV=test`. Use a placeholder like the one below, never a real secret:

```bash
pip install pytest
export GROQ_ENV=test
export OPTISEC_LICENSE_SECRET=dev-only-not-a-secret
pytest tests/ -q
```

Run a single file while iterating, e.g. `pytest tests/test_unified_osint.py -v`.

## Testing Rules

- **Every change needs tests.** Bug fixes include a regression test that
  fails before the fix and passes after it; new features include tests for
  their behavior, including the failure and authorization paths.
- **Zero regressions.** The full suite must pass before a pull request is
  merged. Do not delete, skip, or weaken existing tests to make a change pass.
- Tests must not call real external services (scanners, third-party APIs,
  payment providers); mock them.

## Commit Messages

The project uses short, typed commit subjects in the form:

```
type(scope): summary
```

Types used in the history:

| Type | Use for |
|------|---------|
| `feat` | New functionality |
| `fix` | Bug fixes (including security fixes scoped to one module) |
| `harden` | Tightening an existing control without changing its feature set |
| `security` | Cross-cutting security changes |
| `perf` | Performance improvements |
| `test` | Adding or improving tests only |
| `docs` | Documentation only |
| `refactor` | Code changes with no behavior change |
| `chore` | Dependencies, tooling, housekeeping |
| `ui` | Template/UI-only changes |

The scope is the affected module, e.g. `fix(threat-feed): ...`,
`harden(license): ...`, `feat(osint): ...`. Keep one logical change per
commit.

## Pull Requests

1. Fork the repository and branch from the latest `master`.
2. Keep each PR focused on one feature or fix.
3. Never commit credentials, API keys, or secrets.
4. Update `.env.example` when you add environment variables, and
   `requirements.txt` when you add packages.
5. Give new routes proper FastAPI `tags`, `summary`, and `responses` metadata.
6. Make sure the full test suite passes.

## Contributor License Agreement

OPTISEC Recon Pro is distributed under a dual-licensing model: the
[GNU AGPL-3.0](LICENSE) for the public, and separate commercial licenses
for organizations that cannot comply with the AGPL.

By submitting a contribution (a pull request, patch, or any other code or
documentation) to this project, you agree that:

1. Your contribution is licensed to the public under the **AGPL-3.0**, the
   same license as the project.
2. You grant **OPTISEC** a perpetual, worldwide, non-exclusive,
   royalty-free, irrevocable license to use, modify, and **relicense your
   contribution under other terms, including commercial licenses**.
3. You keep the copyright in your contribution; this grant is non-exclusive.
4. You have the right to make the contribution (it is your original work,
   or you are otherwise authorized to submit it under these terms).

If you do not agree to these terms, please do not submit a contribution.

## Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md). Please report security issues privately by
email and do **not** open a public GitHub issue for them.
