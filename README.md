# MailFort — Gmail Threat Scanner and Mitigation Engine

MailFort is a modular Gmail analysis tool focused on read-only-first scanning, explainable threat scoring, and user-approved mitigation.

Quickstart

1. Create a Google OAuth client (OAuth Desktop) and save `client_secrets.json` at the repository root.
2. Create a virtualenv and install requirements:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


3. Run a scan:

```bash
python -m src.mailfort.cli scan --max 100
```

This will open a browser for OAuth and produce `reports/report.json`, `report.csv`, and `report.html`.

Commands

- `scan` — scan mailbox (read-only by default). Supports `--max` to limit messages.
- `review` — print a summary of the latest report.
- `mitigate` — interactive mitigation workflow which will request elevated scopes when needed. Use `--dry-run` to simulate actions.

State & logs

- Persistent scan state and audit logs are stored in `~/.mailfort_state.db`.
- Tokens are stored in `~/.mailfort_tokens.json` with restrictive permissions.

Security notes

- Default scopes are read-only; mitigation requires explicit escalation.
- Tokens are stored at `~/.mailfort_tokens.json` with restrictive permissions.
- MailFort does not automatically delete or transmit email content externally.

Architecture

- `src/mailfort/auth.py` — OAuth helpers
- `src/mailfort/gmail_connector.py` — Gmail API connector
- `src/mailfort/analysis.py` — heuristics and steganography indicators
- `src/mailfort/scoring.py` — risk scoring
- `src/mailfort/reporting.py` — JSON/CSV/HTML output
- `src/mailfort/mitigation.py` — user-approved mitigation engine (dry-run support)
- `src/mailfort/cli.py` — CLI entrypoint

Next steps

- Add persistent scan state (DB) to enable incremental/resume.
- Harden header analysis (SPF/DKIM/DMARC verification via external libraries).
- Add interactive mitigation UI and batch operations.
# MailFort