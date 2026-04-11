# MailFort v2 Quickstart

Two minutes to your first scan.

---

## 1. Install

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 2. Choose your provider

### Gmail

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials.
2. Create an **OAuth 2.0 Client ID** (Desktop application).
3. Download the JSON and save it as `credentials.json` in the project root.

```bash
# PhishFinder mode — read-only, no quarantine
python -m mailfort.cli scan \
  --provider gmail \
  --mode phishfinder \
  --max 50

# MailFort mode — policy engine enabled, dry-run first
python -m mailfort.cli scan \
  --provider gmail \
  --mode mailfort \
  --dry-run \
  --max 50
```

A browser window opens on first run for OAuth. Tokens are cached in
`~/.mailfort/tokens.json` — subsequent runs are non-interactive.

---

### Enterprise / custom domain (IMAP)

Works with Office 365, Google Workspace, Exchange, Postfix, Zimbra — any server
that exposes IMAP4/SSL on port 993.

```bash
# Basic scan — static analysis, explainable scores
python -m mailfort.cli scan \
  --provider imap \
  --imap-host mail.company.com \
  --username security@company.com \
  --password 'your-app-password' \
  --mode phishfinder \
  --max 100

# MailFort mode — trust your own domain, dry-run first
python -m mailfort.cli scan \
  --provider imap \
  --imap-host mail.company.com \
  --username security@company.com \
  --password 'your-app-password' \
  --mode mailfort \
  --trusted-domains company.com,subsidiary.com \
  --dry-run \
  --max 200

# Drop --dry-run when you are ready for live quarantine actions
```

**Office 365 note:** Use an app password or configure Modern Auth with a
service principal. Standard IMAP must be enabled for the mailbox.

---

## 3. Review results

Reports are written to `~/.mailfort/reports/`:

```
report_<ts>.json    Full case bundles (machine-readable)
report_<ts>.csv     One row per message (spreadsheet-friendly)
report_<ts>.html    Self-contained visual report with severity badges
```

Review from the CLI:

```bash
# All scanned messages
python -m mailfort.cli review

# Only high and critical
python -m mailfort.cli review --severity high
python -m mailfort.cli review --severity critical
```

---

## 4. Triage and mitigate

```bash
# Export a full case bundle for one message
python -m mailfort.cli case --message-id <MESSAGE_ID>

# Manually quarantine a message
python -m mailfort.cli mitigate \
  --provider gmail \
  --message-id <MESSAGE_ID> \
  --action quarantine

# Manually release from quarantine
python -m mailfort.cli mitigate \
  --provider gmail \
  --message-id <MESSAGE_ID> \
  --action release

# List current quarantine queue
python -m mailfort.cli quarantine --list

# Release from queue by ID
python -m mailfort.cli quarantine --release <MESSAGE_ID>
```

---

## 5. Understand a score

Every finding in the report includes:

| Field | Meaning |
|---|---|
| `rule_id` | The specific check that fired (e.g. `spf_fail`, `anchor_text_mismatch`) |
| `severity` | How serious that individual check is (low / medium / high / critical) |
| `confidence` | How certain the analyzer is (0.0–1.0) |
| `reason` | Plain-English explanation of what was found |
| `evidence` | The raw values that triggered the rule |

The `final_score` is a weighted, confidence-scaled sum of all findings, capped at 100.

---

## 6. Adjust policy thresholds

Edit `src/mailfort/config.py` to tune scoring weights and default actions:

```python
# Raise the weight of DMARC failures
SCORING_WEIGHTS["dmarc_fail"] = 30

# Change default action for medium-severity messages
DEFAULT_POLICY["medium"] = "quarantine"   # was "warn"

# Lower the sandbox detonation threshold
DETONATE_THRESHOLD = 40   # was 50
```

---

## Flags reference

```
scan
  --provider        gmail | imap
  --mode            phishfinder | mailfort
  --max             Message limit (default 100)
  --query           Gmail search / IMAP SEARCH string
  --labels          Gmail label IDs (comma-separated)
  --trusted-domains Domains to treat as legitimate (comma-separated)
  --with-sandbox    Enable sandbox detonation (MailFort mode)
  --detonate-links  Detonate suspicious URLs
  --detonate-attachments  Detonate suspicious attachments
  --quarantine-threshold  Auto-quarantine above this score (default 60)
  --dry-run         Analyse without applying any mail actions
  --output-dir      Report output directory
  --db              SQLite database path

  # Gmail-specific
  --credentials     Path to OAuth client-secrets JSON (default: credentials.json)
  --token           Path to cached token file

  # IMAP-specific
  --imap-host       IMAP server hostname
  --imap-port       IMAP port (default 993)
  --username        Email address / IMAP username
  --password        Password or app-password
  --mailbox         IMAP folder to scan (default INBOX)
```
