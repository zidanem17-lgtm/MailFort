# MailFort

**Read-only-first email triage and mitigation engine with explainable scoring and controlled remediation.**

MailFort inspects your mailbox before you ever open a suspicious message. Every finding is explained, every score is traceable, and every remediation action requires explicit approval — unless you configure the policy engine to act automatically.

PhishFinder is the lightweight static-scan mode within the same pipeline, delivering fast explainable results without sandbox detonation. MailFort mode adds sandbox detonation, a verdict engine, and policy-driven quarantine on top.

---

## What it does

```
Inbox
  │
  ▼
Message normalization ── headers, body (text + HTML), attachments, URLs
  │
  ▼
Static analyzers
  ├── Headers     SPF/DKIM/DMARC (regex-parsed), Reply-To mismatch,
  │               display-name spoofing, Return-Path anomaly, urgent subject
  ├── Sender      brand impersonation (display name + subject line),
  │               lookalike/homoglyph domain detection, freemail impersonation
  ├── Body        phishing language, login-link detection, inline credential forms
  ├── URLs        punycode, raw IPs, shorteners, suspicious TLDs,
  │               anchor-text mismatch, excessive query parameters
  └── Attachments MIME vs extension mismatch, entropy, macro-capable Office docs,
                  PDF JavaScript/OpenAction/Launch, nested/encrypted archives
  │
  ▼
Detonation gate (MailFort mode only)
  │   fires when score ≥ 50, critical rule hit, login link, or executable attachment
  ▼
Sandbox detonation — URL browser detonation · file runner
  │   (stubs wired and documented; swap in Playwright or any VM agent)
  │
  ▼
Verdict engine
  │   static score + dynamic score → severity (benign/low/medium/high/critical)
  │   hard-fail override for credential harvest, C2 callback, persistence
  │
  ▼
Policy engine
  │   allow · warn · quarantine · block · escalate
  │   Gmail: label-based quarantine (MAILFORT/QUARANTINE, removes from INBOX)
  │   IMAP:  folder-based quarantine (MAILFORT/QUARANTINE folder move)
  │
  ▼
Case bundle + audit trail + JSON/CSV/HTML reports
```

---

## Operating modes

| | PhishFinder | MailFort |
|---|---|---|
| Static analysis | ✓ | ✓ |
| Explainable scoring | ✓ | ✓ |
| JSON/CSV/HTML reports | ✓ | ✓ |
| Sandbox detonation | — | ✓ |
| Policy engine | — | ✓ |
| Auto-quarantine | — | ✓ |
| Case history | — | ✓ |

---

## Provider support

| Provider | Connection | Notes |
|---|---|---|
| Gmail | OAuth 2.0 (Google API) | Personal and Google Workspace accounts |
| Custom domain (IMAP) | IMAP4/SSL | Office 365, Exchange, Postfix, Zimbra, any IMAP server |
| Microsoft 365 | Microsoft Graph (planned) | |

Enterprise deployments connect via `--provider imap` — no Google account required.

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Gmail (PhishFinder mode — read-only)**
```bash
# Place your OAuth client-secrets JSON at credentials.json
python -m mailfort.cli scan --provider gmail --mode phishfinder --max 50
```

**Custom domain / enterprise IMAP (MailFort mode)**
```bash
python -m mailfort.cli scan \
  --provider imap \
  --imap-host mail.company.com \
  --username security@company.com \
  --password 'app-password' \
  --mode mailfort \
  --trusted-domains company.com,subsidiary.com \
  --dry-run \
  --max 100
```

Remove `--dry-run` to have the policy engine execute quarantine actions.

---

## Commands

```
scan        Scan a mailbox — Gmail or IMAP
review      Review scanned messages from the local database
mitigate    Apply a manual action to a specific message
quarantine  List or release the quarantine queue
case        Export a full case bundle for one message
baseline    Show sender-domain statistics from scan history
```

Run `python -m mailfort.cli <command> --help` for all flags.

---

## Architecture

```
src/mailfort/
├── cli.py                     Entry point — Click commands
├── auth.py                    Gmail OAuth helpers
├── config.py                  Scoring weights and policy thresholds
├── constants.py               Severity levels, provider types, label names
│
├── connectors/
│   ├── gmail.py               Gmail API connector (pagination, quarantine, history)
│   ├── imap.py                IMAP connector for enterprise custom domains
│   └── message_normalizer.py  Provider-agnostic NormalizedMessage builder
│
├── models/
│   ├── message.py             NormalizedMessage dataclass
│   ├── findings.py            Finding / StaticAnalysisResult
│   ├── verdict.py             Verdict / SandboxEvidence
│   ├── artifact.py            URLArtifact / AttachmentArtifact
│   └── policy.py              PolicyResult
│
├── analyzers/
│   ├── coordinator.py         Orchestrates all analyzers, aggregates score
│   ├── headers.py             SPF/DKIM/DMARC (regex), envelope checks, subject
│   ├── sender.py              Brand impersonation, lookalike, freemail checks
│   ├── body.py                Phishing language, login links, inline forms
│   ├── urls.py                Punycode, shorteners, IPs, TLDs, anchor mismatch
│   ├── attachments.py         MIME detection, entropy, extension mismatch
│   ├── office_docs.py         OLE macros, external templates, auto-open
│   ├── pdfs.py                JS, OpenAction, Launch, embedded files
│   └── archives.py            Recursive inspection, encrypted archives
│
├── engine/
│   ├── scoring.py             Static + dynamic score computation
│   ├── verdicts.py            Verdict builder with hard-fail override
│   ├── policy.py              PolicyEngine — decides and executes actions
│   ├── quarantine.py          Quarantine queue management
│   └── case_builder.py        Full case bundle assembly
│
├── sandbox/
│   └── orchestrator.py        Detonation gate + URL/file detonation stubs
│
├── persistence/
│   ├── db.py                  SQLite v2 schema (WAL, 8 tables, indexes)
│   ├── migrations.py          v1 → v2 migration path
│   └── repositories.py        Thread-safe CRUD for all entity types
│
└── reporting/
    ├── json_report.py
    ├── csv_report.py
    ├── html_report.py          Self-contained with severity badges
    └── case_export.py          Per-message case bundle JSON
```

---

## Scoring

Every finding contributes a weighted, confidence-scaled score.

| Severity | Score range | Default action |
|---|---|---|
| Benign | 0–19 | Allow |
| Low | 20–39 | Allow |
| Medium | 40–59 | Warn |
| High | 60–79 | Quarantine |
| Critical | 80–100 | Quarantine |

Hard-fail conditions (detected credential harvest, executable C2 callback, persistence in sandbox) override any score and pin the verdict to critical/quarantine.

---

## Database

State is stored in `~/.mailfort/mailfort_v2.db` (SQLite, WAL mode).

Tables: `messages`, `urls`, `attachments`, `sandbox_runs`, `verdicts`, `audit`, `allowlists`, `blocklists`.

---

## Security notes

- Read-only OAuth scopes are used by default (PhishFinder mode). Modify scopes are only requested when MailFort mode needs to quarantine or label messages.
- Tokens are stored in `~/.mailfort/tokens.json`. The file is created with user-only permissions.
- MailFort does not transmit email content to external services. All analysis is local.
- Every mitigation action is logged to the `audit` table with timestamp and confirmation flag.

---

## Next steps

- Sprint 2: sender trust baselines, domain age/reputation lookups, deeper PDF/Office analysis
- Sprint 3: Playwright browser detonation, VM-agent file runner
- Sprint 4: Microsoft Graph connector, web review UI, alert webhooks
