"""MailFort v2 CLI.

MailFort is the primary threat-analysis platform.  PhishFinder mode is the
lightweight static-scan tier within the same pipeline — both are served by
this CLI.

Commands
--------
  scan        Scan a mailbox for phishing and malicious messages.
  review      Review previously scanned messages from the local database.
  mitigate    Manually apply a mitigation action to a specific message.
  quarantine  Show or release messages in the quarantine queue.
  case        Export a full case bundle for a specific message.
  baseline    Show sender-domain baseline statistics.

Provider flags
--------------
  --provider gmail          Gmail API (OAuth)
  --provider imap           IMAP for enterprise / custom-domain mailboxes

Mode flags
----------
  --mode phishfinder        Static scan + explainable scoring + reports (default)
  --mode mailfort           Full pipeline: static + sandbox + policy + quarantine
"""

import json
import os
import sys
import time
from typing import Optional

import click

from .constants import (
    DEFAULT_DB_PATH,
    DEFAULT_REPORT_DIR,
    PROVIDER_GMAIL,
    PROVIDER_IMAP,
    MODE_PHISHFINDER,
    MODE_MAILFORT,
    MAILFORT_VERSION,
)


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

def _provider_options(f):
    f = click.option("--provider", default=PROVIDER_GMAIL,
                     type=click.Choice([PROVIDER_GMAIL, PROVIDER_IMAP]),
                     show_default=True,
                     help="Mail provider to connect to.")(f)
    f = click.option("--imap-host", default=None,
                     help="IMAP server hostname (required for --provider imap).")(f)
    f = click.option("--imap-port", default=993, show_default=True,
                     help="IMAP port.")(f)
    f = click.option("--username", default=None,
                     help="IMAP username / email address.")(f)
    f = click.option("--password", default=None,
                     help="IMAP password or app-password.")(f)
    f = click.option("--mailbox", default="INBOX", show_default=True,
                     help="IMAP mailbox folder to scan.")(f)
    return f


def _gmail_options(f):
    f = click.option("--credentials", default="credentials.json", show_default=True,
                     help="Path to Gmail OAuth client-secrets JSON.")(f)
    f = click.option("--token", default=None,
                     help="Path to cached OAuth token file.")(f)
    return f


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(MAILFORT_VERSION, prog_name="mailfort")
def cli():
    """MailFort v2 — phishing detection and response platform.

    PhishFinder mode: fast static scan with explainable scoring.
    MailFort mode:    full pipeline including sandbox and policy enforcement.
    """


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@_provider_options
@_gmail_options
@click.option("--mode", default=MODE_PHISHFINDER,
              type=click.Choice([MODE_PHISHFINDER, MODE_MAILFORT]),
              show_default=True,
              help="Operating mode.")
@click.option("--max", "max_messages", default=100, show_default=True,
              help="Maximum number of messages to scan.")
@click.option("--query", default=None,
              help="Gmail search query or IMAP SEARCH criteria.")
@click.option("--labels", default=None,
              help="Comma-separated Gmail label IDs to filter by.")
@click.option("--with-sandbox", is_flag=True, default=False,
              help="Enable sandbox detonation (MailFort mode only).")
@click.option("--detonate-links", is_flag=True, default=False,
              help="Detonate suspicious URLs in the sandbox.")
@click.option("--detonate-attachments", is_flag=True, default=False,
              help="Detonate suspicious attachments in the sandbox.")
@click.option("--quarantine-threshold", default=60, show_default=True,
              help="Score threshold above which messages are quarantined automatically.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Analyse but do not apply any mail provider actions.")
@click.option("--output-dir", default=DEFAULT_REPORT_DIR, show_default=True,
              help="Directory to write reports into.")
@click.option("--db", default=DEFAULT_DB_PATH, show_default=True,
              help="Path to the MailFort SQLite database.")
@click.option("--trusted-domains", default=None,
              help="Comma-separated list of domains considered trusted (for lookalike detection).")
def scan(
    provider, imap_host, imap_port, username, password, mailbox,
    credentials, token,
    mode, max_messages, query, labels, with_sandbox,
    detonate_links, detonate_attachments, quarantine_threshold,
    dry_run, output_dir, db, trusted_domains,
):
    """Scan a mailbox for phishing and malicious messages."""
    from .persistence.db import init_db
    from .analyzers.coordinator import StaticCoordinator
    from .sandbox.orchestrator import SandboxOrchestrator, should_detonate
    from .engine.verdicts import build_verdict
    from .engine.policy import PolicyEngine
    from .engine.case_builder import build_case, format_case_summary
    from .reporting.json_report import write_json_report
    from .reporting.csv_report import write_csv_report
    from .reporting.html_report import write_html_report
    from .reporting.case_export import export_case
    from .persistence.repositories import save_message, save_verdict, was_recently_scanned
    from .persistence.repositories import save_url, save_attachment

    conn = init_db(db)
    click.echo(f"[mailfort] mode={mode} provider={provider} dry_run={dry_run}")

    trusted = [d.strip() for d in (trusted_domains or "").split(",") if d.strip()]
    analyzer = StaticCoordinator(trusted_domains=trusted)
    sandbox = SandboxOrchestrator(
        detonate_links=detonate_links,
        detonate_attachments=detonate_attachments,
    )

    connector = _build_connector(
        provider=provider,
        credentials=credentials,
        token=token,
        imap_host=imap_host,
        imap_port=imap_port,
        username=username,
        password=password,
        mailbox=mailbox,
        mode=mode,
        dry_run=dry_run,
    )

    policy_engine = PolicyEngine(
        connector=connector if mode == MODE_MAILFORT else None,
        dry_run=dry_run,
    )

    os.makedirs(output_dir, exist_ok=True)
    cases = []
    scanned = 0

    label_ids = [l.strip() for l in (labels or "").split(",") if l.strip()] or None

    try:
        messages_iter = _message_iterator(
            provider=provider,
            connector=connector,
            label_ids=label_ids,
            query=query,
            max_messages=max_messages,
        )

        for msg in messages_iter:
            if was_recently_scanned(msg.message_id, conn=conn):
                continue

            click.echo(
                f"  Scanning [{scanned + 1}/{max_messages}] "
                f"{msg.message_id[:12]}... "
                f"from={msg.sender_address[:30]}",
                nl=False,
            )

            static_result = analyzer.run(msg)

            sandbox_results = None
            if mode == MODE_MAILFORT and with_sandbox and should_detonate(
                static_result, detonate_links, detonate_attachments
            ):
                sandbox_results = sandbox.run(msg, static_result)

            verdict = build_verdict(
                message_id=msg.message_id,
                static_result=static_result,
                sandbox_results=sandbox_results,
            )

            policy_result = policy_engine.apply(verdict, sender=msg.sender_address)

            # Persist
            msg_dict = {
                "message_id": msg.message_id,
                "thread_id": msg.thread_id,
                "sender": msg.sender,
                "sender_domain": msg.sender_domain,
                "subject": msg.subject,
                "internal_date": msg.internal_date,
                "labels": msg.labels,
                "body_sha256": msg.body_sha256,
                "html_sha256": msg.html_sha256,
                "provider": msg.provider,
                "first_seen_ts": msg.first_seen_ts,
            }
            save_message(
                msg_dict,
                static_score=verdict.static_score,
                dynamic_score=verdict.dynamic_score,
                final_score=verdict.final_score,
                severity=verdict.severity,
                confidence=verdict.confidence,
                disposition=policy_result.action,
                conn=conn,
            )
            save_verdict(verdict.to_dict(), conn=conn)
            for url_d in static_result.urls:
                url_d["message_id"] = msg.message_id
                save_url(url_d, conn=conn)
            for att_d in static_result.attachments:
                att_d["message_id"] = msg.message_id
                save_attachment(att_d, conn=conn)

            case = build_case(msg, static_result, verdict, policy_result, sandbox_results)
            cases.append(case)

            severity_label = verdict.severity.upper()
            click.echo(
                f" [{severity_label}] score={verdict.final_score} action={policy_result.action}"
            )
            scanned += 1

    finally:
        _close_connector(provider, connector)

    # Reports
    if cases:
        ts = int(time.time())
        json_path = os.path.join(output_dir, f"report_{ts}.json")
        csv_path = os.path.join(output_dir, f"report_{ts}.csv")
        html_path = os.path.join(output_dir, f"report_{ts}.html")
        write_json_report(cases, json_path)
        write_csv_report(cases, csv_path)
        write_html_report(cases, html_path)
        click.echo(f"\n[mailfort] Reports written to {output_dir}")
        click.echo(f"  JSON: {json_path}")
        click.echo(f"  CSV:  {csv_path}")
        click.echo(f"  HTML: {html_path}")
    else:
        click.echo("\n[mailfort] No new messages scanned.")


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--severity", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "benign"]),
              help="Filter by severity level.")
@click.option("--limit", default=50, show_default=True,
              help="Maximum number of messages to display.")
@click.option("--db", default=DEFAULT_DB_PATH, show_default=True,
              help="Path to the MailFort SQLite database.")
def review(severity, limit, db):
    """Review previously scanned messages from the local database."""
    from .persistence.db import init_db
    from .persistence.repositories import list_messages

    init_db(db)
    messages = list_messages(severity=severity, limit=limit)

    if not messages:
        click.echo("No messages found matching the criteria.")
        return

    click.echo(f"{'ID':<16}  {'SENDER':<35}  {'SUBJECT':<40}  {'SCORE':>5}  {'SEVERITY':<10}  ACTION")
    click.echo("-" * 120)
    for m in messages:
        mid = str(m.get("message_id", ""))[:15]
        sender = str(m.get("sender", ""))[:34]
        subject = str(m.get("subject", ""))[:39]
        score = m.get("final_score", 0)
        sev = m.get("severity", "")
        action = m.get("disposition", "")
        click.echo(f"{mid:<16}  {sender:<35}  {subject:<40}  {score:>5}  {sev:<10}  {action}")


# ---------------------------------------------------------------------------
# mitigate
# ---------------------------------------------------------------------------

@cli.command()
@_provider_options
@_gmail_options
@click.option("--message-id", required=True, help="Message ID to act on.")
@click.option("--action", required=True,
              type=click.Choice(["quarantine", "release", "trash", "spam", "warn"]),
              help="Action to apply.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Log the action without executing it.")
@click.option("--db", default=DEFAULT_DB_PATH, show_default=True,
              help="Path to the MailFort SQLite database.")
def mitigate(
    provider, imap_host, imap_port, username, password, mailbox,
    credentials, token, message_id, action, dry_run, db,
):
    """Manually apply a mitigation action to a specific message."""
    from .persistence.db import init_db
    from .persistence.repositories import log_audit

    init_db(db)
    connector = _build_connector(
        provider=provider, credentials=credentials, token=token,
        imap_host=imap_host, imap_port=imap_port,
        username=username, password=password, mailbox=mailbox,
        mode=MODE_MAILFORT, dry_run=dry_run,
    )

    click.echo(f"[mitigate] message_id={message_id} action={action} dry_run={dry_run}")
    if dry_run:
        click.echo("[mitigate] Dry run — no changes applied.")
    else:
        _apply_manual_action(connector, provider, message_id, action)

    log_audit(action=action, message_id=message_id, sender="", confirmed=not dry_run,
              details={"manual": True})
    _close_connector(provider, connector)


# ---------------------------------------------------------------------------
# quarantine
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--list", "list_queue", is_flag=True, default=False,
              help="List all messages currently in quarantine.")
@click.option("--release", "release_id", default=None,
              help="Release a specific message by ID.")
@click.option("--db", default=DEFAULT_DB_PATH, show_default=True,
              help="Path to the MailFort SQLite database.")
def quarantine(list_queue, release_id, db):
    """Show or release messages in the quarantine queue."""
    from .persistence.db import init_db
    from .engine.quarantine import list_quarantined, get_quarantine_summary, mark_released

    init_db(db)

    if release_id:
        mark_released(release_id)
        click.echo(f"[quarantine] Released: {release_id}")
        return

    if list_queue:
        summary = get_quarantine_summary()
        click.echo(f"Quarantine queue: {summary['total']} message(s)")
        for sev, cnt in summary.get("by_severity", {}).items():
            click.echo(f"  {sev}: {cnt}")
        click.echo()
        for m in summary.get("messages", [])[:50]:
            click.echo(
                f"  {m.get('message_id','')[:16]:<18} "
                f"{m.get('sender','')[:35]:<37} "
                f"score={m.get('final_score',0):>3} "
                f"sev={m.get('severity','')}"
            )


# ---------------------------------------------------------------------------
# case
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--message-id", required=True, help="Message ID to export.")
@click.option("--output-dir", default=DEFAULT_REPORT_DIR, show_default=True,
              help="Directory to write the case bundle into.")
@click.option("--db", default=DEFAULT_DB_PATH, show_default=True,
              help="Path to the MailFort SQLite database.")
def case(message_id, output_dir, db):
    """Export a full case bundle for a specific message."""
    from .persistence.db import init_db
    from .persistence.repositories import get_message, get_latest_verdict
    from .reporting.case_export import export_case as _export

    init_db(db)
    msg_row = get_message(message_id)
    if not msg_row:
        click.echo(f"[case] No record found for message_id={message_id}", err=True)
        sys.exit(1)

    verdict_row = get_latest_verdict(message_id) or {}
    case_bundle = {
        "message": msg_row,
        "verdict": verdict_row,
        "policy": {"action": msg_row.get("disposition", "unknown")},
        "static_analysis": {},
        "sandbox_results": [],
    }

    path = _export(case_bundle, output_dir)
    click.echo(f"[case] Exported to: {path}")


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--db", default=DEFAULT_DB_PATH, show_default=True,
              help="Path to the MailFort SQLite database.")
@click.option("--limit", default=20, show_default=True,
              help="Number of top sender domains to display.")
def baseline(db, limit):
    """Show sender-domain baseline statistics from the scan history."""
    from .persistence.db import init_db, get_conn

    init_db(db)
    conn = get_conn(db)
    rows = conn.execute(
        """
        SELECT sender_domain, COUNT(*) as cnt,
               AVG(final_score) as avg_score,
               MAX(severity) as max_severity
        FROM messages
        WHERE sender_domain IS NOT NULL AND sender_domain != ''
        GROUP BY sender_domain
        ORDER BY cnt DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    click.echo(f"{'DOMAIN':<40}  {'COUNT':>6}  {'AVG SCORE':>10}  {'MAX SEV':<10}")
    click.echo("-" * 75)
    for row in rows:
        click.echo(
            f"{str(row[0]):<40}  {row[1]:>6}  {row[2]:>10.1f}  {str(row[3]):<10}"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_connector(
    provider: str,
    credentials: str,
    token: Optional[str],
    imap_host: Optional[str],
    imap_port: int,
    username: Optional[str],
    password: Optional[str],
    mailbox: str,
    mode: str,
    dry_run: bool,
):
    if provider == PROVIDER_GMAIL:
        from .auth import get_gmail_credentials
        from .connectors.gmail import GmailConnector
        readonly = (mode == MODE_PHISHFINDER) or dry_run
        token_path = token or os.path.join(
            os.path.dirname(credentials) if credentials else ".",
            ".mailfort_tokens.json",
        )
        creds = get_gmail_credentials(
            credentials_path=credentials,
            token_path=token_path,
            readonly=readonly,
        )
        return GmailConnector(creds)

    elif provider == PROVIDER_IMAP:
        from .connectors.imap import ImapConnector
        if not imap_host:
            raise click.UsageError("--imap-host is required when --provider=imap")
        if not username:
            raise click.UsageError("--username is required when --provider=imap")
        if not password:
            password = click.prompt("IMAP password", hide_input=True)
        conn = ImapConnector(
            host=imap_host,
            port=imap_port,
            username=username,
            password=password,
            use_ssl=True,
            mailbox=mailbox,
        )
        conn.connect()
        return conn

    raise click.UsageError(f"Unknown provider: {provider}")


def _message_iterator(provider, connector, label_ids, query, max_messages):
    """Yield NormalizedMessage objects from the connected provider."""
    from .connectors.message_normalizer import normalize_gmail_message, normalize_imap_message

    if provider == PROVIDER_GMAIL:
        for stub in connector.list_messages_all(
            label_ids=label_ids,
            query=query,
            max_messages=max_messages,
        ):
            raw = connector.get_message(stub["id"])
            # Pass the attachment fetcher so large attachments referenced
            # only by attachmentId are retrieved and fully analysed.
            yield normalize_gmail_message(
                raw,
                attachment_fetcher=connector.fetch_attachment_bytes,
            )

    elif provider == PROVIDER_IMAP:
        search = query or "ALL"
        for stub in connector.list_messages(
            search_criteria=search,
            max_messages=max_messages,
        ):
            uid = stub["uid"]
            parsed = connector.fetch_message(uid)
            if parsed:
                yield normalize_imap_message(parsed, uid=uid)


def _close_connector(provider, connector):
    if provider == PROVIDER_IMAP and connector:
        try:
            connector.disconnect()
        except Exception:
            pass


def _apply_manual_action(connector, provider, message_id, action):
    from .connectors.gmail import GmailConnector
    from .connectors.imap import ImapConnector
    from .constants import LABEL_QUARANTINE

    if isinstance(connector, GmailConnector):
        if action == "quarantine":
            lid = connector.create_label_if_missing(LABEL_QUARANTINE)
            connector.quarantine_message(message_id, lid)
        elif action == "release":
            qid = connector.label_name_to_id(LABEL_QUARANTINE)
            if qid:
                connector.release_message(message_id, qid)
        elif action == "trash":
            connector.trash_message(message_id)
        elif action == "spam":
            connector.report_spam(message_id)
    elif isinstance(connector, ImapConnector):
        if action == "quarantine":
            connector.quarantine_message(message_id)
        elif action == "release":
            connector.release_message(message_id)


def main():
    cli()


if __name__ == "__main__":
    main()
