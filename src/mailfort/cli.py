import argparse
import os
import json
import base64
from .auth import load_credentials, run_local_oauth, request_elevated_scopes
from .gmail_connector import GmailConnector
from .analysis import EmailAnalyzer
from .scoring import compute_score
from .reporting import to_json, to_csv, to_html
from .mitigation import MitigationEngine
from .state import is_scanned, mark_scanned, init_db

DEFAULT_REPORT_DIR = "reports"


def scan_mailbox(creds, output_dir=DEFAULT_REPORT_DIR, max_messages=200):
    os.makedirs(output_dir, exist_ok=True)
    gc = GmailConnector(creds)
    analyzer = EmailAnalyzer()
    report = []
    count = 0
    for m in gc.list_messages_all():
        mid = m.get("id")
        if is_scanned(mid):
            continue
        msg = gc.get_message(mid)
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        body = ''
        parts = msg.get("payload", {}).get("parts") or []
        for p in parts:
            if p.get("mimeType") == "text/plain" and p.get("body", {}).get("data"):
                body = (body or '') + p.get("body").get("data")
        try:
            body = base64.urlsafe_b64decode(body + "=").decode('utf-8', errors='ignore') if body else ''
        except Exception:
            body = ''
        findings = {}
        findings['headers'] = analyzer.analyze_headers(headers)
        findings['body'] = analyzer.analyze_body(body)
        findings['attachments'] = analyzer.analyze_attachments(parts)
        score = compute_score(findings)
        report_item = {
            'message_id': mid,
            'sender': headers.get('From'),
            'subject': headers.get('Subject'),
            'labels': msg.get('labelIds', []),
            'score': score['score'],
            'reasons': score.get('reasons', []),
            'findings': findings,
        }
        report.append(report_item)
        mark_scanned(mid)
        count += 1
        if count >= max_messages:
            break
    to_json(report, os.path.join(output_dir, 'report.json'))
    to_csv(report, os.path.join(output_dir, 'report.csv'))
    to_html(report, os.path.join(output_dir, 'report.html'))
    print(f"Reports written to {output_dir}")


def review_report(path="reports/report.json"):
    if not os.path.exists(path):
        print("No report found. Run scan first.")
        return
    with open(path, 'r', encoding='utf-8') as f:
        report = json.load(f)
    for i, r in enumerate(report, 1):
        print(f"{i}. {r.get('subject')} from {r.get('sender')} - score {r.get('score')}")
    print(f"{len(report)} items. Use 'mitigate' to act on findings.")


def mitigate(path="reports/report.json", dry_run=True):
    if not os.path.exists(path):
        print("No report found. Run scan first.")
        return
    scopes = [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ]
    creds = load_credentials(["https://www.googleapis.com/auth/gmail.readonly"]) or run_local_oauth(["https://www.googleapis.com/auth/gmail.readonly"]) 
    creds = request_elevated_scopes(creds, scopes)
    gc = GmailConnector(creds)
    me = MitigationEngine(gc, dry_run=dry_run)
    with open(path, 'r', encoding='utf-8') as f:
        report = json.load(f)
    # simple interactive mitigation
    for r in report:
        mid = r.get('message_id')
        sender = r.get('sender')
        subject = r.get('subject')
        score = r.get('score')
        print(f"Message: {subject} from {sender} (score {score})")
        action = input("Action? [s]kip, [d]elete, [l]abel, [r]eport_spam: ").strip().lower()
        if action == 'd':
            ok = input("Confirm delete? y/N: ").strip().lower() == 'y'
            res = me.delete_message(mid, sender, confirm=ok)
            print(res)
        elif action == 'l':
            labels = gc.labels_map()
            print("Available labels:")
            for lid, info in labels.items():
                print(f"{lid}: {info.get('name')}")
            lid = input("Enter label id to apply: ").strip()
            ok = input("Confirm apply label? y/N: ").strip().lower() == 'y'
            res = me.apply_label(mid, lid, sender, confirm=ok)
            print(res)
        elif action == 'r':
            ok = input("Confirm report spam? y/N: ").strip().lower() == 'y'
            res = me.report_spam(mid, sender, confirm=ok)
            print(res)
        else:
            print("Skipped")


def main():
    parser = argparse.ArgumentParser("MailFort CLI")
    parser.add_argument("command", choices=["scan", "review", "mitigate"], help="command to run")
    parser.add_argument("--max", type=int, default=200, help="max messages to scan")
    parser.add_argument("--dry-run", action='store_true', help="dry run for mitigation")
    args = parser.parse_args()
    init_db()
    if args.command == 'scan':
        scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        creds = load_credentials(scopes)
        if not creds:
            creds = run_local_oauth(scopes)
        scan_mailbox(creds, max_messages=args.max)
    elif args.command == 'review':
        review_report()
    elif args.command == 'mitigate':
        mitigate(dry_run=args.dry_run)


if __name__ == '__main__':
    main()
