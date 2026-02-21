import time
from .state import log_audit


class MitigationEngine:
    def __init__(self, gmail_connector, dry_run=True):
        self.gc = gmail_connector
        self.dry_run = dry_run

    def _log(self, action, message_id, sender, user_confirmed):
        ts = time.time()
        log_audit(ts, action, message_id, sender, user_confirmed)

    def delete_message(self, message_id, sender, confirm=True):
        self._log("delete", message_id, sender, confirm)
        if not confirm:
            return {"status": "skipped"}
        if self.dry_run:
            return {"status": "dry-run"}
        return self.gc.service.users().messages().trash(userId="me", id=message_id).execute()

    def apply_label(self, message_id, label_id, sender, confirm=True):
        self._log("label", message_id, sender, confirm)
        if not confirm:
            return {"status": "skipped"}
        if self.dry_run:
            return {"status": "dry-run"}
        body = {"addLabelIds": [label_id]}
        return self.gc.service.users().messages().modify(userId="me", id=message_id, body=body).execute()

    def report_spam(self, message_id, sender, confirm=True):
        self._log("report_spam", message_id, sender, confirm)
        if not confirm:
            return {"status": "skipped"}
        if self.dry_run:
            return {"status": "dry-run"}
        return self.gc.service.users().messages().modify(userId="me", id=message_id, body={"removeLabelIds": [], "addLabelIds": ["SPAM"]}).execute()

