"""Gmail connector — wraps the Gmail API for MailFort v2."""

import time
from typing import Optional, Iterator, Dict, Any, List

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


class GmailConnector:
    """Wraps the Gmail API with pagination, rate-limit handling, and label management."""

    def __init__(self, creds):
        self.creds = creds
        self.service = build("gmail", "v1", credentials=creds)
        self._labels_cache: Optional[Dict[str, Dict]] = None

    # ------------------------------------------------------------------
    # Labels
    # ------------------------------------------------------------------

    def labels_map(self) -> Dict[str, Dict]:
        """Return a dict of label_id → label object."""
        if self._labels_cache is None:
            resp = self.service.users().labels().list(userId="me").execute()
            labels = resp.get("labels", [])
            self._labels_cache = {lb["id"]: lb for lb in labels}
        return self._labels_cache

    def label_name_to_id(self, name: str) -> Optional[str]:
        for lid, lb in self.labels_map().items():
            if lb.get("name", "").lower() == name.lower():
                return lid
        return None

    def create_label_if_missing(self, name: str) -> str:
        """Create a Gmail label if it does not exist; return its ID."""
        existing_id = self.label_name_to_id(name)
        if existing_id:
            return existing_id
        body = {
            "name": name,
            "messageListVisibility": "show",
            "labelListVisibility": "labelShow",
        }
        result = self.service.users().labels().create(userId="me", body=body).execute()
        self._labels_cache = None  # invalidate cache
        return result["id"]

    # ------------------------------------------------------------------
    # Message listing with pagination
    # ------------------------------------------------------------------

    def list_messages_page(
        self,
        label_ids: Optional[List[str]] = None,
        query: Optional[str] = None,
        page_token: Optional[str] = None,
        max_results: int = 100,
    ) -> Dict[str, Any]:
        try:
            req = self.service.users().messages().list(
                userId="me",
                labelIds=label_ids or [],
                q=query,
                pageToken=page_token,
                maxResults=max_results,
            )
            return req.execute()
        except HttpError as e:
            if getattr(e, "status_code", None) == 429:
                time.sleep(2)
                return self.list_messages_page(
                    label_ids=label_ids,
                    query=query,
                    page_token=page_token,
                    max_results=max_results,
                )
            raise

    def list_messages_all(
        self,
        label_ids: Optional[List[str]] = None,
        query: Optional[str] = None,
        max_messages: int = 0,
    ) -> Iterator[Dict[str, Any]]:
        """Yield all message stubs, respecting an optional total cap."""
        page_token = None
        yielded = 0
        while True:
            resp = self.list_messages_page(
                label_ids=label_ids,
                query=query,
                page_token=page_token,
            )
            for m in resp.get("messages", []):
                yield m
                yielded += 1
                if max_messages and yielded >= max_messages:
                    return
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

    # ------------------------------------------------------------------
    # Message fetch
    # ------------------------------------------------------------------

    def get_message(self, message_id: str, format: str = "full") -> Dict[str, Any]:
        return (
            self.service.users()
            .messages()
            .get(userId="me", id=message_id, format=format)
            .execute()
        )

    def get_thread(self, thread_id: str) -> Dict[str, Any]:
        return (
            self.service.users()
            .threads()
            .get(userId="me", id=thread_id)
            .execute()
        )

    def get_attachment(self, message_id: str, attachment_id: str) -> Dict[str, Any]:
        return (
            self.service.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=message_id, id=attachment_id)
            .execute()
        )

    # ------------------------------------------------------------------
    # Label modification
    # ------------------------------------------------------------------

    def modify_labels(
        self,
        message_id: str,
        add_label_ids: Optional[List[str]] = None,
        remove_label_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if add_label_ids:
            body["addLabelIds"] = add_label_ids
        if remove_label_ids:
            body["removeLabelIds"] = remove_label_ids
        return (
            self.service.users()
            .messages()
            .modify(userId="me", id=message_id, body=body)
            .execute()
        )

    def quarantine_message(
        self, message_id: str, quarantine_label_id: str
    ) -> Dict[str, Any]:
        """Apply quarantine label and remove from INBOX."""
        return self.modify_labels(
            message_id,
            add_label_ids=[quarantine_label_id],
            remove_label_ids=["INBOX"],
        )

    def release_message(
        self,
        message_id: str,
        quarantine_label_id: str,
        cleared_label_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Remove quarantine label and restore to INBOX."""
        add_ids = ["INBOX"]
        if cleared_label_id:
            add_ids.append(cleared_label_id)
        return self.modify_labels(
            message_id,
            add_label_ids=add_ids,
            remove_label_ids=[quarantine_label_id],
        )

    # ------------------------------------------------------------------
    # Trash / spam
    # ------------------------------------------------------------------

    def trash_message(self, message_id: str) -> Dict[str, Any]:
        return (
            self.service.users().messages().trash(userId="me", id=message_id).execute()
        )

    def report_spam(self, message_id: str) -> Dict[str, Any]:
        return self.modify_labels(
            message_id,
            add_label_ids=["SPAM"],
            remove_label_ids=["INBOX"],
        )

    # ------------------------------------------------------------------
    # History (incremental sync)
    # ------------------------------------------------------------------

    def list_history(
        self,
        start_history_id: str,
        label_id: Optional[str] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "userId": "me",
            "startHistoryId": start_history_id,
        }
        if label_id:
            kwargs["labelId"] = label_id
        if page_token:
            kwargs["pageToken"] = page_token
        return self.service.users().history().list(**kwargs).execute()
