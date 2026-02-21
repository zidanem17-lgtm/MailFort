import time
import json
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


class GmailConnector:
    def __init__(self, creds):
        self.creds = creds
        self.service = build("gmail", "v1", credentials=creds)

    def labels_map(self):
        resp = self.service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
        return {l["id"]: l for l in labels}

    def list_messages_page(self, label_ids=None, query=None, page_token=None):
        try:
            req = self.service.users().messages().list(userId="me", labelIds=label_ids or [], q=query, pageToken=page_token)
            return req.execute()
        except HttpError as e:
            status = getattr(e, 'status_code', None)
            if status == 429:
                time.sleep(2)
                return self.list_messages_page(label_ids=label_ids, query=query, page_token=page_token)
            raise

    def list_messages_all(self, label_ids=None, query=None):
        page_token = None
        while True:
            resp = self.list_messages_page(label_ids=label_ids, query=query, page_token=page_token)
            for m in resp.get('messages', []):
                yield m
            page_token = resp.get('nextPageToken')
            if not page_token:
                break

    def get_message(self, message_id, format="full"):
        return self.service.users().messages().get(userId="me", id=message_id, format=format).execute()
