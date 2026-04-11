"""Gmail OAuth authentication for MailFort v2."""

import json
import os
from typing import Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from .constants import (
    GMAIL_SCOPES_READONLY,
    GMAIL_SCOPES_MODIFY,
    DEFAULT_TOKEN_PATH,
    DEFAULT_CREDENTIALS_PATH,
)


def get_gmail_credentials(
    credentials_path: str = DEFAULT_CREDENTIALS_PATH,
    token_path: str = DEFAULT_TOKEN_PATH,
    readonly: bool = True,
) -> Credentials:
    """Load or create Gmail OAuth2 credentials.

    On the first run an OAuth browser flow is triggered.  Subsequent runs
    reload tokens from *token_path* and refresh them automatically.

    Args:
        credentials_path: Path to the OAuth client-secrets JSON downloaded
            from the Google Cloud Console.
        token_path: Path where the access + refresh tokens will be cached.
        readonly: If True, request only read-only Gmail scope (PhishFinder
            mode).  If False, request modify + label scopes (MailFort mode).
    """
    scopes = GMAIL_SCOPES_READONLY if readonly else GMAIL_SCOPES_MODIFY
    creds: Optional[Credentials] = None

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, scopes)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(credentials_path):
                raise FileNotFoundError(
                    f"OAuth credentials file not found: {credentials_path}\n"
                    "Download it from the Google Cloud Console → APIs & Services → Credentials."
                )
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes)
            creds = flow.run_local_server(port=0)

        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        with open(token_path, "w") as f:
            f.write(creds.to_json())

    return creds
