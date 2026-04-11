# Connectors are loaded on demand to avoid hard-failing when optional
# provider dependencies (google-api-python-client) are not installed.
from .imap import ImapConnector
from .message_normalizer import normalize_gmail_message, normalize_imap_message

__all__ = [
    "ImapConnector",
    "normalize_gmail_message",
    "normalize_imap_message",
]

def __getattr__(name):
    if name == "GmailConnector":
        from .gmail import GmailConnector
        return GmailConnector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
