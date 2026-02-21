import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DEFAULT_SCOPES = {
    "read_only": [
        "https://www.googleapis.com/auth/gmail.readonly",
    ],
    "full": [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ],
}

SCORING_WEIGHTS = {
    "spf_fail": 25,
    "dkim_fail": 20,
    "dmarc_fail": 20,
    "suspicious_link": 20,
    "malicious_attachment": 30,
    "steg_indicator": 20,
    "impersonation": 15,
}
