"""MailFort v2 configuration.

Scoring weights, thresholds, and runtime settings used across the pipeline.
"""

from .constants import (
    DETONATE_AT_SCORE,
    ACTION_QUARANTINE,
    ACTION_WARN,
    ACTION_ALLOW,
)

# ---------------------------------------------------------------------------
# Scoring weights — static analysis
# ---------------------------------------------------------------------------
SCORING_WEIGHTS = {
    # Authentication failures
    "spf_fail": 15,
    "dkim_fail": 15,
    "dmarc_fail": 20,
    # Header anomalies
    "reply_to_mismatch": 10,
    "display_name_mismatch": 15,
    "suspicious_return_path": 8,
    "missing_message_id": 5,
    "received_chain_anomaly": 8,
    "urgent_subject": 8,
    "all_caps_subject": 5,
    # Sender signals
    "new_sender": 5,
    "lookalike_domain": 25,
    "brand_impersonation": 20,
    "freemail_brand_impersonation": 22,
    # Body signals
    "phishing_language": 10,
    # URL signals
    "suspicious_link": 15,
    "punycode_domain": 20,
    "url_shortener": 10,
    "raw_ip_url": 15,
    "anchor_text_mismatch": 12,
    "suspicious_tld": 10,
    "excessive_query_params": 5,
    # Attachment signals
    "malicious_attachment": 30,
    "steg_indicator": 15,
    "extension_mismatch": 20,
    "high_risk_extension": 25,
    "encrypted_archive": 15,
    "nested_archive": 10,
    # Office doc signals
    "macro_indicator": 30,
    "external_template_ref": 20,
    "auto_open_action": 25,
    # PDF signals
    "pdf_javascript": 25,
    "pdf_launch_action": 25,
    "pdf_embedded_file": 15,
    "pdf_open_action": 20,
}

# ---------------------------------------------------------------------------
# Dynamic scoring — sandbox results
# ---------------------------------------------------------------------------
DYNAMIC_SCORING_WEIGHTS = {
    "credential_harvest": 50,
    "executable_network_callback": 40,
    "persistence_attempt": 40,
    "file_drop_executable": 30,
    "redirect_to_login_form": 25,
    "process_injection": 35,
    "registry_modification": 20,
    "dns_lookup_suspicious": 15,
    "download_triggered": 20,
    "clipboard_access": 10,
}

# ---------------------------------------------------------------------------
# Policy thresholds — maps severity to default action
# ---------------------------------------------------------------------------
DEFAULT_POLICY = {
    "critical": ACTION_QUARANTINE,
    "high": ACTION_QUARANTINE,
    "medium": ACTION_WARN,
    "low": ACTION_ALLOW,
    "benign": ACTION_ALLOW,
}

# ---------------------------------------------------------------------------
# Runtime defaults
# ---------------------------------------------------------------------------
DEFAULT_MAX_MESSAGES = 100
DEFAULT_IMAP_PORT = 993
DEFAULT_IMAP_SSL = True
DEFAULT_IMAP_MAILBOX = "INBOX"
DEFAULT_ENTROPY_THRESHOLD = 7.5
DEFAULT_QUARANTINE_THRESHOLD = 60  # severity >= high triggers quarantine

# Score at which detonation fires in MailFort mode
DETONATE_THRESHOLD = DETONATE_AT_SCORE
