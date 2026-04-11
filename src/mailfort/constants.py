"""MailFort v2 constants.

MailFort is the primary threat-analysis platform providing full static analysis,
sandbox detonation, verdict engine, and policy-driven quarantine.
PhishFinder represents the lightweight static-scan mode within the same pipeline,
supporting the same threat-analysis thread with explainable scoring and reporting.
"""

import os

MAILFORT_VERSION = "2.0.0"
MAILFORT_DB_VERSION = 2

# Operating modes
MODE_PHISHFINDER = "phishfinder"
MODE_MAILFORT = "mailfort"

# Severity levels
SEVERITY_BENIGN = "benign"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = [
    SEVERITY_BENIGN,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
]

SEVERITY_THRESHOLDS = {
    SEVERITY_CRITICAL: 80,
    SEVERITY_HIGH: 60,
    SEVERITY_MEDIUM: 40,
    SEVERITY_LOW: 20,
    SEVERITY_BENIGN: 0,
}

# Policy actions
ACTION_ALLOW = "allow"
ACTION_WARN = "warn"
ACTION_QUARANTINE = "quarantine"
ACTION_BLOCK = "block"
ACTION_ESCALATE = "escalate"
ACTION_RELEASE = "release"

# Artifact types
ARTIFACT_URL = "url"
ARTIFACT_ATTACHMENT = "attachment"

# Provider types
PROVIDER_GMAIL = "gmail"
PROVIDER_IMAP = "imap"
PROVIDER_GRAPH = "graph"

# Gmail labels for quarantine workflow
LABEL_QUARANTINE = "MAILFORT/QUARANTINE"
LABEL_REVIEW = "MAILFORT/REVIEW"
LABEL_CLEARED = "MAILFORT/CLEARED"

# Default file paths
DEFAULT_MAILFORT_DIR = os.path.join(os.path.expanduser("~"), ".mailfort")
DEFAULT_DB_PATH = os.path.join(DEFAULT_MAILFORT_DIR, "mailfort_v2.db")
DEFAULT_TOKEN_PATH = os.path.join(DEFAULT_MAILFORT_DIR, "tokens.json")
DEFAULT_REPORT_DIR = os.path.join(DEFAULT_MAILFORT_DIR, "reports")
DEFAULT_CREDENTIALS_PATH = os.path.join(os.getcwd(), "credentials.json")

# Gmail OAuth scopes — read-only for PhishFinder mode, modify for MailFort mode
GMAIL_SCOPES_READONLY = ["https://www.googleapis.com/auth/gmail.readonly"]
GMAIL_SCOPES_MODIFY = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "v.gd", "rebrand.ly", "short.io",
    "tiny.cc", "shorte.st", "adf.ly", "shrinkme.io", "cutt.ly",
    "rb.gy", "shorturl.at", "snip.ly", "tr.im", "cli.gs",
}

# High-risk file extensions
HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".vbs",
    ".ps1", ".pif", ".reg", ".js", ".jse", ".wsf", ".hta",
    ".jar", ".msi", ".lnk", ".iso", ".img", ".application",
    ".gadget", ".msp", ".msc", ".cpl",
}

# Office extensions that may contain macros
MACRO_EXTENSIONS = {
    ".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm",
    ".xlsb", ".dotm", ".xltm", ".potm", ".sldm",
}

# Archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".ace", ".arj", ".lzh",
}

# Phishing language signals
PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "urgent action required",
    "your account will be suspended", "click here to verify", "login immediately",
    "update your payment", "your password has expired", "suspicious activity",
    "click below to confirm", "verify now", "account locked", "immediate action",
    "validate your account", "unusual sign-in", "security alert",
    "account has been compromised", "unusual activity detected", "reset your password",
    "confirm your email", "update billing", "payment failed", "invoice attached",
    "you have a pending", "click the link below", "will expire in",
]

# Suspicious TLDs associated with high abuse rates
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".space", ".fun", ".link",
    ".buzz", ".click", ".download", ".stream", ".bid",
}

# MIME types considered high risk for attachments
HIGH_RISK_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-shellscript",
    "application/x-sh",
    "application/x-bat",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
}

# Score threshold at which sandbox detonation is triggered in MailFort mode
DETONATE_AT_SCORE = 50

# Brands commonly impersonated in phishing campaigns
KNOWN_BRANDS = {
    "microsoft", "google", "apple", "amazon", "paypal", "facebook",
    "netflix", "linkedin", "twitter", "dropbox", "docusign", "fedex",
    "ups", "dhl", "usps", "irs", "wellsfargo", "chase", "citibank",
    "bankofamerica", "outlook", "office365", "onedrive", "sharepoint",
}
