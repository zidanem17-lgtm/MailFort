"""MailFort v2 — phishing detection and response platform.

MailFort is the primary threat-analysis platform providing full static analysis,
sandbox detonation, a verdict engine, and policy-driven quarantine across any
mail provider.

PhishFinder is the lightweight static-scan operating mode within the same
pipeline — delivering explainable scoring, URL and attachment inspection, and
structured reports as supporting evidence of the same threat-analysis thread.

Enterprise deployment supports Gmail (via OAuth) and any custom business domain
via standard IMAP, enabling coverage beyond personal inboxes into organisational
mail environments at scale.
"""

from .constants import MAILFORT_VERSION

__version__ = MAILFORT_VERSION
__all__ = ["__version__"]
