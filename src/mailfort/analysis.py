import re
import base64
import io
import math
import tldextract
import magic
from collections import defaultdict

URL_RE = re.compile(r"https?://[\w\-\.\/:?&=%#@+]+", re.IGNORECASE)

def extract_urls(text):
    return URL_RE.findall(text or "")

def is_punycode(domain):
    return "xn--" in domain

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    ent = 0.0
    for count in freq.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return ent

class EmailAnalyzer:
    def __init__(self):
        pass

    def analyze_headers(self, headers):
        h = {k.lower(): v for k, v in headers.items()}
        auth_results = h.get("authentication-results", "")
        findings = {
            "spf": "pass" if "spf=pass" in auth_results.lower() else "fail",
            "dkim": "pass" if "dkim=pass" in auth_results.lower() else "fail",
            "dmarc": "pass" if "dmarc=pass" in auth_results.lower() else "fail",
        }
        return findings

    def analyze_body(self, body_text):
        urls = extract_urls(body_text)
        url_findings = []
        for u in urls:
            domain = tldextract.extract(u).registered_domain
            pf = is_punycode(domain)
            url_findings.append({"url": u, "domain": domain, "punycode": pf})
        lang_indicators = []
        if any(w in (body_text or "").lower() for w in ["verify", "login", "password", "urgent", "immediately"]):
            lang_indicators.append("phishing-language")
        return {"urls": url_findings, "language": lang_indicators}

    def analyze_attachments(self, parts):
        att_findings = []
        for p in parts or []:
            if p.get("filename"):
                data_b64 = p.get("body", {}).get("data")
                if not data_b64:
                    continue
                raw = base64.urlsafe_b64decode(data_b64 + "=")
                try:
                    mtype = magic.from_buffer(raw, mime=True)
                except Exception:
                    mtype = "application/octet-stream"
                ent = entropy(raw)
                att_findings.append({"filename": p.get("filename"), "mtype": mtype, "entropy": ent})
        return att_findings
