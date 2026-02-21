from .config import SCORING_WEIGHTS

def compute_score(findings):
    score = 0
    reasons = []
    if findings.get("headers", {}).get("spf") == "fail":
        score += SCORING_WEIGHTS.get("spf_fail", 0)
        reasons.append("SPF failure")
    if findings.get("headers", {}).get("dkim") == "fail":
        score += SCORING_WEIGHTS.get("dkim_fail", 0)
        reasons.append("DKIM failure")
    if findings.get("headers", {}).get("dmarc") == "fail":
        score += SCORING_WEIGHTS.get("dmarc_fail", 0)
        reasons.append("DMARC failure")
    if findings.get("body", {}).get("language"):
        score += 10
        reasons.append("Phishing language indicators")
    for u in findings.get("body", {}).get("urls", []):
        if u.get("punycode"):
            score += SCORING_WEIGHTS.get("suspicious_link", 0)
            reasons.append(f"Punycode domain {u.get('domain')}")
    for a in findings.get("attachments", []):
        if a.get("mtype") in ("application/x-msdownload", "application/x-msdos-program"):
            score += SCORING_WEIGHTS.get("malicious_attachment", 0)
            reasons.append(f"High-risk attachment {a.get('filename')}")
        if a.get("entropy", 0) > 7.5:
            score += SCORING_WEIGHTS.get("steg_indicator", 0)
            reasons.append(f"High-entropy attachment {a.get('filename')}")
    total = min(int(score), 100)
    return {"score": total, "reasons": reasons}
