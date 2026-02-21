import json
import pandas as pd
from jinja2 import Template

HTML_TEMPLATE = """
<html><head><meta charset="utf-8"><title>MailFort Report</title></head><body>
<h1>MailFort Threat Report</h1>
<table border="1"><tr><th>Message ID</th><th>Sender</th><th>Subject</th><th>Score</th><th>Reasons</th></tr>
{% for r in rows %}
<tr><td>{{r.message_id}}</td><td>{{r.sender}}</td><td>{{r.subject}}</td><td>{{r.score}}</td><td>{{r.reasons}}</td></tr>
{% endfor %}
</table></body></html>
"""

def to_json(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def to_csv(report, path):
    rows = []
    for item in report:
        rows.append({
            "message_id": item.get("message_id"),
            "sender": item.get("sender"),
            "subject": item.get("subject"),
            "score": item.get("score"),
            "reasons": "; ".join(item.get("reasons", []))
        })
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)

def to_html(report, path):
    tmpl = Template(HTML_TEMPLATE)
    rows = [
        {"message_id": r.get("message_id"), "sender": r.get("sender"), "subject": r.get("subject"), "score": r.get("score"), "reasons": ", ".join(r.get("reasons", []))}
        for r in report
    ]
    html = tmpl.render(rows=rows)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
