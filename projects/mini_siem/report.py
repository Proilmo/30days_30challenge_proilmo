"""
report.py
---------
Generates a single static HTML file (dashboard.html) summarizing alerts and
recent events. No web server needed -- just open the file in a browser.
Kept deliberately simple (plain HTML + a little inline CSS, no JS framework)
since the goal is a mini-SIEM, not a mini-Kibana.
"""

import html
from datetime import datetime

from siem_core import all_alerts, all_events

SEVERITY_COLOR = {
    "critical": "#7f1d1d",
    "high": "#b45309",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#374151",
}


def _badge(sev):
    color = SEVERITY_COLOR.get(sev, "#374151")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;">{sev.upper()}</span>'


def generate(conn, out_path="dashboard.html"):
    alerts = all_alerts(conn)
    events = all_events(conn)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in alerts:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1

    alert_rows = "".join(
        f"<tr><td>{html.escape(a['timestamp'])}</td>"
        f"<td>{_badge(a['severity'])}</td>"
        f"<td>{html.escape(a['rule'])}</td>"
        f"<td>{html.escape(a['description'])}</td>"
        f"<td>{html.escape(a['src_ip'] or '')}</td>"
        f"<td>{html.escape(a['user'] or '')}</td></tr>"
        for a in alerts
    )

    event_rows = "".join(
        f"<tr><td>{html.escape(e['timestamp'])}</td>"
        f"<td>{html.escape(e['source'])}</td>"
        f"<td>{html.escape(e['event_type'])}</td>"
        f"<td>{html.escape(e['host'] or '')}</td>"
        f"<td>{html.escape(e['user'] or '')}</td>"
        f"<td>{html.escape(e['src_ip'] or '')}</td>"
        f"<td>{html.escape(e['message'] or '')}</td></tr>"
        for e in events
    )

    summary_cards = "".join(
        f'<div class="card"><div class="num" style="color:{SEVERITY_COLOR[s]}">{counts[s]}</div>'
        f'<div class="label">{s.upper()}</div></div>'
        for s in ["critical", "high", "medium", "low", "info"]
    )

    html_doc = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Mini-SIEM Dashboard</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 24px; background: #0b1120; color: #e5e7eb; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #9ca3af; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 12px; margin-bottom: 28px; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 14px 20px; text-align: center; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .label {{ font-size: 12px; color: #9ca3af; letter-spacing: 1px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 36px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #1f2937; }}
  th {{ color: #9ca3af; text-transform: uppercase; font-size: 11px; }}
  tr:hover {{ background: #111827; }}
  h2 {{ border-bottom: 1px solid #1f2937; padding-bottom: 6px; }}
</style>
</head>
<body>
  <h1>Mini-SIEM Dashboard</h1>
  <div class="meta">Generated {datetime.utcnow().isoformat()} UTC &middot; {len(events)} events ingested &middot; {len(alerts)} alerts raised</div>

  <div class="cards">{summary_cards}</div>

  <h2>Alerts ({len(alerts)})</h2>
  <table>
    <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Description</th><th>Src IP</th><th>User</th></tr>
    {alert_rows if alert_rows else '<tr><td colspan="6">No alerts raised.</td></tr>'}
  </table>

  <h2>Recent Events ({len(events)})</h2>
  <table>
    <tr><th>Time</th><th>Source</th><th>Type</th><th>Host</th><th>User</th><th>Src IP</th><th>Message</th></tr>
    {event_rows if event_rows else '<tr><td colspan="7">No events ingested.</td></tr>'}
  </table>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return out_path
