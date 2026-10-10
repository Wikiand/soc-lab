#!/usr/bin/env python3
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse

BASE = Path.home() / "soc-lab"
ALERTS = BASE / "alerts" / "alerts.jsonl"
HOST = "127.0.0.1"
PORT = 8080

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local SOC Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#131c30;--line:#26344e;
--text:#e6edf7;--muted:#94a3b8;--green:#53e0a1;--red:#ff707b;
--yellow:#ffd166;--blue:#7db4ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,sans-serif}
main{max-width:1150px;margin:auto;padding:28px 18px}
header{display:flex;justify-content:space-between;align-items:center;
gap:16px;flex-wrap:wrap;margin-bottom:24px}
h1{font-size:25px;margin:0}h2{font-size:17px;margin:0 0 15px}
p{color:var(--muted);margin:5px 0}
.pill{border:1px solid var(--line);border-radius:20px;padding:6px 12px;
color:var(--green);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px}
.card,.panel{background:var(--panel);border:1px solid var(--line);
border-radius:13px;padding:18px}
.metric{font-size:30px;font-weight:700;margin-top:8px}
.label{font-size:13px;color:var(--muted)}
section{margin-top:20px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
input,select,button{background:#0b1426;color:var(--text);
border:1px solid var(--line);border-radius:8px;padding:10px;font:inherit}
input{flex:1;min-width:190px}button{cursor:pointer}
button:hover{border-color:var(--blue)}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--muted);font-weight:500}
.severity{font-weight:700}
.HIGH{color:var(--red)}.MEDIUM{color:var(--yellow)}.LOW{color:var(--blue)}
.evidence{white-space:pre-wrap;overflow-wrap:anywhere;max-width:440px;
color:#c5d2e5}
footer{margin-top:22px;color:var(--muted);font-size:12px}
@media(max-width:700px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}
main{padding:18px 12px}.metric{font-size:25px}}
</style>
</head>
<body>
<main>
<header>
<div><h1>Local SOC Dashboard</h1>
<p>Host authentication monitoring · Local analysis</p></div>
<span class="pill">● LOCAL LAB</span>
</header>
<div class="cards">
<div class="card"><div class="label">Total alerts</div><div class="metric" id="total">—</div></div>
<div class="card"><div class="label">High severity</div><div class="metric HIGH" id="high">—</div></div>
<div class="card"><div class="label">Medium severity</div><div class="metric MEDIUM" id="medium">—</div></div>
<div class="card"><div class="label">Low severity</div><div class="metric LOW" id="low">—</div></div>
</div>
<section class="panel" style="margin-top:20px">
<h2>Failed-login burst monitor</h2>
<p id="burst-status">Checking authentication logs...</p>
<p id="burst-detail">Threshold: 3 failures within 10 minutes.</p>
<div class="toolbar">
<button id="demoBurst">Show synthetic ALERT demo</button>
<button id="realBurst">Return to real logs</button>
</div>
<p id="demo-note" class="label">Real-log mode. Demo data is kept separate from actual logs.</p>
</section>
<section class="panel">
<h2>Alert investigation</h2>
<div class="toolbar">
<input id="search" placeholder="Search rules, evidence, timestamps...">
<select id="severity"><option value="">All severities</option>
<option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
<button id="refresh">Refresh alerts</button>
</div>
<p id="status">Loading alerts...</p>
<div class="table-wrap">
<table><thead><tr><th>Severity</th><th>Rule</th><th>Event time</th>
<th>Source</th><th>Evidence</th><th>Recommended action</th></tr></thead>
<tbody id="rows"></tbody></table>
</div>
</section>
<footer>Local-only dashboard. Rule matches are not proof of compromise.
Refresh after running the detector to see updated results.</footer>
</main>
<script>
let alerts=[];
const el=id=>document.getElementById(id);
function safe(value){return String(value??"").replace(/[&<>"']/g,c=>({
"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[c]));}
function render(){
 const counts={HIGH:0,MEDIUM:0,LOW:0};
 alerts.forEach(a=>{if(a.severity in counts)counts[a.severity]++});
 el("total").textContent=alerts.length;
 el("high").textContent=counts.HIGH;
 el("medium").textContent=counts.MEDIUM;
 el("low").textContent=counts.LOW;
 const query=el("search").value.toLowerCase();
 const severity=el("severity").value;
 const filtered=alerts.filter(a=>
   (!severity||a.severity===severity)&&
   JSON.stringify(a).toLowerCase().includes(query));
 el("status").textContent=`Showing ${filtered.length} of ${alerts.length} alerts`;
 el("rows").innerHTML=filtered.slice().reverse().map(a=>`
 <tr>
 <td class="severity ${safe(a.severity)}">${safe(a.severity)}</td>
 <td><strong>${safe(a.rule_name)}</strong><br><span class="label">${safe(a.rule_id)}</span></td>
 <td>${safe(a.event_timestamp)}</td>
 <td>${safe(a.source)}<br><span class="label">Line ${safe(a.source_line)}</span></td>
 <td class="evidence">${safe(a.evidence)}</td>
 <td>${safe(a.recommended_action || "No recommendation available.")}</td>
 </tr>`).join("");
}
async function showBurstDemo(){
 try{
  const response=await fetch("/api/burst-demo",{cache:"no-store"});
  if(!response.ok)throw new Error("HTTP "+response.status);
  const data=await response.json();
  el("burst-status").textContent="DEMO ALERT — synthetic failed-login burst";
  el("burst-status").style.color="#ff707b";
  el("burst-detail").textContent=
   `${data.failed_events} synthetic failures within ${data.window_minutes} minutes. ${data.note}`;
  el("demo-note").textContent="DEMO MODE — these are fabricated events, not real security incidents.";
 }catch(e){el("burst-status").textContent="Demo failed: "+e.message;}
}
async function loadBurst(){
 try{
  const response=await fetch("/api/burst-status",{cache:"no-store"});
  if(!response.ok)throw new Error("HTTP "+response.status);
  const data=await response.json();
  const status=el("burst-status");
  status.textContent=data.status==="ALERT"
   ? "ALERT — possible failed-login burst detected"
   : "CLEAR — no qualifying burst detected";
  status.style.color=data.status==="ALERT"?"#ff707b":"#53e0a1";
  el("burst-detail").textContent=
   `${data.failed_events} failed-authentication events checked; threshold ${data.threshold} within ${data.window_minutes} minutes. ${data.note}`;
 }catch(e){
  el("burst-status").textContent="Could not load burst status: "+e.message;
 }
}
async function load(){
 await loadBurst();
 try{
  const response=await fetch("/api/alerts",{cache:"no-store"});
  if(!response.ok)throw new Error("HTTP "+response.status);
  const data=await response.json();
  alerts=data.alerts;
  render();
 }catch(e){el("status").textContent="Could not load alerts: "+e.message;}
}
el("search").addEventListener("input",render);
el("severity").addEventListener("change",render);
el("refresh").addEventListener("click",load);
el("demoBurst").addEventListener("click",showBurstDemo);
el("realBurst").addEventListener("click",async()=>{
 el("demo-note").textContent="Real-log mode. Demo data is kept separate from actual logs.";
 await loadBurst();
});
load();
</script>
</body></html>"""


FAIL_RE = re.compile(
    r"authentication failure|FAILED LOGIN|user unknown", re.I
)

def get_burst_status():
    sources = [
        Path.home() / "auth-events.log",
        BASE / "logs" / "auth-live.log",
    ]
    events = []

    for source in sources:
        if not source.exists():
            continue
        for line in source.read_text(errors="replace").splitlines():
            if not FAIL_RE.search(line):
                continue
            match = re.match(r"^(\S+)", line)
            if not match:
                continue
            try:
                timestamp = datetime.fromisoformat(match.group(1))
            except ValueError:
                continue
            events.append({"time": timestamp, "source": str(source), "line": line})

    events.sort(key=lambda event: event["time"])
    window = timedelta(minutes=10)
    threshold = 3
    burst = []

    for i, event in enumerate(events):
        matches = [
            item for item in events[i:]
            if item["time"] - event["time"] <= window
        ]
        if len(matches) >= threshold:
            burst = matches
            break

    return {
        "status": "ALERT" if burst else "CLEAR",
        "threshold": threshold,
        "window_minutes": 10,
        "failed_events": len(events),
        "burst_count": len(burst),
        "evidence": [
            {
                "timestamp": item["time"].isoformat(),
                "source": item["source"],
                "line": item["line"],
            }
            for item in burst
        ],
        "note": "A burst is a detection signal, not proof of an attack.",
    }

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif path == "/api/alerts":
            alerts = []
            if ALERTS.exists():
                for line in ALERTS.read_text(errors="replace").splitlines():
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            body = json.dumps({"alerts": alerts}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        elif path == "/api/burst-status":
            body = json.dumps(get_burst_status()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        elif path == "/api/burst-demo":
            body = json.dumps({
                "status": "ALERT",
                "threshold": 3,
                "window_minutes": 10,
                "failed_events": 3,
                "burst_count": 3,
                "synthetic": True,
                "evidence": [
                    {"timestamp": "2026-10-10T10:00:00+03:00",
                     "source": "SYNTHETIC DEMO DATA",
                     "line": "FAILED LOGIN test event 1"},
                    {"timestamp": "2026-10-10T10:02:00+03:00",
                     "source": "SYNTHETIC DEMO DATA",
                     "line": "FAILED LOGIN test event 2"},
                    {"timestamp": "2026-10-10T10:04:00+03:00",
                     "source": "SYNTHETIC DEMO DATA",
                     "line": "FAILED LOGIN test event 3"}
                ],
                "note": "Demonstration only; no real login attempts occurred."
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        else:
            body = b"Not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

if __name__ == "__main__":
    print(f"SOC dashboard: http://{HOST}:{PORT}")
    print(f"Alert source: {ALERTS}")
    HTTPServer((HOST, PORT), Handler).serve_forever()
