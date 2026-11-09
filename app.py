import csv, io, json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from .database import Database
from .capture import read_pcap
from .analyzer import analyze_frames, make_filter

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "packets.sqlite3"
SETTINGS = json.loads((ROOT / "config" / "settings.json").read_text(encoding="utf-8"))
STATE = {"data": {"packets":[], "protocols":{}, "hosts":{}, "flows":[], "alerts":[]},
         "source":"Not loaded", "started":time.time()}
LOCK = threading.Lock()

def load_capture(path, protocol="ALL", ip=""):
    db = Database(DB_PATH)
    frames = list(read_pcap(path))
    data = analyze_frames(frames, db, SETTINGS, make_filter(protocol, ip))
    db.close()
    with LOCK:
        STATE["data"] = data
        STATE["source"] = str(path)
    return len(data["packets"])

def page():
    return r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Packet Sniffer Dashboard</title><style>
*{box-sizing:border-box}body{margin:0;background:#eef3f8;color:#172b3a;font:15px Arial,sans-serif}
header{background:#125879;color:white;padding:22px 5%;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
header h1{margin:0;font-size:24px}header small{opacity:.85}.wrap{max-width:1200px;margin:24px auto;padding:0 18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}.card,.panel{background:white;border-radius:12px;padding:18px;box-shadow:0 2px 10px #102c3d12}
.card span{color:#627889;font-size:13px}.card strong{display:block;font-size:28px;margin-top:8px;color:#125879}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}.panel{margin-top:16px;overflow:auto}.grid .panel{margin-top:0}
h2{font-size:18px;margin:0 0 14px}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:10px;border-bottom:1px solid #e5edf2;font-size:13px}th{background:#eaf2f6;color:#28546a}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}.controls input,.controls select{padding:10px;border:1px solid #cad7df;border-radius:8px;background:white}
button,.btn{border:0;background:#14749b;color:white;padding:10px 15px;border-radius:8px;cursor:pointer;text-decoration:none}
.muted{color:#6b7f8d;font-size:13px}.alert{padding:10px;border-left:4px solid #d98b27;background:#fff8ec;margin:8px 0;border-radius:5px}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
</style></head><body><header><div><h1>Packet Sniffer</h1><small>Educational network traffic analysis dashboard</small></div><div id="source">Loading…</div></header>
<div class="wrap"><div class="cards">
<div class="card"><span>Total packets</span><strong id="packets">0</strong></div><div class="card"><span>Total bytes</span><strong id="bytes">0</strong></div>
<div class="card"><span>Protocols</span><strong id="protocolCount">0</strong></div><div class="card"><span>Active flows</span><strong id="flowsCount">0</strong></div>
<div class="card"><span>Unique hosts</span><strong id="hostsCount">0</strong></div><div class="card"><span>Alerts</span><strong id="alertsCount">0</strong></div></div>
<div class="controls"><select id="protocol"><option>ALL</option><option>TCP</option><option>UDP</option><option>DNS</option><option>ICMP</option><option>ARP</option></select><input id="ip" placeholder="Filter by IP address"><button onclick="applyFilter()">Apply filter</button><button onclick="refresh()">Refresh</button><a class="btn" href="/export.csv">Export CSV</a></div>
<div class="grid"><section class="panel"><h2>Protocol distribution</h2><div id="protocols" class="muted">No data</div></section>
<section class="panel"><h2>Top talkers</h2><div id="talkers"></div></section></div>
<section class="panel"><h2>Recent packets</h2><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody id="packetRows"></tbody></table></section>
<div class="grid"><section class="panel"><h2>Flows / conversations</h2><div id="flows"></div></section><section class="panel"><h2>Security alerts</h2><div id="alerts" class="muted">No alerts</div></section></div>
<p class="muted">Local-only dashboard. Metadata and headers are displayed; application payloads are not collected for display. Monitor only authorised networks.</p></div>
<script>
async function refresh(){let r=await fetch('/api/data');let d=await r.json();let p=d.packets||[];
document.getElementById('source').textContent='Source: '+d.source;
document.getElementById('packets').textContent=p.length;
document.getElementById('bytes').textContent=p.reduce((a,x)=>a+(x.length||0),0).toLocaleString();
document.getElementById('protocolCount').textContent=Object.keys(d.protocols||{}).length;
document.getElementById('flowsCount').textContent=(d.flows||[]).length;
document.getElementById('hostsCount').textContent=Object.keys(d.hosts||{}).length;
document.getElementById('alertsCount').textContent=(d.alerts||[]).length;
document.getElementById('protocols').innerHTML=Object.entries(d.protocols||{}).map(([k,v])=>`<p><b>${k}</b> — ${v} packets</p>`).join('')||'No data';
document.getElementById('talkers').innerHTML=Object.entries(d.hosts||{}).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([k,v])=>`<p>${k} <b style="float:right">${v}</b></p>`).join('')||'No hosts';
document.getElementById('packetRows').innerHTML=p.slice(-100).reverse().map(x=>`<tr><td>${new Date((x.timestamp||0)*1000).toLocaleTimeString()}</td><td>${x.src_ip||x.src_mac||'—'}</td><td>${x.dst_ip||x.dst_mac||'—'}</td><td>${x.protocol}</td><td>${x.length}</td><td>${x.info||''}</td></tr>`).join('');
document.getElementById('flows').innerHTML=(d.flows||[]).slice(0,30).map(x=>`<p>${x.conversation} <b>${x.protocol}</b> — ${x.packets} packets / ${x.bytes} bytes</p>`).join('')||'No flows';
document.getElementById('alerts').innerHTML=(d.alerts||[]).map(x=>`<div class="alert"><b>${x.severity}: ${x.rule}</b><br>${x.source} — ${x.message}</div>`).join('')||'No alerts detected';
}
async function applyFilter(){let q=new URLSearchParams({protocol:document.getElementById('protocol').value,ip:document.getElementById('ip').value});await fetch('/api/filter?'+q);refresh()}
refresh();
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def _send(self, body, content_type="application/json; charset=utf-8", status=200):
        raw = body.encode("utf-8")
        self.send_response(status); self.send_header("Content-Type",content_type)
        self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(page(), "text/html; charset=utf-8"); return
        if path == "/api/data":
            with LOCK: payload = dict(STATE["data"], source=STATE["source"])
            self._send(json.dumps(payload)); return
        if path == "/api/stats":
            d=STATE["data"]; self._send(json.dumps({"packets":len(d["packets"]),"protocols":d["protocols"],"flows":len(d["flows"]),"alerts":len(d["alerts"])})); return
        if path == "/api/packets": self._send(json.dumps(STATE["data"]["packets"])); return
        if path == "/api/protocols": self._send(json.dumps(STATE["data"]["protocols"])); return
        if path == "/api/flows": self._send(json.dumps(STATE["data"]["flows"])); return
        if path == "/api/talkers": self._send(json.dumps(STATE["data"]["hosts"])); return
        if path == "/api/alerts": self._send(json.dumps(STATE["data"]["alerts"])); return
        if path == "/api/filter":
            q=parse_qs(urlparse(self.path).query)
            protocol=q.get("protocol",["ALL"])[0]; ip=q.get("ip",[""])[0]
            source=STATE["source"]
            if source and source != "Not loaded":
                try: load_capture(source,protocol,ip)
                except Exception as e: self._send(json.dumps({"error":str(e)}),status=400); return
            self._send(json.dumps({"ok":True})); return
        if path == "/export.csv":
            output=io.StringIO(); writer=csv.DictWriter(output,fieldnames=["timestamp","length","protocol","src_ip","dst_ip","src_port","dst_port","tcp_flags","info"])
            writer.writeheader()
            for p in STATE["data"]["packets"]: writer.writerow({k:p.get(k) for k in writer.fieldnames})
            self._send(output.getvalue(),"text/csv; charset=utf-8"); return
        self._send("Not found","text/plain",404)
    def log_message(self, fmt, *args): print("[HTTP]", fmt % args)

def serve(host="127.0.0.1", port=5000):
    server=ThreadingHTTPServer((host,port),Handler)
    print(f"Packet Sniffer dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\\nStopping dashboard…")
    finally: server.server_close()
