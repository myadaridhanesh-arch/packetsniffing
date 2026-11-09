from collections import Counter, defaultdict
from .decoder import decode_frame

def analyze_frames(frames, db, settings, packet_filter=None):
    db.reset()
    packets, protocols, hosts, flows = [], Counter(), Counter(), defaultdict(lambda: {"packets":0,"bytes":0})
    syn_ports = defaultdict(set)
    arp_claims = defaultdict(set)
    alerts = []
    for frame, ts in frames:
        p = decode_frame(frame, ts)
        if packet_filter and not packet_filter(p):
            continue
        packets.append(p)
        protocols[p["protocol"]] += 1
        for host in (p.get("src_ip"), p.get("dst_ip")):
            if host: hosts[host] += 1
        if p.get("src_ip") and p.get("dst_ip"):
            left = (p["src_ip"], p.get("src_port") or 0)
            right = (p["dst_ip"], p.get("dst_port") or 0)
            key = tuple(sorted((left,right))) + (p["protocol"],)
            flows[key]["packets"] += 1
            flows[key]["bytes"] += p["length"]
        if p["protocol"] == "TCP" and p.get("tcp_syn") and p.get("src_ip") and p.get("dst_port"):
            syn_ports[p["src_ip"]].add(p["dst_port"])
        if p["protocol"] == "ARP" and p.get("src_ip") and p.get("arp_sender_mac"):
            arp_claims[p["src_ip"]].add(p["arp_sender_mac"])
        db.add_packet(p)

    threshold = int(settings.get("port_scan",{}).get("distinct_ports_threshold",8))
    if settings.get("port_scan",{}).get("enabled",True):
        for src, ports in syn_ports.items():
            if len(ports) >= threshold:
                alerts.append({"timestamp":packets[-1]["timestamp"] if packets else 0,
                    "severity":"HIGH","rule":"Possible TCP port scan","source":src,
                    "message":f"{len(ports)} distinct destination ports received SYN packets"})
    if settings.get("arp_conflict",{}).get("enabled",True):
        for ip, macs in arp_claims.items():
            if len(macs) > 1:
                alerts.append({"timestamp":packets[-1]["timestamp"] if packets else 0,
                    "severity":"MEDIUM","rule":"Conflicting ARP mapping","source":ip,
                    "message":f"IP address claimed by {len(macs)} different MAC addresses"})
    for a in alerts: db.add_alert(a)
    db.commit()
    flow_rows = [{"conversation":f"{k[0][0]}:{k[0][1]} ↔ {k[1][0]}:{k[1][1]}",
                  "protocol":k[2], **v} for k,v in flows.items()]
    return {"packets":packets,"protocols":dict(protocols),"hosts":dict(hosts),
            "flows":flow_rows,"alerts":alerts}

def make_filter(protocol="ALL", ip=""):
    protocol, ip = protocol.upper(), ip.strip()
    def predicate(p):
        if protocol != "ALL" and p["protocol"] != protocol: return False
        if ip and ip not in (p.get("src_ip") or "") and ip not in (p.get("dst_ip") or ""): return False
        return True
    return predicate
