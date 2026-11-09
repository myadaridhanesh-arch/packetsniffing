import sqlite3
from pathlib import Path

class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
          id INTEGER PRIMARY KEY, timestamp REAL, length INTEGER, protocol TEXT,
          src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
          src_mac TEXT, dst_mac TEXT, tcp_flags TEXT, info TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY, timestamp REAL, severity TEXT, rule TEXT,
          source TEXT, message TEXT
        );
        """)
        self.conn.commit()

    def reset(self):
        self.conn.execute("DELETE FROM packets")
        self.conn.execute("DELETE FROM alerts")
        self.conn.commit()

    def add_packet(self, p):
        self.conn.execute("""INSERT INTO packets
        (timestamp,length,protocol,src_ip,dst_ip,src_port,dst_port,src_mac,dst_mac,tcp_flags,info)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        tuple(p.get(k) for k in ("timestamp","length","protocol","src_ip","dst_ip",
                                  "src_port","dst_port","src_mac","dst_mac","tcp_flags","info")))

    def add_alert(self, a):
        self.conn.execute("INSERT INTO alerts(timestamp,severity,rule,source,message) VALUES(?,?,?,?,?)",
                          (a["timestamp"],a["severity"],a["rule"],a["source"],a["message"]))
    def commit(self): self.conn.commit()
    def rows(self, sql, args=()): return [dict(r) for r in self.conn.execute(sql,args).fetchall()]
    def close(self): self.conn.close()
