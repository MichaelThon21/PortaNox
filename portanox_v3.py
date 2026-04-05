#!/usr/bin/env python3
"""
PortaNox v3.0 — Professional Secure LAN Chat
═════════════════════════════════════════════
Single file · Zero external dependencies · Python 3.7+

HOW IT WORKS:
  • Run this on your laptop/server: python portanox_v3.py
  • Your laptop IP becomes the ADMIN identity automatically
  • Anyone on the same network opens http://<your-ip>:5000/ in their browser
  • Admin panel auto-unlocks when accessing from the server machine

SECURITY MODEL:
  • Admin (server IP) approves/denies all join requests
  • Groups: PIN-protected, creator is owner and manages membership
  • Private chat: PIN-protected 1-on-1, encrypted in browser
  • Admin manages users (kick/ban/mute) but NEVER sees chat content
  • No idle timeouts — connections stay alive as long as browser is open

Usage:
    python portanox_v3.py                    # port 5000
    python portanox_v3.py --port 8080
    python portanox_v3.py --open             # skip approval (demo mode)
"""

import socket, threading, time, os, json, base64, hashlib
import secrets, re, argparse, queue, struct
from datetime import datetime
from pathlib import Path

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
DEFAULT_PORT  = 5000
WS_MAGIC      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_PUB_HIST  = 200
MAX_GRP_HIST  = 100
MAX_LOG       = 800
MAX_FILE_MB   = 15
ALLOWED_EXT   = {".jpg",".jpeg",".png",".gif",".webp",
                 ".pdf",".zip",".mp4",".mp3",".txt",".docx"}
USERNAME_RE   = re.compile(r"^[a-zA-Z0-9_\-]{2,24}$")
CODE_RE       = re.compile(r"^[A-Za-z0-9]{4,12}$")
HIST_FILE     = "pnox_history.json"
GRP_DIR       = "pnox_groups"
BAN_FILE      = "pnox_banned.json"

# ══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET PROTOCOL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: raise ConnectionError("closed")
        buf += c
    return buf

def ws_handshake(sock, key):
    accept = base64.b64encode(
        hashlib.sha1((key + WS_MAGIC).encode()).digest()
    ).decode()
    sock.sendall((
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n"
    ).encode())

def ws_recv(sock):
    try:
        b0, b1 = _exact(sock, 2)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        plen   = b1 & 0x7F
        if plen == 126: plen = int.from_bytes(_exact(sock, 2), "big")
        elif plen == 127: plen = int.from_bytes(_exact(sock, 8), "big")
        mask = _exact(sock, 4) if masked else None
        data = bytearray(_exact(sock, plen))
        if mask:
            for i in range(plen): data[i] ^= mask[i % 4]
        return opcode, bytes(data)
    except: return None, None

def ws_send(sock, data, opcode=1):
    if isinstance(data, str): data = data.encode()
    n = len(data)
    hdr = bytearray([0x80 | opcode])
    if n < 126:     hdr.append(n)
    elif n < 65536: hdr += bytes([126]) + n.to_bytes(2, "big")
    else:           hdr += bytes([127]) + n.to_bytes(8, "big")
    try: sock.sendall(bytes(hdr) + data); return True
    except: return False

def wsj(sock, obj): return ws_send(sock, json.dumps(obj))

def read_http_request(sock):
    buf = b""
    sock.settimeout(15)
    try:
        while b"\r\n\r\n" not in buf:
            c = sock.recv(8192)
            if not c: return None, None, {}, b""
            buf += c
    except: return None, None, {}, b""
    finally: sock.settimeout(None)
    hdr_raw, _, body = buf.partition(b"\r\n\r\n")
    try:
        lines = hdr_raw.decode("utf-8", "replace").split("\r\n")
        p = lines[0].split(" ", 2)
        method, path = p[0].upper(), p[1] if len(p) > 1 else "/"
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        clen = int(hdrs.get("content-length", 0))
        while len(body) < clen:
            c = sock.recv(min(65536, clen - len(body)))
            if not c: break
            body += c
        return method, path, hdrs, body
    except: return None, None, {}, b""

def http_resp(sock, code, ctype, body, extra_headers=""):
    if isinstance(body, str): body = body.encode()
    h = (f"HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\n"
         f"Content-Length: {len(body)}\r\n"
         "Access-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\n"
         f"{extra_headers}\r\n")
    try: sock.sendall(h.encode() + body)
    except: pass

def http_json(sock, data, code="200 OK"):
    http_resp(sock, code, "application/json", json.dumps(data))

def get_local_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."): ips.add(ip)
    except: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ips.add(s.getsockname()[0]); s.close()
    except: pass
    ips.discard("127.0.0.1")
    return sorted(ips) or ["127.0.0.1"]

# ══════════════════════════════════════════════════════════════════════════════
#  SERVER STATE
# ══════════════════════════════════════════════════════════════════════════════
class State:
    def __init__(self, open_mode=False, port=DEFAULT_PORT):
        self.lock       = threading.RLock()
        self.clients    = {}   # sid → ClientRecord
        self.pending    = {}   # sock → PendingRecord
        self.banned     = {}   # ip  → until_ts (0 = permanent)
        self.groups     = {}   # name → GroupRecord
        self.pub_hist   = []
        self.logs       = []
        self.sse_q      = []
        self.open_mode  = open_mode
        self.server_ips = set(get_local_ips()) | {"127.0.0.1"}
        self.start_time = time.time()
        self.msg_count  = 0
        self.port       = port
        self._load()

    class ClientRecord:
        def __init__(self, sid, sock, username, ip, is_admin=False):
            self.sid       = sid
            self.sock      = sock
            self.username  = username
            self.ip        = ip
            self.is_admin  = is_admin
            self.muted     = False
            self.mute_end  = 0
            self.joined_at = datetime.now().strftime("%H:%M:%S")

        def is_muted(self): return self.muted and time.time() < self.mute_end
        def as_dict(self):
            return {"sid":self.sid,"username":self.username,"ip":self.ip,
                    "is_admin":self.is_admin,"muted":self.is_muted(),
                    "joined":self.joined_at}

    class GroupRecord:
        def __init__(self, name, pin, owner_sid, owner_name):
            self.name       = name
            self.pin        = pin
            self.owner_sid  = owner_sid
            self.owner_name = owner_name
            self.members    = {owner_sid}  # set of sids
            self.created_at = datetime.now().strftime("%H:%M:%S")

    def _load(self):
        if os.path.exists(BAN_FILE):
            try:
                with open(BAN_FILE) as f: self.banned = json.load(f)
            except: pass
        if os.path.exists(HIST_FILE):
            try:
                with open(HIST_FILE) as f: self.pub_hist = json.load(f)
            except: pass
        Path(GRP_DIR).mkdir(exist_ok=True)

    def _save_banned(self):
        try:
            with open(BAN_FILE,"w") as f: json.dump(self.banned, f)
        except: pass

    def _save_hist(self):
        try:
            with open(HIST_FILE,"w") as f:
                json.dump(self.pub_hist[-MAX_PUB_HIST:], f)
        except: pass

    # ── Logging ──────────────────────────────────────────────────────────────
    def log(self, msg, alert=False):
        ts = datetime.now().strftime("%H:%M:%S")
        e  = {"time": ts, "msg": msg, "alert": alert}
        with self.lock:
            self.logs.append(e)
            if len(self.logs) > MAX_LOG: self.logs.pop(0)
        tag = "⚠ " if alert else "  "
        print(f"[{ts}]{tag}{msg}")
        self._sse({"type":"log","data":e})

    # ── SSE broadcast ─────────────────────────────────────────────────────────
    def _sse(self, data):
        payload = f"data: {json.dumps(data)}\n\n"
        with self.lock:
            dead = []
            for q in self.sse_q:
                try: q.put_nowait(payload)
                except: dead.append(q)
            for q in dead:
                try: self.sse_q.remove(q)
                except: pass

    # ── Queries ───────────────────────────────────────────────────────────────
    def is_banned(self, ip):
        with self.lock:
            u = self.banned.get(ip, -1)
            if u == -1: return False
            if u == 0:  return True   # permanent
            return time.time() < u

    def is_admin_ip(self, ip):
        return ip in self.server_ips

    def get_stats(self):
        now = time.time()
        with self.lock:
            return {
                "active":   len(self.clients),
                "pending":  len(self.pending),
                "banned":   len(self.banned),
                "groups":   len(self.groups),
                "messages": self.msg_count,
                "uptime":   int(now - self.start_time),
                "open":     self.open_mode,
                "port":     self.port,
            }

    def get_users_list(self):
        with self.lock:
            return [c.as_dict() for c in self.clients.values()]

    def get_pending_list(self):
        with self.lock:
            return [{"username":v["username"],"ip":v["ip"],"at":v["at"]}
                    for v in self.pending.values()]

    def get_banned_list(self):
        now = time.time()
        with self.lock:
            out = []
            for ip, until in self.banned.items():
                if until == 0: out.append({"ip":ip,"remaining":-1,"permanent":True})
                elif until > now: out.append({"ip":ip,"remaining":int(until-now),"permanent":False})
            return out

    def get_groups_list(self):
        with self.lock:
            out = []
            for g in self.groups.values():
                members = [self.clients[s].username
                           for s in g.members if s in self.clients]
                out.append({
                    "name": g.name, "owner": g.owner_name,
                    "count": len(members), "members": members,
                    "created": g.created_at,
                })
            return out

    # ── Admin actions ─────────────────────────────────────────────────────────
    def approve(self, username):
        with self.lock:
            for sock, v in list(self.pending.items()):
                if v["username"] == username:
                    v["result"] = "approved"; v["event"].set(); return True
        return False

    def deny(self, username):
        with self.lock:
            for sock, v in list(self.pending.items()):
                if v["username"] == username:
                    v["result"] = "denied"; v["event"].set(); return True
        return False

    def kick(self, sid):
        with self.lock: c = self.clients.get(sid)
        if not c: return False
        wsj(c.sock, {"type":"kicked","message":"You have been removed by admin."})
        try: c.sock.close()
        except: pass
        return True

    def ban(self, ip, duration=0):
        """duration=0 means permanent"""
        until = 0 if duration == 0 else time.time() + duration
        with self.lock: self.banned[ip] = until
        self._save_banned()
        dur_str = "permanently" if duration == 0 else f"for {duration}s"
        self.log(f"[BAN] {ip} banned {dur_str}", alert=True)
        # Kick all from that IP
        with self.lock:
            victims = [c for c in self.clients.values() if c.ip == ip]
        for c in victims:
            wsj(c.sock, {"type":"kicked","message":"Your IP has been banned."})
            try: c.sock.close()
            except: pass
        self._sse({"type":"update"})

    def unban(self, ip):
        with self.lock: self.banned.pop(ip, None)
        self._save_banned()
        self.log(f"[UNBAN] {ip}")
        self._sse({"type":"update"})

    def mute(self, sid, minutes):
        with self.lock: c = self.clients.get(sid)
        if not c: return False
        c.muted   = True
        c.mute_end= time.time() + minutes * 60
        wsj(c.sock, {"type":"server_msg","level":"warn",
                     "message":f"You have been muted for {minutes} minute(s)."})
        self.log(f"[MUTE] {c.username} for {minutes}m")
        return True

    def unmute(self, sid):
        with self.lock: c = self.clients.get(sid)
        if not c: return False
        c.muted = False; c.mute_end = 0
        wsj(c.sock, {"type":"server_msg","level":"ok","message":"You have been unmuted."})
        return True

    def admin_broadcast(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        pkt = {"type":"public","from":"📢 SERVER","message":message,
               "timestamp":ts,"is_admin":True}
        self.broadcast(pkt)
        self.log(f"[BROADCAST] {message}")

    # ── Socket helpers ────────────────────────────────────────────────────────
    def broadcast(self, msg, excl_sid=None):
        with self.lock:
            targets = [(s, c.sock) for s, c in self.clients.items() if s != excl_sid]
        for _, sock in targets: wsj(sock, msg)

    def send_to_sid(self, sid, msg):
        with self.lock: c = self.clients.get(sid)
        if c: return wsj(c.sock, msg)
        return False

    def send_to_username(self, username, msg):
        with self.lock:
            for c in self.clients.values():
                if c.username == username:
                    return wsj(c.sock, msg)
        return False

    def send_to_group(self, gname, excl_sid, msg):
        with self.lock:
            g = self.groups.get(gname)
            if not g: return
            targets = [(s, self.clients[s].sock)
                       for s in g.members if s in self.clients and s != excl_sid]
        for _, sock in targets: wsj(sock, msg)

    def send_pub_history(self, sock):
        with self.lock: hist = list(self.pub_hist[-60:])
        for m in hist:
            wsj(sock, m)

    def send_grp_history(self, gname, sock):
        p = Path(GRP_DIR) / f"{gname}.json"
        if not p.exists(): return
        try:
            with open(p) as f: hist = json.load(f)
            for entry in hist[-30:]:
                wsj(sock, {"type":"group_history","group":gname,**entry})
        except: pass

    def save_grp_msg(self, gname, sender, content, ts):
        p = Path(GRP_DIR) / f"{gname}.json"
        try:
            hist = []
            if p.exists():
                with open(p) as f: hist = json.load(f)
            hist.append({"from":sender,"content":content,"timestamp":ts})
            hist = hist[-MAX_GRP_HIST:]
            with open(p,"w") as f: json.dump(hist, f)
        except: pass

    def remove_client(self, sid):
        with self.lock:
            c = self.clients.pop(sid, None)
            if not c: return
            for g in self.groups.values():
                g.members.discard(sid)
        ts = datetime.now().strftime("%H:%M:%S")
        self.broadcast({"type":"user_left","username":c.username,"timestamp":ts})
        self.log(f"[LEAVE] {c.username} ({c.ip})")
        self._sse({"type":"update"})
        try: c.sock.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET CLIENT HANDLER
# ══════════════════════════════════════════════════════════════════════════════
def handle_ws(sock, addr, state: State):
    ip  = addr[0]
    sid = None
    try:
        # ── Handshake — expect JOIN ───────────────────────────────────────────
        opcode, raw = ws_recv(sock)
        if opcode != 1: return
        msg = json.loads(raw)
        if msg.get("type") != "join": return

        username = msg.get("username", "").strip()
        if not username or not USERNAME_RE.match(username):
            wsj(sock, {"type":"error","message":
                "Username must be 2–24 chars, letters/digits/underscore/hyphen only."}); return

        # Duplicate check
        with state.lock:
            taken = (any(c.username == username for c in state.clients.values()) or
                     any(v["username"] == username for v in state.pending.values()))
        if taken:
            wsj(sock, {"type":"error","message":"That username is already taken."}); return

        # Banned?
        if state.is_banned(ip):
            wsj(sock, {"type":"error","message":"Your IP address is banned."}); return

        is_admin = state.is_admin_ip(ip)

        # ── Approval flow ─────────────────────────────────────────────────────
        if not state.open_mode and not is_admin:
            event  = threading.Event()
            record = {"username":username,"ip":ip,"event":event,
                      "result":None,"sock":sock,"at":datetime.now().strftime("%H:%M")}
            with state.lock: state.pending[sock] = record
            wsj(sock, {"type":"waiting",
                        "message":"Your join request has been sent to the admin. Please wait..."})
            state.log(f"[PENDING] {username} from {ip}")
            state._sse({"type":"pending","username":username,"ip":ip})

            event.wait()   # No timeout — wait indefinitely

            with state.lock: res = state.pending.pop(sock, {}).get("result", "denied")
            if res != "approved":
                wsj(sock, {"type":"error","message":"Your join request was denied."}); return
        else:
            # Open mode or admin IP — auto-approve
            pass

        # ── Create session ────────────────────────────────────────────────────
        sid = secrets.token_hex(8)
        client = State.ClientRecord(sid, sock, username, ip, is_admin)
        with state.lock: state.clients[sid] = client

        users = state.get_users_list()
        wsj(sock, {
            "type":     "joined",
            "sid":      sid,
            "username": username,
            "is_admin": is_admin,
            "users":    users,
        })
        ts = datetime.now().strftime("%H:%M:%S")
        state.broadcast({"type":"user_joined","username":username,"ip":ip,
                          "is_admin":is_admin,"timestamp":ts}, excl_sid=sid)
        state.log(f"[JOIN] {username} ({ip}){' [ADMIN]' if is_admin else ''}")
        state._sse({"type":"update"})
        state.send_pub_history(sock)

        # ── Message loop ──────────────────────────────────────────────────────
        while True:
            opcode, raw = ws_recv(sock)
            if opcode is None or opcode == 8: break
            if opcode == 9: ws_send(sock, raw, 10); continue
            if opcode != 1: continue
            try: dispatch(json.loads(raw), sock, sid, state)
            except Exception as e:
                state.log(f"[DISPATCH ERR] {e}")

    except Exception as e:
        if sid: state.log(f"[WS ERR] {e}")
    finally:
        if sid: state.remove_client(sid)
        with state.lock: state.pending.pop(sock, None)
        try: sock.close()
        except: pass


def dispatch(msg, sock, sid, state: State):
    with state.lock: cl = state.clients.get(sid)
    if not cl: return

    mtype  = msg.get("type", "")
    ts     = datetime.now().strftime("%H:%M:%S")
    uname  = cl.username

    # ── Mute gate ─────────────────────────────────────────────────────────────
    SEND_TYPES = {"public","private_msg","group_msg","self_destruct"}
    if mtype in SEND_TYPES and cl.is_muted():
        wsj(sock, {"type":"server_msg","level":"warn",
                   "message":"You are muted and cannot send messages."}); return

    # ── PUBLIC ────────────────────────────────────────────────────────────────
    if mtype == "public":
        text = msg.get("message","").strip()
        if not text: return
        pkt = {"type":"public","from":uname,"message":text,
               "timestamp":ts,"is_admin":cl.is_admin}
        state.broadcast(pkt, excl_sid=sid)
        wsj(sock, {**pkt,"mine":True})
        with state.lock:
            state.pub_hist.append(pkt)
            state.msg_count += 1
            if len(state.pub_hist) > MAX_PUB_HIST: state.pub_hist.pop(0)
        state._save_hist()
        state.log(f"[PUB] {uname}: {text[:60]}")

    # ── PRIVATE (encrypted, server only routes — never reads) ─────────────────
    elif mtype == "private_msg":
        to      = msg.get("to","").strip()
        content = msg.get("content","")   # E2E encrypted blob (server never decrypts)
        if not to or not content: return
        ok = state.send_to_username(to, {
            "type":"private_msg","from":uname,"content":content,"timestamp":ts})
        if ok:
            wsj(sock, {"type":"private_sent","to":to,"timestamp":ts})
            state.msg_count += 1
        else:
            wsj(sock, {"type":"server_msg","level":"warn",
                        "message":f"User '{to}' is not online."})

    # ── SELF-DESTRUCT ─────────────────────────────────────────────────────────
    elif mtype == "self_destruct":
        text = msg.get("message","").strip()
        secs = max(5, min(int(msg.get("secs",30)), 600))
        if not text: return
        pkt = {"type":"self_destruct","from":uname,"message":text,
               "secs":secs,"timestamp":ts}
        state.broadcast(pkt, excl_sid=sid)
        wsj(sock, {**pkt,"mine":True})
        state.msg_count += 1

    # ── FILE ──────────────────────────────────────────────────────────────────
    elif mtype == "file_send":
        fname   = msg.get("filename","").strip()
        fsize   = int(msg.get("filesize",0))
        content = msg.get("content","")  # base64
        targets = msg.get("targets",[])
        ext     = Path(fname).suffix.lower()
        if ext not in ALLOWED_EXT:
            wsj(sock, {"type":"server_msg","level":"warn",
                        "message":f"File type '{ext}' is not allowed."}); return
        if fsize > MAX_FILE_MB * 1024 * 1024:
            wsj(sock, {"type":"server_msg","level":"warn",
                        "message":f"File too large (max {MAX_FILE_MB}MB)."}); return
        pkt = {"type":"file_recv","from":uname,"filename":fname,
               "filesize":fsize,"content":content,"timestamp":ts}
        sent = 0
        if targets:
            for t in targets:
                if state.send_to_username(t, pkt): sent += 1
        else:
            state.broadcast(pkt, excl_sid=sid); sent = -1
        wsj(sock, {"type":"file_sent","filename":fname,
                    "recipients":"everyone" if sent < 0 else sent})
        state.log(f"[FILE] {uname} → {targets or 'all'}: {fname} ({fsize}B)")

    # ── GROUP CREATE ──────────────────────────────────────────────────────────
    elif mtype == "group_create":
        gname = msg.get("group","").strip()
        pin   = msg.get("pin","").strip()
        if not gname or len(gname) > 32:
            wsj(sock, {"type":"server_msg","level":"warn","message":"Invalid group name."}); return
        if not CODE_RE.match(pin):
            wsj(sock, {"type":"server_msg","level":"warn",
                        "message":"PIN must be 4–12 alphanumeric characters."}); return
        with state.lock:
            if gname in state.groups:
                wsj(sock, {"type":"server_msg","level":"warn",
                            "message":f"Group '{gname}' already exists."}); return
            g = State.GroupRecord(gname, pin, sid, uname)
            state.groups[gname] = g
        wsj(sock, {"type":"group_joined","group":gname,"owner":uname,
                    "is_owner":True,"members":[uname]})
        state.log(f"[GROUP+] {uname} created '{gname}'")
        state._sse({"type":"update"})
        state.send_grp_history(gname, sock)

    # ── GROUP JOIN ────────────────────────────────────────────────────────────
    elif mtype == "group_join":
        gname = msg.get("group","").strip()
        pin   = msg.get("pin","").strip()
        with state.lock:
            g = state.groups.get(gname)
            if not g:
                wsj(sock, {"type":"server_msg","level":"warn",
                            "message":f"Group '{gname}' does not exist."}); return
            if g.pin != pin:
                wsj(sock, {"type":"server_msg","level":"warn","message":"Incorrect PIN."}); return
            if sid in g.members:
                wsj(sock, {"type":"server_msg","level":"warn",
                            "message":f"You are already in '{gname}'."}); return
            g.members.add(sid)
            is_owner = (g.owner_sid == sid)
            members  = [state.clients[s].username for s in g.members if s in state.clients]
            owner    = g.owner_name
        wsj(sock, {"type":"group_joined","group":gname,"owner":owner,
                    "is_owner":is_owner,"members":members})
        # Notify existing members
        state.send_to_group(gname, sid, {
            "type":"group_event","group":gname,"event":"joined","username":uname,
            "timestamp":ts})
        state.log(f"[GROUP] {uname} joined '{gname}'")
        state.send_grp_history(gname, sock)

    # ── GROUP LEAVE ───────────────────────────────────────────────────────────
    elif mtype == "group_leave":
        gname = msg.get("group","").strip()
        with state.lock:
            g = state.groups.get(gname)
            if g:
                g.members.discard(sid)
                if not g.members and g.owner_sid == sid:
                    del state.groups[gname]
                    state._sse({"type":"update"})
        wsj(sock, {"type":"group_left","group":gname})
        state.send_to_group(gname, sid, {
            "type":"group_event","group":gname,"event":"left","username":uname,"timestamp":ts})

    # ── GROUP KICK (owner only) ───────────────────────────────────────────────
    elif mtype == "group_kick":
        gname      = msg.get("group","").strip()
        target_u   = msg.get("target","").strip()
        with state.lock:
            g = state.groups.get(gname)
            if not g or g.owner_sid != sid:
                wsj(sock, {"type":"server_msg","level":"warn",
                            "message":"Only the group owner can remove members."}); return
            target_sid = next((s for s,c in state.clients.items()
                                if c.username == target_u and s in g.members), None)
            if not target_sid:
                wsj(sock, {"type":"server_msg","level":"warn","message":"Member not found."}); return
            g.members.discard(target_sid)
            target_sock = state.clients[target_sid].sock
        wsj(target_sock, {"type":"group_left","group":gname,
                           "reason":f"You were removed from '{gname}' by the owner."})
        wsj(sock, {"type":"server_msg","level":"ok","message":f"{target_u} removed from {gname}."})
        state.send_to_group(gname, sid, {
            "type":"group_event","group":gname,"event":"kicked","username":target_u,"timestamp":ts})

    # ── GROUP MESSAGE ─────────────────────────────────────────────────────────
    elif mtype == "group_msg":
        gname   = msg.get("group","").strip()
        content = msg.get("content","")   # E2E encrypted — server doesn't read
        with state.lock:
            g = state.groups.get(gname)
            if not g or sid not in g.members:
                wsj(sock, {"type":"server_msg","level":"warn","message":"Not a member."}); return
        pkt = {"type":"group_msg","group":gname,"from":uname,"content":content,"timestamp":ts}
        state.send_to_group(gname, sid, pkt)
        wsj(sock, {**pkt,"mine":True})
        state.save_grp_msg(gname, uname, content, ts)
        state.msg_count += 1

    # ── GROUP LIST ────────────────────────────────────────────────────────────
    elif mtype == "group_list":
        wsj(sock, {"type":"group_list_result","groups":state.get_groups_list()})

    # ── GROUP MEMBERS ─────────────────────────────────────────────────────────
    elif mtype == "group_members":
        gname = msg.get("group","").strip()
        with state.lock:
            g = state.groups.get(gname)
            if not g or sid not in g.members:
                wsj(sock, {"type":"server_msg","level":"warn","message":"Not a member."}); return
            members  = [state.clients[s].username for s in g.members if s in state.clients]
            is_owner = g.owner_sid == sid
        wsj(sock, {"type":"group_members_result","group":gname,
                    "members":members,"is_owner":is_owner})

    # ── LIST USERS ────────────────────────────────────────────────────────────
    elif mtype == "list_users":
        wsj(sock, {"type":"user_list","users":state.get_users_list()})

    # ── PING ──────────────────────────────────────────────────────────────────
    elif mtype == "ping":
        wsj(sock, {"type":"pong","ts":ts})

    elif mtype == "leave":
        pass  # handled by connection close


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP / ADMIN API HANDLER
# ══════════════════════════════════════════════════════════════════════════════
def handle_http(sock, addr, method, path, hdrs, body, state: State):
    ip    = addr[0]
    clean = path.split("?")[0].rstrip("/") or "/"

    # ── SSE endpoint ──────────────────────────────────────────────────────────
    if clean == "/events":
        q = queue.Queue(maxsize=400)
        with state.lock: state.sse_q.append(q)
        sock.sendall((
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\nConnection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\nX-Accel-Buffering: no\r\n\r\n"
        ).encode())
        try:
            sock.sendall(f"data: {json.dumps({'type':'hello'})}\n\n".encode())
            while True:
                try:    sock.sendall(q.get(timeout=25).encode())
                except queue.Empty: sock.sendall(b": ka\n\n")
        except: pass
        finally:
            with state.lock:
                try: state.sse_q.remove(q)
                except: pass
        return

    # ── Public API (no auth) ──────────────────────────────────────────────────
    if method == "GET":
        if clean == "/api/stats":    http_json(sock, state.get_stats()); return
        if clean == "/api/users":    http_json(sock, state.get_users_list()); return
        if clean == "/api/groups":   http_json(sock, state.get_groups_list()); return
        if clean == "/api/pending":  http_json(sock, state.get_pending_list()); return
        if clean == "/api/banned":   http_json(sock, state.get_banned_list()); return
        if clean == "/api/logs":
            with state.lock: logs = state.logs[-300:]
            http_json(sock, logs); return
        if clean == "/":
            http_resp(sock, "200 OK", "text/html; charset=utf-8", CLIENT_HTML); return
        if clean == "/admin":
            # Admin panel only accessible from server IP
            if not state.is_admin_ip(ip):
                http_resp(sock, "403 Forbidden", "text/html",
                          "<h1>403 — Admin panel only accessible from the server machine.</h1>"); return
            http_resp(sock, "200 OK", "text/html; charset=utf-8", ADMIN_HTML); return

    if method == "POST":
        try: data = json.loads(body)
        except: data = {}

        # Admin-only endpoints — require server IP
        admin_routes = {"/api/approve","/api/deny","/api/kick","/api/ban",
                        "/api/unban","/api/mute","/api/unmute","/api/broadcast","/api/shutdown"}
        if clean in admin_routes and not state.is_admin_ip(ip):
            http_json(sock, {"error":"Forbidden — admin only"}, "403 Forbidden"); return

        if clean == "/api/approve":
            ok = state.approve(data.get("username",""))
            if ok: state.log(f"[APPROVE] {data.get('username','')} approved")
            http_json(sock, {"ok":ok}); state._sse({"type":"update"}); return

        if clean == "/api/deny":
            ok = state.deny(data.get("username",""))
            if ok: state.log(f"[DENY] {data.get('username','')} denied")
            http_json(sock, {"ok":ok}); state._sse({"type":"update"}); return

        if clean == "/api/kick":
            ok = state.kick(data.get("sid",""))
            if ok: state.log(f"[KICK] {data.get('sid','')}")
            http_json(sock, {"ok":ok}); state._sse({"type":"update"}); return

        if clean == "/api/ban":
            ip_to_ban = data.get("ip","")
            duration  = int(data.get("duration", 0))  # 0 = permanent
            state.ban(ip_to_ban, duration)
            http_json(sock, {"ok":True}); return

        if clean == "/api/unban":
            state.unban(data.get("ip",""))
            http_json(sock, {"ok":True}); return

        if clean == "/api/mute":
            ok = state.mute(data.get("sid",""), int(data.get("minutes",5)))
            http_json(sock, {"ok":ok}); state._sse({"type":"update"}); return

        if clean == "/api/unmute":
            ok = state.unmute(data.get("sid",""))
            http_json(sock, {"ok":ok}); state._sse({"type":"update"}); return

        if clean == "/api/broadcast":
            msg = data.get("message","").strip()
            if msg: state.admin_broadcast(msg)
            http_json(sock, {"ok":True}); return

        if clean == "/api/shutdown":
            http_json(sock, {"ok":True})
            time.sleep(0.3)
            os._exit(0)

    http_resp(sock, "404 Not Found", "text/plain", "Not found")


# ══════════════════════════════════════════════════════════════════════════════
#  CONNECTION DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════
def handle_conn(sock, addr, state: State):
    method, path, hdrs, body = read_http_request(sock)
    if not method:
        try: sock.close()
        except: pass
        return
    if (hdrs.get("upgrade","").lower() == "websocket"
            and path.startswith("/ws")):
        key = hdrs.get("sec-websocket-key","")
        if key:
            ws_handshake(sock, key)
            handle_ws(sock, addr, state)
        else:
            try: sock.close()
            except: pass
    else:
        handle_http(sock, addr, method, path, hdrs, body, state)
        try: sock.close()
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED HTML — CLIENT (served to every browser)
# ══════════════════════════════════════════════════════════════════════════════
CLIENT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#080f1c">
<title>PortaNox — Secure Chat</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;-webkit-text-size-adjust:100%}
:root{
  --bg:#080f1c;--surface:#0d1829;--card:#111f35;--raised:#162740;--hover:#1a2f4a;
  --b1:#1e3450;--b2:#254060;
  --blue:#3b9eff;--green:#22d3a0;--purple:#9d6eff;--amber:#f59e0b;--red:#ef4444;--teal:#06b6d4;
  --text:#dce8f5;--text2:#6b90b0;--text3:#324d66;
  --r:12px;--r-sm:8px;--r-lg:16px;
  --font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace;
  --safe-bottom:env(safe-area-inset-bottom,0px);
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;overflow:hidden;line-height:1.5}

/* Scrollbars */
::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-thumb{background:var(--b1);border-radius:2px}

/* ── SCREENS ── */
.screen{position:fixed;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:10;transition:opacity .3s,transform .3s}
.screen.hidden{opacity:0;pointer-events:none;transform:scale(.98)}

/* Login */
#scr-login{background:var(--bg)}
#scr-login::before{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse 80% 60% at 50% -10%,rgba(59,158,255,.1) 0%,transparent 70%),
             radial-gradient(ellipse 50% 40% at 90% 90%,rgba(157,110,255,.06) 0%,transparent 60%);
  pointer-events:none}
.login-box{width:min(400px,94vw);display:flex;flex-direction:column;gap:0;position:relative}
.login-brand{text-align:center;padding:0 0 32px}
.login-brand-icon{width:56px;height:56px;border-radius:14px;
  background:linear-gradient(135deg,var(--blue),var(--teal));
  display:flex;align-items:center;justify-content:center;font-size:26px;
  margin:0 auto 14px;box-shadow:0 0 40px rgba(59,158,255,.3)}
.login-brand h1{font-size:24px;font-weight:700;letter-spacing:-.5px;color:var(--text)}
.login-brand p{color:var(--text2);font-size:12px;margin-top:4px;letter-spacing:.3px}
.lcard{background:var(--surface);border:1px solid var(--b1);border-radius:var(--r-lg);padding:24px;display:flex;flex-direction:column;gap:16px}
.lcard::before{content:'';position:absolute;top:0;left:24px;right:24px;height:1px;
  background:linear-gradient(90deg,transparent,rgba(59,158,255,.4),transparent);border-radius:1px}
.field label{display:block;font-size:11px;font-weight:600;color:var(--text2);letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px}
.field input{width:100%;background:var(--card);border:1.5px solid var(--b1);border-radius:var(--r-sm);
  padding:11px 14px;color:var(--text);font-family:var(--font);font-size:14px;outline:none;transition:.2s}
.field input:focus{border-color:var(--blue);background:var(--raised)}
.field input::placeholder{color:var(--text3)}
.conn-btn{background:linear-gradient(135deg,var(--blue),var(--teal));
  border:none;border-radius:var(--r-sm);padding:13px;width:100%;
  color:#fff;font-family:var(--font);font-size:14px;font-weight:600;cursor:pointer;
  letter-spacing:.2px;transition:.2s;display:flex;align-items:center;justify-content:center;gap:8px}
.conn-btn:hover:not(:disabled){filter:brightness(1.08);transform:translateY(-1px)}
.conn-btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
.lmsg{text-align:center;font-size:12px;color:var(--text2);min-height:18px}
.lmsg.err{color:var(--red)}.lmsg.ok{color:var(--green)}
.enc-chip{display:flex;align-items:center;gap:6px;padding:8px 12px;
  background:rgba(34,211,160,.06);border:1px solid rgba(34,211,160,.15);
  border-radius:var(--r-sm);font-size:11px;color:var(--text2)}

/* Waiting */
#scr-wait{background:var(--bg);gap:20px}
.wait-ring{width:72px;height:72px;border-radius:50%;border:2px solid transparent;
  border-top-color:var(--blue);animation:spin 1s linear infinite;
  box-shadow:0 0 30px rgba(59,158,255,.2)}
@keyframes spin{to{transform:rotate(360deg)}}
.wait-title{font-size:18px;font-weight:600;color:var(--text)}
.wait-sub{font-size:13px;color:var(--text2);text-align:center;max-width:280px}

/* ── APP LAYOUT ── */
#app{position:fixed;inset:0;display:flex;flex-direction:column;opacity:0;pointer-events:none;transition:opacity .3s}
#app.active{opacity:1;pointer-events:all}

/* Header */
#hdr{background:var(--surface);border-bottom:1px solid var(--b1);
  padding:0 16px;height:54px;display:flex;align-items:center;gap:10px;flex-shrink:0;z-index:20}
.hdr-logo{font-size:15px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:8px}
.hdr-logo-dot{width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 8px var(--green);flex-shrink:0}
.hdr-logo-dot.off{background:var(--red);box-shadow:0 0 8px var(--red)}
#hdr-right{margin-left:auto;display:flex;align-items:center;gap:6px}
.icon-btn{width:36px;height:36px;border-radius:var(--r-sm);background:var(--card);
  border:1px solid var(--b1);display:flex;align-items:center;justify-content:center;
  cursor:pointer;color:var(--text2);font-size:16px;transition:.15s;user-select:none}
.icon-btn:hover,.icon-btn:active{border-color:var(--blue);color:var(--blue);background:var(--raised)}
.icon-btn.active{border-color:var(--blue);color:var(--blue)}
.hdr-you{font-size:12px;color:var(--text2);max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* Tab bar */
#tabbar{background:var(--surface);border-bottom:1px solid var(--b1);
  display:flex;flex-shrink:0;overflow-x:auto;-webkit-overflow-scrolling:touch}
#tabbar::-webkit-scrollbar{height:0}
.tab{padding:10px 16px;font-size:13px;font-weight:500;color:var(--text2);
  cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;
  transition:.15s;user-select:none;display:flex;align-items:center;gap:5px}
.tab:hover{color:var(--text)}
.tab.on{color:var(--blue);border-bottom-color:var(--blue)}
.t-badge{background:var(--red);color:#fff;border-radius:20px;padding:1px 6px;font-size:10px;font-weight:700}

/* Layout */
#body{display:flex;flex:1;min-height:0;position:relative}

/* Sidebar */
#sidebar{width:220px;background:var(--surface);border-right:1px solid var(--b1);
  display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto;transition:.25s}
@media(max-width:700px){
  #sidebar{position:absolute;top:0;bottom:0;left:0;z-index:15;transform:translateX(-100%)}
  #sidebar.open{transform:translateX(0);box-shadow:4px 0 24px rgba(0,0,0,.4)}
}
.sb-sec{padding:14px 12px 6px;font-size:10px;font-weight:600;color:var(--text3);letter-spacing:.8px;text-transform:uppercase}
.sb-item{padding:8px 12px;display:flex;align-items:center;gap:9px;border-radius:var(--r-sm);
  margin:2px 6px;cursor:pointer;transition:.15s;user-select:none}
.sb-item:hover{background:var(--hover)}
.sb-item.active{background:var(--raised);color:var(--blue)}
.sb-avatar{width:28px;height:28px;border-radius:7px;display:flex;align-items:center;
  justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
.sb-name{font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.sb-badge{font-size:10px;padding:1px 6px;border-radius:20px}
.you-tag{font-size:10px;color:var(--green);font-weight:600;background:rgba(34,211,160,.1);
  padding:1px 5px;border-radius:4px}
.admin-tag{font-size:10px;color:var(--amber);background:rgba(245,158,11,.1);padding:1px 5px;border-radius:4px}
.muted-tag{font-size:10px;color:var(--red);background:rgba(239,68,68,.1);padding:1px 5px;border-radius:4px}

/* Main content */
#main{flex:1;display:flex;flex-direction:column;min-width:0;position:relative}

/* Panels */
.panel{display:none;flex:1;flex-direction:column;min-height:0;position:relative}
.panel.on{display:flex}

/* Messages */
.msgs{flex:1;overflow-y:auto;padding:14px 14px 4px;display:flex;flex-direction:column;gap:5px;
  -webkit-overflow-scrolling:touch}
.day-div{text-align:center;font-size:11px;color:var(--text3);margin:8px 0;letter-spacing:.3px}

/* Bubbles */
.msg{display:flex;flex-direction:column;max-width:78%;animation:bubbleIn .2s ease}
@keyframes bubbleIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.msg.mine{align-self:flex-end;align-items:flex-end}
.msg.theirs{align-self:flex-start;align-items:flex-start}
.msg.sys{align-self:center;align-items:center;max-width:90%}
.msg-who{display:flex;align-items:center;gap:5px;margin-bottom:3px}
.msg-from{font-size:11px;font-weight:600}
.msg-time{font-size:10px;color:var(--text3)}
.bbl{padding:9px 13px;border-radius:14px;word-break:break-word;line-height:1.55;font-size:13.5px;position:relative}
.mine .bbl{background:linear-gradient(135deg,#0e2d58,#122f5e);border:1px solid #1e4a88;border-radius:14px 14px 4px 14px}
.theirs .bbl{background:var(--raised);border:1px solid var(--b1);border-radius:14px 14px 14px 4px}
.sys .bbl{background:rgba(255,255,255,.03);border:1px solid var(--b1);color:var(--text2);font-size:12px;border-radius:8px;padding:5px 12px}
.bbl.priv{border-left:3px solid var(--purple);background:rgba(157,110,255,.08)}
.bbl.grp{border-left:3px solid var(--amber);background:rgba(245,158,11,.06)}
.bbl.sd{border-left:3px solid var(--red);background:rgba(239,68,68,.07)}
.bbl.admin-msg{border-left:3px solid var(--blue);background:rgba(59,158,255,.07)}
.enc-mark{font-size:10px;color:var(--purple);display:flex;align-items:center;gap:3px;margin-top:3px}
.sd-bar-wrap{height:3px;background:var(--b1);border-radius:2px;margin-top:6px;overflow:hidden}
.sd-bar{height:100%;background:var(--red);border-radius:2px;transition:width .5s linear}
.sd-lbl{font-size:10px;color:var(--red);margin-top:3px}

/* File bubble */
.file-bbl{display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:var(--raised);border:1.5px solid var(--b1);border-radius:12px}
.file-ico{font-size:26px}
.file-info{min-width:0;flex:1}.file-name{font-weight:600;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-sz{font-size:11px;color:var(--text2);margin-top:1px}
.file-dl{font-size:12px;color:var(--blue);cursor:pointer;display:block;margin-top:4px}
.img-thumb{max-width:200px;max-height:150px;border-radius:10px;margin-top:6px;cursor:pointer;display:block}
.typing-row{height:22px;padding:0 16px;font-size:11px;color:var(--text3);font-style:italic}

/* Group header */
.panel-hdr{padding:10px 14px;background:var(--surface);border-bottom:1px solid var(--b1);
  display:flex;align-items:center;gap:8px;flex-shrink:0}
.panel-hdr-title{font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.panel-hdr-sub{font-size:11px;color:var(--text2)}

/* Input bar */
#input-bar{background:var(--surface);border-top:1px solid var(--b1);
  padding:10px 12px;padding-bottom:calc(10px + var(--safe-bottom));flex-shrink:0}
.tools{display:flex;gap:5px;margin-bottom:8px;flex-wrap:wrap}
.tool{padding:4px 10px;border:1.5px solid var(--b1);border-radius:20px;background:var(--card);
  color:var(--text2);font-size:12px;cursor:pointer;transition:.15s;display:flex;align-items:center;gap:4px;
  white-space:nowrap;font-family:var(--font)}
.tool:hover,.tool:active{border-color:var(--blue);color:var(--blue)}
.tool.active-tool{border-color:var(--amber);color:var(--amber);background:rgba(245,158,11,.08)}
.input-row{display:flex;gap:8px;align-items:flex-end}
#msg-in{flex:1;background:var(--card);border:1.5px solid var(--b1);border-radius:22px;
  padding:10px 16px;color:var(--text);font-family:var(--font);font-size:14px;outline:none;
  resize:none;max-height:120px;min-height:42px;line-height:1.45;transition:.2s}
#msg-in:focus{border-color:var(--blue);background:var(--raised)}
#msg-in::placeholder{color:var(--text3)}
.send{width:42px;height:42px;border-radius:50%;
  background:linear-gradient(135deg,var(--blue),var(--teal));
  border:none;display:flex;align-items:center;justify-content:center;
  cursor:pointer;font-size:18px;color:#fff;flex-shrink:0;transition:.2s}
.send:hover{transform:scale(1.08);filter:brightness(1.1)}
.send:active{transform:scale(.95)}
.send:disabled{opacity:.4;transform:none}

/* ── MODALS ── */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:50;
  display:none;align-items:flex-end;justify-content:center;
  backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}
.overlay.show{display:flex}
@media(min-width:520px){.overlay{align-items:center}}
.modal{background:var(--surface);border:1px solid var(--b1);
  width:min(460px,100%);max-height:85vh;display:flex;flex-direction:column;overflow:hidden;
  border-radius:var(--r-lg) var(--r-lg) 0 0;position:relative}
@media(min-width:520px){.modal{border-radius:var(--r-lg)}}
.modal::after{content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(59,158,255,.5),transparent)}
.mhdr{padding:16px 18px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.mhdr h2{font-size:15px;font-weight:700}
.mclose{background:none;border:none;color:var(--text2);font-size:22px;cursor:pointer;
  width:32px;height:32px;display:flex;align-items:center;justify-content:center;border-radius:6px}
.mclose:hover{background:var(--hover);color:var(--text)}
.mbody{padding:18px;overflow-y:auto;display:flex;flex-direction:column;gap:14px;-webkit-overflow-scrolling:touch}
.mfld{display:flex;flex-direction:column;gap:6px}
.mfld label{font-size:11px;font-weight:600;color:var(--text2);letter-spacing:.4px;text-transform:uppercase}
.mfld input,.mfld textarea,.mfld select{background:var(--card);border:1.5px solid var(--b1);
  border-radius:var(--r-sm);padding:10px 12px;color:var(--text);font-family:var(--font);
  font-size:14px;outline:none;width:100%;transition:.2s}
.mfld input:focus,.mfld textarea:focus{border-color:var(--blue);background:var(--raised)}
.mfld textarea{resize:vertical;min-height:80px}
.mfld select option{background:var(--surface)}
.hint{font-size:11px;color:var(--text3)}
.mfoot{padding:14px 18px;border-top:1px solid var(--b1);display:flex;gap:8px;justify-content:flex-end;flex-shrink:0}
.btn{padding:9px 18px;border-radius:var(--r-sm);font-size:13px;font-weight:600;cursor:pointer;
  border:none;font-family:var(--font);transition:.15s}
.btn:hover{filter:brightness(1.1)}
.btn-pri{background:linear-gradient(135deg,var(--blue),var(--teal));color:#fff}
.btn-red{background:var(--red);color:#fff}
.btn-ghost{background:var(--card);border:1.5px solid var(--b1);color:var(--text2)}
.btn-ghost:hover{color:var(--text);border-color:var(--b2)}
.seg{display:flex;gap:4px}
.seg-btn{flex:1;padding:8px;border:1.5px solid var(--b1);border-radius:var(--r-sm);background:var(--card);
  color:var(--text2);font-size:13px;cursor:pointer;font-family:var(--font);transition:.15s}
.seg-btn.on{border-color:var(--blue);color:var(--blue);background:rgba(59,158,255,.1)}
.grp-opt{padding:10px 12px;background:var(--card);border:1.5px solid var(--b1);border-radius:var(--r-sm);
  cursor:pointer;display:flex;align-items:center;gap:8px;transition:.15s;margin-bottom:4px}
.grp-opt:hover,.grp-opt.sel{border-color:var(--blue);background:rgba(59,158,255,.08)}
.grp-opt-name{font-weight:600;flex:1}
.grp-opt-cnt{font-size:11px;color:var(--text2)}
.member-item{padding:8px 10px;background:var(--card);border-radius:var(--r-sm);
  display:flex;align-items:center;gap:8px;margin-bottom:4px}
.member-name{flex:1;font-size:13px;font-weight:500}

/* Drop zone */
.dz{border:2px dashed var(--b1);border-radius:var(--r);padding:30px 20px;text-align:center;
  cursor:pointer;transition:.2s;color:var(--text2)}
.dz:hover,.dz.over{border-color:var(--blue);color:var(--blue);background:rgba(59,158,255,.05)}
.dz-ico{font-size:40px;margin-bottom:8px;display:block}
.dz p{font-size:13px}.dz small{font-size:11px;color:var(--text3);display:block;margin-top:4px}
.file-prev{padding:10px;background:var(--card);border-radius:var(--r-sm);font-size:12px;display:none}

/* Toasts */
#toasts{position:fixed;top:64px;right:12px;z-index:100;display:flex;flex-direction:column;gap:6px;pointer-events:none}
@media(max-width:480px){#toasts{right:8px;left:8px}}
.toast{background:var(--raised);border:1px solid var(--b2);border-left:3px solid var(--blue);
  border-radius:var(--r-sm);padding:10px 14px;animation:tIn .25s ease;
  box-shadow:0 8px 32px rgba(0,0,0,.4);pointer-events:all;cursor:pointer;
  min-width:200px;max-width:320px}
@keyframes tIn{from{opacity:0;transform:translateX(24px)}to{opacity:1}}
.toast.green{border-left-color:var(--green)}.toast.red{border-left-color:var(--red)}.toast.amber{border-left-color:var(--amber)}
.t-title{font-size:12px;font-weight:600;color:var(--text)}
.t-sub{font-size:11px;color:var(--text2);margin-top:2px;word-break:break-word}

/* Private tab inbox */
.inbox-item{padding:12px;background:var(--card);border:1.5px solid var(--b1);border-radius:var(--r);
  margin-bottom:8px;display:flex;flex-direction:column;gap:8px}
.inbox-who{font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px}
.inbox-decode{display:flex;gap:6px}
.inbox-decode input{flex:1;background:var(--raised);border:1.5px solid var(--b1);border-radius:var(--r-sm);
  padding:7px 10px;color:var(--text);font-size:13px;outline:none;font-family:var(--font)}
.inbox-decode input:focus{border-color:var(--purple)}
.inbox-plain{font-size:13px;color:var(--green);padding:8px;background:rgba(34,211,160,.06);
  border-radius:var(--r-sm);display:none;word-break:break-all}

/* Private groups section */
.grp-panel-hdr{padding:10px 14px;background:var(--surface);border-bottom:1px solid var(--b1);
  display:flex;align-items:center;gap:8px;flex-shrink:0}
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;
  flex:1;gap:12px;color:var(--text2);padding:40px 20px;text-align:center}
.empty-state .ei{font-size:48px;opacity:.4}
.empty-state p{font-size:13px}
</style>
</head>
<body>

<!-- Login Screen -->
<div class="screen" id="scr-login">
  <div class="login-box">
    <div class="login-brand">
      <div class="login-brand-icon">⬡</div>
      <h1>PortaNox</h1>
      <p>SECURE · PRIVATE · ENCRYPTED</p>
    </div>
    <div class="lcard">
      <div class="field">
        <label>Username</label>
        <input id="l-user" placeholder="Your display name" maxlength="24" autocomplete="off" spellcheck="false">
      </div>
      <div class="field">
        <label>Server Address <span style="color:var(--text3);text-transform:none;font-weight:400">(leave blank if on same network)</span></label>
        <input id="l-host" placeholder="e.g. 192.168.1.5 or leave blank">
      </div>
      <button class="conn-btn" id="conn-btn" onclick="doConnect()">
        <span id="conn-ico">⬡</span> Connect Securely
      </button>
      <div class="lmsg" id="l-msg">Ready to connect</div>
      <div class="enc-chip">
        <span style="font-size:16px">🔐</span>
        <span id="enc-chip-txt">Private messages encrypted in your browser with AES-256. Server sees no content.</span>
      </div>
    </div>
  </div>
</div>

<!-- Waiting Screen -->
<div class="screen hidden" id="scr-wait">
  <div class="wait-ring"></div>
  <div class="wait-title">Awaiting Admin Approval</div>
  <div class="wait-sub" id="wait-sub">Your request has been sent to the admin. This may take a moment.</div>
  <div style="margin-top:8px;font-size:12px;color:var(--text3)">Page will update automatically</div>
</div>

<!-- Main App -->
<div id="app">
  <!-- Header -->
  <div id="hdr">
    <div class="hdr-logo">
      <div class="hdr-logo-dot" id="conn-dot"></div>
      PortaNox
    </div>
    <div class="hdr-you" id="hdr-you"></div>
    <div id="hdr-right">
      <div class="icon-btn" onclick="toggleSidebar()" title="Users">👥</div>
      <div class="icon-btn" onclick="openModal('m-file')" title="Send File">📎</div>
      <div class="icon-btn" onclick="openModal('m-sd')" title="Expiring Message">💣</div>
    </div>
  </div>

  <!-- Tab bar -->
  <div id="tabbar">
    <div class="tab on" data-tab="pub" onclick="goTab('pub')">💬 Chat</div>
    <div class="tab" data-tab="grp" onclick="goTab('grp')">
      📁 Groups <span class="t-badge" id="grp-badge" style="display:none"></span>
    </div>
    <div class="tab" data-tab="priv" onclick="goTab('priv')">
      🔒 Private <span class="t-badge" id="priv-badge" style="display:none"></span>
    </div>
  </div>

  <!-- Body -->
  <div id="body">
    <!-- Sidebar -->
    <div id="sidebar">
      <div class="sb-sec">Online — <span id="sb-count">0</span></div>
      <div id="sb-users"></div>
      <div class="sb-sec" id="sb-grp-sec" style="display:none;margin-top:4px">My Groups</div>
      <div id="sb-groups"></div>
    </div>

    <!-- Main panels -->
    <div id="main">

      <!-- PUBLIC TAB -->
      <div class="panel on" id="tab-pub">
        <div class="msgs" id="msgs-pub"></div>
        <div class="typing-row" id="typ-pub"></div>
      </div>

      <!-- GROUPS TAB -->
      <div class="panel" id="tab-grp">
        <div class="grp-panel-hdr">
          <span class="panel-hdr-title" id="grp-cur-name">No group selected</span>
          <div style="display:flex;gap:5px">
            <div class="tool" onclick="openModal('m-grp')" style="font-size:12px">+ Join / Create</div>
            <div class="tool" id="grp-members-btn" onclick="openGroupMembers()" style="display:none">👥</div>
            <div class="tool" id="grp-leave-btn" onclick="leaveGroup()" style="display:none;color:var(--red);border-color:var(--red)">Leave</div>
          </div>
        </div>
        <div class="msgs" id="msgs-grp">
          <div class="empty-state">
            <span class="ei">📁</span>
            <p>Join or create a group to start chatting.<br>Groups are PIN-protected and end-to-end encrypted.</p>
          </div>
        </div>
        <div class="typing-row" id="typ-grp"></div>
      </div>

      <!-- PRIVATE TAB -->
      <div class="panel" id="tab-priv">
        <div class="panel-hdr">
          <span class="panel-hdr-title">🔒 Private Messages</span>
          <div class="tool" onclick="openModal('m-priv')">+ New</div>
        </div>
        <div class="msgs" id="msgs-priv">
          <div class="empty-state">
            <span class="ei">🔒</span>
            <p>Private messages are encrypted end-to-end using a shared code.<br>The server never sees the content.</p>
          </div>
        </div>
      </div>

      <!-- Input bar -->
      <div id="input-bar">
        <div class="tools" id="tools-row">
          <div class="tool" onclick="openModal('m-priv')">🔒 Private</div>
          <div class="tool" onclick="openModal('m-grp')">📁 Group</div>
          <div class="tool" onclick="openModal('m-file')">📎 File</div>
          <div class="tool" onclick="openModal('m-sd')">💣 Expiring</div>
        </div>
        <div class="input-row">
          <textarea id="msg-in" placeholder="Message everyone..." rows="1"
            onkeydown="msgKey(event)" oninput="autoGrow(this)"></textarea>
          <button class="send" onclick="sendMsg()" id="send-btn">➤</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Toast container -->
<div id="toasts"></div>

<!-- ── MODALS ── -->

<!-- Private message -->
<div class="overlay" id="m-priv">
  <div class="modal">
    <div class="mhdr"><h2>🔒 Private Message</h2><button class="mclose" onclick="closeModal('m-priv')">✕</button></div>
    <div class="mbody">
      <div class="mfld">
        <label>Send to</label>
        <input id="pm-to" placeholder="Username" list="dl-users">
        <datalist id="dl-users"></datalist>
      </div>
      <div class="mfld">
        <label>Shared Code (4–12 chars)</label>
        <input id="pm-code" placeholder="e.g. mySecret1" maxlength="12" spellcheck="false">
        <div class="hint">Both parties must use the same code. Messages are AES-256 encrypted in the browser.</div>
      </div>
      <div class="mfld">
        <label>Message</label>
        <textarea id="pm-msg" placeholder="Your private message..."></textarea>
      </div>
      <!-- Received inbox -->
      <div id="pm-inbox-sec" style="display:none">
        <div style="font-size:11px;font-weight:600;color:var(--text2);letter-spacing:.4px;text-transform:uppercase;margin-bottom:8px">Received Private Messages</div>
        <div id="pm-inbox"></div>
      </div>
    </div>
    <div class="mfoot">
      <button class="btn btn-ghost" onclick="closeModal('m-priv')">Cancel</button>
      <button class="btn btn-pri" onclick="sendPrivate()">🔒 Send Encrypted</button>
    </div>
  </div>
</div>

<!-- Group -->
<div class="overlay" id="m-grp">
  <div class="modal">
    <div class="mhdr"><h2>📁 Group Chat</h2><button class="mclose" onclick="closeModal('m-grp')">✕</button></div>
    <div class="mbody">
      <div class="seg">
        <button class="seg-btn on" id="seg-join" onclick="setGrpSeg('join')">Join Group</button>
        <button class="seg-btn" id="seg-create" onclick="setGrpSeg('create')">Create Group</button>
      </div>
      <div id="grp-join-body">
        <div class="mfld" style="margin-bottom:8px">
          <label>Available Groups (tap to select)</label>
          <div id="grp-available"></div>
        </div>
        <div class="mfld">
          <label>Group Name</label>
          <input id="gj-name" placeholder="Group name" spellcheck="false">
        </div>
        <div class="mfld">
          <label>PIN</label>
          <input id="gj-pin" placeholder="Ask the group creator for the PIN" maxlength="12" spellcheck="false">
        </div>
      </div>
      <div id="grp-create-body" style="display:none">
        <div class="mfld">
          <label>Group Name</label>
          <input id="gc-name" placeholder="E.g. devteam, family, study" spellcheck="false">
        </div>
        <div class="mfld">
          <label>PIN (4–12 alphanumeric chars)</label>
          <input id="gc-pin" placeholder="E.g. Secret007" maxlength="12" spellcheck="false">
          <div class="hint">Share this PIN only with people you want in the group. All messages are E2E encrypted with this PIN.</div>
        </div>
      </div>
    </div>
    <div class="mfoot">
      <button class="btn btn-ghost" onclick="closeModal('m-grp')">Cancel</button>
      <button class="btn btn-pri" id="grp-action-btn" onclick="doGrpAction()">Join Group</button>
    </div>
  </div>
</div>

<!-- Group members modal -->
<div class="overlay" id="m-grp-members">
  <div class="modal">
    <div class="mhdr"><h2>👥 Group Members</h2><button class="mclose" onclick="closeModal('m-grp-members')">✕</button></div>
    <div class="mbody" id="grp-members-body"></div>
    <div class="mfoot"><button class="btn btn-ghost" onclick="closeModal('m-grp-members')">Close</button></div>
  </div>
</div>

<!-- File send -->
<div class="overlay" id="m-file">
  <div class="modal">
    <div class="mhdr"><h2>📎 Send File</h2><button class="mclose" onclick="closeModal('m-file')">✕</button></div>
    <div class="mbody">
      <div class="dz" id="dz" onclick="document.getElementById('fi').click()"
           ondragover="dzOn(event)" ondragleave="dzOff(event)" ondrop="dzDrop(event)">
        <span class="dz-ico">📁</span>
        <p>Tap to choose file or drag & drop</p>
        <small>Max 15 MB · jpg png gif pdf zip mp4 mp3 txt webp docx</small>
        <input type="file" id="fi" style="display:none" onchange="fileChosen(this)">
      </div>
      <div class="file-prev" id="file-prev"></div>
      <div class="mfld">
        <label>Send to (blank = everyone)</label>
        <input id="f-targets" placeholder="username1, username2 or leave blank" list="dl-users">
      </div>
    </div>
    <div class="mfoot">
      <button class="btn btn-ghost" onclick="closeModal('m-file')">Cancel</button>
      <button class="btn btn-pri" id="f-send-btn" onclick="sendFile()" disabled>Send</button>
    </div>
  </div>
</div>

<!-- Self-destruct -->
<div class="overlay" id="m-sd">
  <div class="modal">
    <div class="mhdr"><h2>💣 Expiring Message</h2><button class="mclose" onclick="closeModal('m-sd')">✕</button></div>
    <div class="mbody">
      <div class="mfld">
        <label>Message</label>
        <textarea id="sd-msg" placeholder="This message will disappear after the timer..." style="min-height:90px"></textarea>
      </div>
      <div class="mfld">
        <label>Disappears after (seconds)</label>
        <input id="sd-secs" type="number" value="30" min="5" max="600" step="5">
        <div class="hint">Everyone sees a countdown. Message vanishes from all screens automatically.</div>
      </div>
    </div>
    <div class="mfoot">
      <button class="btn btn-ghost" onclick="closeModal('m-sd')">Cancel</button>
      <button class="btn btn-red" onclick="sendSD()">💣 Send</button>
    </div>
  </div>
</div>

<script>
'use strict';

// ══════════════════════════════════════════════════════
//  APP STATE
// ══════════════════════════════════════════════════════
const App = {
  ws: null,
  username: null,
  sid: null,
  isAdmin: false,
  tab: 'pub',
  users: [],
  myGroups: {},      // name → {pin, isOwner}
  activeGroup: null,
  privInbox: [],     // [{from, content, ts}]
  privBadge: 0,
  grpBadge: {},      // name → count
  fileB64: null, fileName: null, fileSize: 0,
  grpSeg: 'join',
  keyCache: {},
  reconnecting: false,
};

// ══════════════════════════════════════════════════════
//  CRYPTO (AES-256-GCM in secure context; XOR fallback)
// ══════════════════════════════════════════════════════
const SEC = window.isSecureContext;

async function getKey(code) {
  if (App.keyCache[code]) return App.keyCache[code];
  if (SEC && window.crypto?.subtle) {
    const raw = new TextEncoder().encode(code);
    const km  = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
    const k   = await crypto.subtle.deriveKey(
      {name:'PBKDF2', salt: new TextEncoder().encode('portanox-salt-v3'), iterations:120000, hash:'SHA-256'},
      km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
    );
    App.keyCache[code] = {k, type:'aes'};
  } else {
    // PBKDF2-like XOR key stretch
    let h = new Uint8Array(32);
    const cb = new TextEncoder().encode(code);
    for (let i=0;i<32;i++) h[i]=cb[i%cb.length]^(i*37+13);
    for (let r=0;r<3000;r++) { let x=h[0]; for(let i=0;i<31;i++) h[i]=(h[i]^h[i+1]+r)&0xff; h[31]=(h[31]^x)&0xff; }
    App.keyCache[code] = {k:h, type:'xor'};
  }
  return App.keyCache[code];
}

async function enc(text, code) {
  const k = await getKey(code);
  const b = new TextEncoder().encode(text);
  if (k.type === 'aes') {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({name:'AES-GCM',iv}, k.k, b);
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv); out.set(new Uint8Array(ct), 12);
    return btoa(String.fromCharCode(...out));
  }
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = b.map((x,i) => (x ^ k.k[(i+iv[i%16])%32])&0xff);
  return btoa(String.fromCharCode(...iv, ...ct));
}

async function dec(b64, code) {
  try {
    const k    = await getKey(code);
    const data = Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
    if (k.type === 'aes') {
      const iv = data.slice(0,12), ct = data.slice(12);
      const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv}, k.k, ct);
      return new TextDecoder().decode(pt);
    }
    const iv = data.slice(0,16), ct = Array.from(data.slice(16));
    return new TextDecoder().decode(new Uint8Array(ct.map((x,i)=>(x^k.k[(i+iv[i%16])%32])&0xff)));
  } catch { return '⚠ Decryption failed — wrong code?'; }
}

// ══════════════════════════════════════════════════════
//  WEBSOCKET
// ══════════════════════════════════════════════════════
function doConnect() {
  const uname  = document.getElementById('l-user').value.trim();
  const hostIn = document.getElementById('l-host').value.trim();
  if (!uname) { lmsg('Enter a username', true); return; }
  if (!/^[a-zA-Z0-9_\-]{2,24}$/.test(uname)) { lmsg('Username: 2–24 chars, letters/digits/_ /- only', true); return; }
  App.username = uname;
  const host  = hostIn || location.host;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url   = `${proto}//${host}/ws`;
  lmsg(`Connecting to ${host}...`);
  document.getElementById('conn-btn').disabled = true;
  try {
    App.ws = new WebSocket(url);
    App.ws.onopen  = () => { ws({type:'join', username:App.username}); lmsg('Connected — identifying...'); };
    App.ws.onmessage = e => { try { handle(JSON.parse(e.data)); } catch{} };
    App.ws.onerror = () => lmsg('Connection error. Check server address.', true);
    App.ws.onclose = () => {
      setConn(false);
      if (document.getElementById('app').classList.contains('active'))
        toast('Disconnected', 'Lost connection to server.', 'red');
      document.getElementById('conn-btn').disabled = false;
    };
  } catch(e) { lmsg('Error: ' + e.message, true); document.getElementById('conn-btn').disabled=false; }
}

function ws(obj) { if (App.ws?.readyState===1) App.ws.send(JSON.stringify(obj)); }

// Keepalive ping every 25s
setInterval(() => { if (App.ws?.readyState===1) ws({type:'ping'}); }, 25000);

// ══════════════════════════════════════════════════════
//  MESSAGE HANDLER
// ══════════════════════════════════════════════════════
function handle(m) {
  switch(m.type) {
    case 'waiting':
      show('scr-wait');
      document.getElementById('wait-sub').textContent = m.message;
      break;

    case 'joined':
      App.sid     = m.sid;
      App.isAdmin = m.is_admin;
      show('app');
      setConn(true);
      document.getElementById('hdr-you').textContent = App.username + (App.isAdmin?' ★':'');
      updateUsers(m.users||[]);
      document.getElementById('enc-chip-txt').textContent = SEC
        ? '🔐 AES-256-GCM active. Server never sees private/group content.'
        : '⚠ XOR cipher active. For stronger encryption, access via HTTPS.';
      if (App.isAdmin) toast('Admin Access', 'You have admin privileges from the server machine.', 'amber');
      else toast('Welcome!', `Joined as ${App.username}`, 'green');
      break;

    case 'error':
      if (!document.getElementById('app').classList.contains('active')) {
        show('scr-login');
        lmsg(m.message, true);
        document.getElementById('conn-btn').disabled = false;
      } else toast('Error', m.message, 'red');
      break;

    case 'kicked':
      addSysMsg('pub', '🚫 ' + (m.message||'You were removed.'));
      setConn(false);
      setTimeout(()=>show('scr-login'), 2000);
      break;

    case 'server_msg':
      addSysMsg('pub', m.message);
      if (m.level==='warn') toast('Notice', m.message, 'amber');
      if (m.level==='ok')   toast('', m.message, 'green');
      break;

    case 'server_shutdown':
      addSysMsg('pub', '⏹ Server is shutting down.');
      toast('Server Offline', m.message||'Server going down.', 'red');
      setConn(false);
      break;

    case 'pong': break;

    case 'public':
      addPub(m);
      if (App.tab !== 'pub') flashTab('pub');
      break;

    case 'user_joined':
      updateUser({username:m.username, ip:m.ip, is_admin:m.is_admin}, true);
      addSysMsg('pub', `✦ ${m.username} joined${m.is_admin?' (admin)':''}`);
      toast('Joined', m.username, 'green');
      break;

    case 'user_left':
      removeUser(m.username);
      addSysMsg('pub', `✦ ${m.username} left`);
      break;

    case 'user_list':
      updateUsers(m.users||[]);
      break;

    case 'private_msg':
      App.privInbox.push({from:m.from, content:m.content, ts:m.timestamp});
      App.privBadge++;
      updatePrivBadge();
      if (App.tab==='priv') renderInbox();
      addSysMsg('priv', `🔒 Encrypted message from ${m.from} — decode it in this tab`);
      toast(`🔒 Private from ${m.from}`, 'Open Private tab to decode', 'amber');
      break;

    case 'private_sent':
      toast('Sent 🔒', `Private message → ${m.to}`, 'green');
      break;

    case 'group_joined':
      App.myGroups[m.group] = {pin: App.myGroups[m.group]?.pin, isOwner:m.is_owner};
      renderSbGroups();
      if (App.tab==='grp' || true) setActiveGroup(m.group, m.is_owner, m.members, m.owner);
      toast('Joined 📁', `Group: ${m.group}`, 'green');
      break;

    case 'group_left':
      const lg = m.group;
      delete App.myGroups[lg];
      renderSbGroups();
      if (App.activeGroup === lg) {
        App.activeGroup = null;
        document.getElementById('grp-cur-name').textContent = 'No group selected';
        document.getElementById('grp-leave-btn').style.display='none';
        document.getElementById('grp-members-btn').style.display='none';
        document.getElementById('msg-in').placeholder = 'Select a group first...';
        setMsgsArea('grp', createEmptyState('📁','Join or create a group to start chatting.'));
      }
      if (m.reason) toast('Removed', m.reason, 'amber');
      else toast('Left', `Left group ${lg}`, '');
      break;

    case 'group_event':
      addSysMsg('grp', `✦ ${m.username} ${m.event} the group`);
      if (m.event === 'joined') toast(`${m.username} joined`, m.group, 'green');
      if (m.event === 'kicked') toast(`${m.username} removed`, m.group, 'amber');
      break;

    case 'group_history':
      addGrpHistMsg(m);
      break;

    case 'group_msg':
      addGrpMsg(m);
      if (App.tab!=='grp' || App.activeGroup!==m.group) {
        App.grpBadge[m.group] = (App.grpBadge[m.group]||0)+1;
        updateGrpBadge();
      }
      break;

    case 'group_members_result':
      showMembersModal(m.group, m.members, m.is_owner);
      break;

    case 'group_list_result':
      renderAvailGroups(m.groups);
      break;

    case 'group_ok':
      toast('', m.message||'OK', 'green');
      break;

    case 'group_sent': break;

    case 'file_recv':
      addFile(m);
      if (App.tab!=='pub') flashTab('pub');
      break;

    case 'file_sent':
      toast('File Sent 📎', `${m.filename} → ${m.recipients}`, 'green');
      break;

    case 'self_destruct':
      addSD(m);
      if (App.tab!=='pub') flashTab('pub');
      break;
  }
}

// ══════════════════════════════════════════════════════
//  RENDER MESSAGES
// ══════════════════════════════════════════════════════
function addPub(m) {
  const mine = m.mine || m.from===App.username;
  const d = mkMsg(mine ? 'mine':'theirs', m.from, m.timestamp, m.is_admin);
  const bbl = el('div','bbl'); bbl.textContent = m.message;
  if (m.is_admin) bbl.classList.add('admin-msg');
  d.appendChild(bbl);
  appendToMsgs('pub', d);
}

function addSysMsg(area, text) {
  const d = el('div','msg sys');
  const b = el('div','bbl'); b.textContent = text; d.appendChild(b);
  appendToMsgs(area, d);
}

function addSD(m) {
  const mine = m.mine || m.from===App.username;
  const d = mkMsg(mine?'mine':'theirs', m.from, m.timestamp);
  const bbl = el('div','bbl sd'); bbl.textContent = m.message;
  const wrap = el('div','sd-bar-wrap');
  const bar  = el('div','sd-bar'); bar.style.width='100%';
  const lbl  = el('div','sd-lbl');
  wrap.appendChild(bar); d.appendChild(bbl); d.appendChild(wrap); d.appendChild(lbl);
  appendToMsgs('pub', d);
  let rem = m.secs;
  lbl.textContent = `Expires in ${rem}s`;
  const iv = setInterval(()=>{
    rem -= .5;
    bar.style.width = Math.max(0,rem/m.secs*100)+'%';
    lbl.textContent = `Expires in ${Math.ceil(rem)}s`;
    if (rem <= 0) {
      clearInterval(iv);
      if (d.parentNode) { d.style.opacity='0'; d.style.transition='.4s'; setTimeout(()=>d.remove(),400); }
    }
  }, 500);
}

function addGrpMsg(m) {
  const grp = App.myGroups[m.group];
  if (!grp?.pin) { addSysMsg('grp', `[${m.group}] New encrypted message from ${m.from}`); return; }
  dec(m.content, grp.pin).then(plain => {
    const mine = m.mine||m.from===App.username;
    const d = mkMsg(mine?'mine':'theirs', m.from, m.timestamp);
    const bbl = el('div','bbl grp'); bbl.textContent = plain;
    const enc = el('div','enc-mark'); enc.textContent = `🔐 ${m.group}`;
    d.appendChild(bbl); d.appendChild(enc);
    appendToMsgs('grp', d);
  });
}

function addGrpHistMsg(m) {
  const grp = App.myGroups[m.group];
  if (!grp?.pin) return;
  dec(m.content, grp.pin).then(plain => {
    const d = mkMsg('theirs', m.from, m.timestamp);
    d.style.opacity = '.7';
    const bbl = el('div','bbl grp'); bbl.textContent = plain;
    const enc = el('div','enc-mark'); enc.textContent = `📜 History · ${m.group}`;
    d.appendChild(bbl); d.appendChild(enc);
    appendToMsgs('grp', d, true);
  });
}

function addFile(m) {
  const mine = m.from===App.username;
  const d    = mkMsg(mine?'mine':'theirs', m.from, m.timestamp);
  const ext  = (m.filename||'').split('.').pop().toLowerCase();
  const isImg= ['jpg','jpeg','png','gif','webp'].includes(ext);
  const ico  = isImg?'🖼':ext==='pdf'?'📄':ext==='zip'?'🗜':ext==='mp4'?'🎬':ext==='mp3'?'🎵':'📁';
  const sz   = m.filesize > 1048576 ? (m.filesize/1048576).toFixed(1)+'MB' : Math.ceil(m.filesize/1024)+'KB';
  const fb   = el('div','file-bbl');
  fb.innerHTML = `<span class="file-ico">${ico}</span>
    <div class="file-info">
      <div class="file-name">${esc(m.filename)}</div>
      <div class="file-sz">${sz}</div>
      <a class="file-dl" onclick="dlFile('${esc(m.content)}','${esc(m.filename)}')">⬇ Download</a>
    </div>`;
  d.appendChild(fb);
  if (isImg && m.content) {
    const img = el('img'); img.className='img-thumb';
    img.src = `data:image/${ext};base64,${m.content}`;
    img.onclick = ()=>{ const w=window.open(); w.document.write(`<img src="${img.src}" style="max-width:100%">`); };
    d.appendChild(img);
  }
  appendToMsgs('pub', d);
}

function mkMsg(cls, from, ts, isAdm) {
  const d = el('div','msg '+cls);
  const who = el('div','msg-who');
  const f = el('span','msg-from');
  f.textContent = from+(isAdm?' ★':'');
  f.style.color = userColor(from);
  const t = el('span','msg-time'); t.textContent = ts||'';
  who.appendChild(f); who.appendChild(t);
  d.appendChild(who);
  return d;
}

function appendToMsgs(area, node, prepend=false) {
  const el_ = area==='pub' ? document.getElementById('msgs-pub')
            : area==='grp' ? document.getElementById('msgs-grp')
            : area==='priv'? document.getElementById('msgs-priv') : null;
  if (!el_) return;
  if (prepend) el_.insertBefore(node, el_.firstChild);
  else el_.appendChild(node);
  if (!prepend) el_.scrollTop = el_.scrollHeight;
}

function setMsgsArea(area, node) {
  const el_ = area==='grp' ? document.getElementById('msgs-grp') : null;
  if (el_) { el_.innerHTML=''; el_.appendChild(node); }
}

function createEmptyState(ico, txt) {
  const d = el('div','empty-state');
  d.innerHTML = `<span class="ei">${ico}</span><p>${txt}</p>`;
  return d;
}

// ══════════════════════════════════════════════════════
//  SEND FUNCTIONS
// ══════════════════════════════════════════════════════
function sendMsg() {
  const inp = document.getElementById('msg-in');
  const txt = inp.value.trim();
  if (!txt) return;

  if (App.tab==='grp' && App.activeGroup) {
    sendGrpMsg(txt);
  } else if (App.tab==='pub') {
    ws({type:'public', message:txt});
  } else return;
  inp.value=''; autoGrow(inp);
}

async function sendPrivate() {
  const to   = document.getElementById('pm-to').value.trim();
  const code = document.getElementById('pm-code').value.trim();
  const msg  = document.getElementById('pm-msg').value.trim();
  if (!to||!code||!msg) { alert('Fill all fields'); return; }
  if (!/^[A-Za-z0-9]{4,12}$/.test(code)) { alert('Code must be 4–12 alphanumeric chars'); return; }
  const ct = await enc(msg, code);
  ws({type:'private_msg', to, content:ct});
  // Show locally in private tab
  const d = mkMsg('mine','You → '+to, new Date().toLocaleTimeString().slice(0,-3));
  const bbl = el('div','bbl priv'); bbl.textContent = msg;
  const em  = el('div','enc-mark'); em.textContent = '🔐 Sent encrypted to '+to;
  d.appendChild(bbl); d.appendChild(em);
  appendToMsgs('priv', d);
  closeModal('m-priv');
  document.getElementById('pm-msg').value='';
}

async function sendGrpMsg(text) {
  const grp = App.myGroups[App.activeGroup];
  if (!grp?.pin) return;
  const ct = await enc(text, grp.pin);
  ws({type:'group_msg', group:App.activeGroup, content:ct});
  // Render locally immediately
  const d = mkMsg('mine', App.username, new Date().toLocaleTimeString().slice(0,-3));
  const bbl = el('div','bbl grp'); bbl.textContent = text;
  d.appendChild(bbl);
  appendToMsgs('grp', d);
}

function sendFile() {
  if (!App.fileB64) return;
  const ts = document.getElementById('f-targets').value;
  const targets = ts.split(',').map(t=>t.trim()).filter(Boolean);
  ws({type:'file_send', filename:App.fileName, filesize:App.fileSize,
       content:App.fileB64, targets});
  closeModal('m-file');
  App.fileB64=App.fileName=null; App.fileSize=0;
  document.getElementById('f-send-btn').disabled=true;
  document.getElementById('file-prev').style.display='none';
}

function sendSD() {
  const msg  = document.getElementById('sd-msg').value.trim();
  const secs = parseInt(document.getElementById('sd-secs').value)||30;
  if (!msg) return;
  ws({type:'self_destruct', message:msg, secs});
  closeModal('m-sd');
  document.getElementById('sd-msg').value='';
}

function doGrpAction() {
  if (App.grpSeg==='join') {
    const name = document.getElementById('gj-name').value.trim();
    const pin  = document.getElementById('gj-pin').value.trim();
    if (!name||!pin) { alert('Enter group name and PIN'); return; }
    if (!/^[A-Za-z0-9]{4,12}$/.test(pin)) { alert('PIN must be 4–12 alphanumeric chars'); return; }
    App.myGroups[name] = {pin};  // store PIN for decryption
    ws({type:'group_join', group:name, pin});
    closeModal('m-grp');
  } else {
    const name = document.getElementById('gc-name').value.trim();
    const pin  = document.getElementById('gc-pin').value.trim();
    if (!name||!pin) { alert('Enter group name and PIN'); return; }
    if (!/^[A-Za-z0-9]{4,12}$/.test(pin)) { alert('PIN must be 4–12 alphanumeric chars'); return; }
    App.myGroups[name] = {pin, isOwner:true};
    ws({type:'group_create', group:name, pin});
    closeModal('m-grp');
  }
}

function leaveGroup() {
  if (!App.activeGroup) return;
  if (!confirm(`Leave group "${App.activeGroup}"?`)) return;
  ws({type:'group_leave', group:App.activeGroup});
}

function openGroupMembers() {
  if (!App.activeGroup) return;
  ws({type:'group_members', group:App.activeGroup});
}

function showMembersModal(gname, members, isOwner) {
  const el_ = document.getElementById('grp-members-body');
  el_.innerHTML = members.map(u => `
    <div class="member-item">
      <div class="sb-avatar" style="background:${userColor(u)}22;color:${userColor(u)}">${u[0].toUpperCase()}</div>
      <span class="member-name">${esc(u)}</span>
      ${u===App.username ? '<span class="you-tag">you</span>' : ''}
      ${isOwner && u!==App.username ? `<button class="btn btn-red" style="padding:4px 10px;font-size:11px" onclick="kickFromGroup('${esc(gname)}','${esc(u)}')">Remove</button>` : ''}
    </div>`).join('');
  openModal('m-grp-members');
}

function kickFromGroup(gname, target) {
  if (!confirm(`Remove ${target} from ${gname}?`)) return;
  ws({type:'group_kick', group:gname, target});
  closeModal('m-grp-members');
}

// ══════════════════════════════════════════════════════
//  UI HELPERS
// ══════════════════════════════════════════════════════
function goTab(tab) {
  App.tab = tab;
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on', t.dataset.tab===tab));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('on'));
  document.getElementById('tab-'+tab).classList.add('on');
  const inp = document.getElementById('msg-in');
  if (tab==='pub')  inp.placeholder='Message everyone...';
  if (tab==='grp')  inp.placeholder=App.activeGroup?`Message [${App.activeGroup}]...`:'Select a group first...';
  if (tab==='priv') inp.placeholder='Use the Private tab controls above';
  if (tab==='priv') { App.privBadge=0; updatePrivBadge(); renderInbox(); }
  if (tab==='grp')  { App.grpBadge[App.activeGroup||'']=0; updateGrpBadge(); }
}

function setActiveGroup(name, isOwner, members, owner) {
  App.activeGroup = name;
  goTab('grp');
  document.getElementById('grp-cur-name').textContent = `📁 ${name}`;
  document.getElementById('grp-leave-btn').style.display='';
  document.getElementById('grp-members-btn').style.display='';
  document.getElementById('msg-in').placeholder=`Message [${name}]...`;
  App.grpBadge[name]=0; updateGrpBadge();
  // Clear + set group messages area
  const msgs = document.getElementById('msgs-grp');
  msgs.innerHTML='';
  if (members?.length) {
    const sys = el('div','msg sys');
    const b = el('div','bbl');
    b.textContent = `Group "${name}" · ${members.length} member(s) · Owner: ${owner}`;
    sys.appendChild(b); msgs.appendChild(sys);
  }
  renderSbGroups();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

function openModal(id) {
  if (id==='m-grp') { ws({type:'group_list'}); }
  if (id==='m-priv') renderInbox();
  document.getElementById(id).classList.add('show');
}
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

function setGrpSeg(s) {
  App.grpSeg=s;
  document.getElementById('grp-join-body').style.display=s==='join'?'':'none';
  document.getElementById('grp-create-body').style.display=s==='create'?'':'none';
  document.getElementById('seg-join').classList.toggle('on',s==='join');
  document.getElementById('seg-create').classList.toggle('on',s==='create');
  document.getElementById('grp-action-btn').textContent=s==='join'?'Join Group':'Create Group';
}

function renderAvailGroups(groups) {
  const c = document.getElementById('grp-available');
  c.innerHTML = groups.length ? groups.map(g=>`
    <div class="grp-opt" onclick="document.getElementById('gj-name').value='${esc(g.name)}'">
      <span>📁</span>
      <span class="grp-opt-name">${esc(g.name)}</span>
      <span class="grp-opt-cnt">${g.count} member${g.count!==1?'s':''}</span>
    </div>`).join('') : '<div style="font-size:12px;color:var(--text3);padding:8px 0">No groups yet</div>';
}

function renderInbox() {
  const sec = document.getElementById('pm-inbox-sec');
  const box = document.getElementById('pm-inbox');
  if (!App.privInbox.length) { sec.style.display='none'; return; }
  sec.style.display='';
  box.innerHTML = App.privInbox.slice(-8).reverse().map((m,i)=>`
    <div class="inbox-item">
      <div class="inbox-who">🔒 <span style="color:var(--purple);font-weight:700">${esc(m.from)}</span>
        <span style="color:var(--text3)">${m.ts||''}</span></div>
      <div class="inbox-decode">
        <input placeholder="Enter shared code" id="ic-${i}" maxlength="12" spellcheck="false">
        <button class="btn btn-pri" style="padding:6px 12px;font-size:12px" onclick="decodeInbox(${i})">Decode</button>
      </div>
      <div class="inbox-plain" id="ip-${i}"></div>
    </div>`).join('');
}

async function decodeInbox(i) {
  const msgs = App.privInbox.slice(-8).reverse();
  const m    = msgs[i];
  const code = document.getElementById(`ic-${i}`).value.trim();
  if (!code) { alert('Enter the shared code'); return; }
  const plain = await dec(m.content, code);
  const el_   = document.getElementById(`ip-${i}`);
  el_.textContent = plain;
  el_.style.display='block';
}

function updateUsers(users) {
  App.users = users;
  const dl = document.getElementById('dl-users');
  dl.innerHTML = users.filter(u=>u.username!==App.username)
    .map(u=>`<option value="${esc(u.username)}">`).join('');
  renderSbUsers();
}

function updateUser(u, add) {
  if (add) {
    if (!App.users.find(x=>x.username===u.username)) App.users.push(u);
  }
  renderSbUsers();
}

function removeUser(uname) {
  App.users = App.users.filter(u=>u.username!==uname);
  renderSbUsers();
}

function renderSbUsers() {
  const c = document.getElementById('sb-users');
  document.getElementById('sb-count').textContent = App.users.length;
  c.innerHTML = App.users.map(u=>`
    <div class="sb-item" onclick="prefillPM('${esc(u.username)}')">
      <div class="sb-avatar" style="background:${userColor(u.username)}22;color:${userColor(u.username)}">${u.username[0].toUpperCase()}</div>
      <span class="sb-name">${esc(u.username)}</span>
      ${u.username===App.username?'<span class="you-tag">you</span>':''}
      ${u.is_admin?'<span class="admin-tag">admin</span>':''}
      ${u.muted?'<span class="muted-tag">muted</span>':''}
    </div>`).join('');
}

function renderSbGroups() {
  const sec = document.getElementById('sb-grp-sec');
  const c   = document.getElementById('sb-groups');
  const names = Object.keys(App.myGroups);
  sec.style.display = names.length?'':'none';
  c.innerHTML = names.map(n=>`
    <div class="sb-item ${App.activeGroup===n?'active':''}" onclick="goTab('grp');if(App.myGroups['${esc(n)}'])setActiveGroup('${esc(n)}',App.myGroups['${esc(n)}'].isOwner)">
      <span style="font-size:16px">📁</span>
      <span class="sb-name">${esc(n)}</span>
      ${App.grpBadge[n]>0?`<span class="sb-badge" style="background:var(--red);color:#fff">${App.grpBadge[n]}</span>`:''}
    </div>`).join('');
}

function prefillPM(uname) {
  document.getElementById('pm-to').value = uname;
  openModal('m-priv');
  if (window.innerWidth<=700) document.getElementById('sidebar').classList.remove('open');
}

function updatePrivBadge() {
  const b=document.getElementById('priv-badge');
  if (App.privBadge>0) { b.textContent=App.privBadge; b.style.display=''; }
  else b.style.display='none';
}

function updateGrpBadge() {
  const total = Object.values(App.grpBadge).reduce((a,b)=>a+b,0);
  const b = document.getElementById('grp-badge');
  if (total>0) { b.textContent=total; b.style.display=''; }
  else b.style.display='none';
}

function flashTab(tab) {
  const t = document.querySelector(`[data-tab="${tab}"]`);
  if (t) { t.style.animation='none'; setTimeout(()=>t.style.animation='',10); }
}

function setConn(ok) {
  document.getElementById('conn-dot').className='hdr-logo-dot'+(ok?'':' off');
}

function show(id) {
  ['scr-login','scr-wait'].forEach(s=>{
    document.getElementById(s).classList.toggle('hidden', s!==id);
    document.getElementById(s).style.display = s===id?'flex':'none';
  });
  const app=document.getElementById('app');
  if (id==='app') app.classList.add('active'); else app.classList.remove('active');
}

function lmsg(txt, err=false) {
  const e=document.getElementById('l-msg');
  e.textContent=txt; e.className='lmsg'+(err?' err':'');
}

// ── File handling ──────────────────────────────────────
function dzOn(e)  { e.preventDefault(); document.getElementById('dz').classList.add('over'); }
function dzOff(e) { document.getElementById('dz').classList.remove('over'); }
function dzDrop(e){ e.preventDefault(); dzOff(e); const f=e.dataTransfer.files[0]; if(f) loadFile(f); }
function fileChosen(inp){ if(inp.files[0]) loadFile(inp.files[0]); }
function loadFile(file) {
  const MAX=15*1024*1024;
  if (file.size>MAX) { alert('File too large (max 15MB)'); return; }
  const ext='.'+file.name.split('.').pop().toLowerCase();
  const ok=['.jpg','.jpeg','.png','.gif','.webp','.pdf','.zip','.mp4','.mp3','.txt','.docx'];
  if (!ok.includes(ext)) { alert(`File type not allowed: ${ext}`); return; }
  App.fileName=file.name; App.fileSize=file.size;
  const r=new FileReader();
  r.onload=e=>{
    App.fileB64=e.target.result.split(',')[1];
    const pv=document.getElementById('file-prev');
    pv.style.display=''; pv.textContent=`✓ ${file.name} (${Math.ceil(file.size/1024)}KB)`;
    document.getElementById('f-send-btn').disabled=false;
  };
  r.readAsDataURL(file);
}
function dlFile(b64,name) {
  const a=document.createElement('a');
  a.href=`data:application/octet-stream;base64,${b64}`;
  a.download=name; a.click();
}

// ── Input ──────────────────────────────────────────────
function msgKey(e) { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();} }
function autoGrow(t) { t.style.height='auto'; t.style.height=Math.min(t.scrollHeight,120)+'px'; }

// ── Toasts ─────────────────────────────────────────────
function toast(title, sub, type='') {
  const c=document.getElementById('toasts');
  const d=document.createElement('div');
  d.className='toast'+(type?' '+type:'');
  d.innerHTML=`<div class="t-title">${esc(title)}</div><div class="t-sub">${esc(String(sub).slice(0,80))}</div>`;
  d.onclick=()=>d.remove();
  c.appendChild(d);
  setTimeout(()=>{ if(d.parentNode)d.remove(); },4500);
  while(c.children.length>5) c.removeChild(c.firstChild);
}

// ── Colours ────────────────────────────────────────────
const COLS=['#3b9eff','#22d3a0','#9d6eff','#f59e0b','#ef4444','#06b6d4','#fb923c','#a3e635'];
const _uc={};
function userColor(n){ if(!_uc[n])_uc[n]=COLS[Object.keys(_uc).length%COLS.length]; return _uc[n]; }

// ── DOM helpers ────────────────────────────────────────
function el(tag,cls=''){const e=document.createElement(tag);if(cls)e.className=cls;return e;}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── Init ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',()=>{
  show('scr-login');
  document.getElementById('l-user').addEventListener('keydown',e=>{ if(e.key==='Enter') document.getElementById('l-host').focus(); });
  document.getElementById('l-host').addEventListener('keydown',e=>{ if(e.key==='Enter') doConnect(); });
  document.querySelectorAll('.overlay').forEach(o=>{
    o.addEventListener('click',e=>{ if(e.target===o) o.classList.remove('show'); });
  });
  setGrpSeg('join');
});
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED HTML — ADMIN PANEL (server IP only)
# ══════════════════════════════════════════════════════════════════════════════
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PortaNox — Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060d18;--s:#0a1422;--c:#0e1d30;--r:#12243a;--h:#162c46;--b1:#1c3450;--b2:#234060;
  --blue:#3b9eff;--green:#22d3a0;--purple:#9d6eff;--amber:#f59e0b;--red:#ef4444;
  --t:#d4e8f8;--t2:#5580a0;--t3:#2a4560;
  --font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace}
html,body{height:100%;background:var(--bg);color:var(--t);font-family:var(--font);font-size:13px;overflow:hidden}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-thumb{background:var(--b1)}
#app{display:flex;flex-direction:column;height:100vh}
header{background:var(--s);border-bottom:1px solid var(--b1);padding:0 18px;height:50px;display:flex;align-items:center;gap:10px;flex-shrink:0}
.hlogo{font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px}
.hadmin{font-size:10px;padding:2px 8px;border-radius:20px;background:rgba(245,158,11,.15);color:var(--amber);border:1px solid rgba(245,158,11,.3);font-weight:600;letter-spacing:.3px}
.hup{margin-left:auto;font-size:11px;color:var(--t2)}
.hinfo{font-size:11px;color:var(--t3)}

#stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;padding:10px 18px;flex-shrink:0}
.sc{background:var(--s);border:1px solid var(--b1);border-radius:8px;padding:10px 14px;cursor:pointer;transition:.15s}
.sc:hover{border-color:var(--blue)}.sv{font-size:22px;font-weight:700;line-height:1.1}.sl{font-size:10px;color:var(--t2);margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
.sc.sa .sv{color:var(--blue)}.sc.sp .sv{color:var(--amber)}.sc.sb_ .sv{color:var(--red)}.sc.sg .sv{color:var(--green)}

#nav{display:flex;gap:1px;padding:0 18px;background:var(--s);border-bottom:1px solid var(--b1);flex-shrink:0;overflow-x:auto}
#nav::-webkit-scrollbar{height:0}
.ntab{padding:9px 14px;border:none;background:none;color:var(--t2);font-size:12px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;font-family:var(--font);transition:.15s}
.ntab:hover{color:var(--t)}.ntab.on{color:var(--blue);border-bottom-color:var(--blue)}
.nb{background:var(--amber);color:#000;border-radius:20px;padding:1px 5px;font-size:10px;font-weight:700;margin-left:3px}

#content{flex:1;overflow:hidden;display:flex}
.sec{display:none;flex:1;overflow-y:auto;padding:14px 18px;flex-direction:column;gap:10px}
.sec.on{display:flex}
.panel{background:var(--s);border:1px solid var(--b1);border-radius:8px;overflow:hidden}
.phdr{padding:9px 14px;font-size:10px;font-weight:700;color:var(--t2);text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between}
.logarea{background:var(--bg);font-family:var(--mono);font-size:11px;padding:8px 10px;height:200px;overflow-y:auto}
.ll{padding:2px 0;display:flex;gap:8px;border-bottom:1px solid rgba(255,255,255,.025)}
.lt{color:var(--t3);flex-shrink:0;width:60px}.lm{word-break:break-all;flex:1}.la{color:var(--red)}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 14px;text-align:left;border-bottom:1px solid var(--b1)}
th{color:var(--t2);font-size:10px;text-transform:uppercase;letter-spacing:.5px;background:var(--bg);font-weight:700}
tr:hover td{background:var(--r)}
.acts{display:flex;gap:4px;flex-wrap:wrap}
.btn{padding:4px 10px;border:none;border-radius:5px;font-size:11px;font-weight:600;cursor:pointer;font-family:var(--font);transition:.15s}
.btn:hover{filter:brightness(1.15)}
.bok{background:var(--green);color:#000}.berr{background:var(--red);color:#fff}
.bwarn{background:var(--amber);color:#000}.bacc{background:var(--blue);color:#fff}
.bghost{background:transparent;border:1px solid var(--b1);color:var(--t2)}
.bghost:hover{color:var(--t);border-color:var(--b2)}
input{background:var(--r);border:1px solid var(--b1);border-radius:6px;padding:7px 10px;color:var(--t);font-family:var(--font);font-size:12px;outline:none;transition:.2s}
input:focus{border-color:var(--blue)}
input::placeholder{color:var(--t2)}
.irow{display:flex;gap:6px;padding:10px 14px;align-items:center}
.empty{text-align:center;padding:28px;color:var(--t2);font-size:12px}
.pcard{padding:10px 14px;border-bottom:1px solid var(--b1);display:flex;align-items:center;gap:8px;animation:fi .2s ease}
@keyframes fi{from{opacity:0;transform:translateY(-4px)}to{opacity:1}}
.pcard:last-child{border-bottom:none}
.pname{font-weight:700;font-size:13px}.pip{font-size:11px;color:var(--t2)}
.gcard{padding:10px 14px;border-bottom:1px solid var(--b1);display:flex;align-items:center;gap:8px}
.gcard:last-child{border-bottom:none}

#bbar{display:flex;gap:6px;padding:10px 18px;background:var(--s);border-top:1px solid var(--b1);flex-shrink:0}
#bbar input{flex:1}
.conn-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green)}
.conn-dot.off{background:var(--red);box-shadow:0 0 6px var(--red)}
</style>
</head>
<body>
<div id="app">
<header>
  <div class="hlogo"><div class="conn-dot" id="cdot"></div>PortaNox Admin</div>
  <div class="hadmin">★ ADMIN PANEL</div>
  <div class="hinfo" id="h-ips">Loading...</div>
  <div class="hup" id="hup">Uptime: --:--:--</div>
</header>

<div id="stats">
  <div class="sc sa" onclick="goSec('users')"><div class="sv" id="s-a">0</div><div class="sl">👥 Online</div></div>
  <div class="sc sp" onclick="goSec('pend')"><div class="sv" id="s-p">0</div><div class="sl">⏳ Pending</div></div>
  <div class="sc sb_" onclick="goSec('bans')"><div class="sv" id="s-b">0</div><div class="sl">🚫 Banned</div></div>
  <div class="sc sg" onclick="goSec('groups')"><div class="sv" id="s-g">0</div><div class="sl">📁 Groups</div></div>
  <div class="sc" style="cursor:default"><div class="sv" id="s-m" style="color:var(--t2)">0</div><div class="sl">💬 Messages</div></div>
</div>

<div id="nav">
  <button class="ntab on" onclick="goSec('dash')">Dashboard</button>
  <button class="ntab" onclick="goSec('pend')" id="pend-tab">Pending <span class="nb" id="pend-nb" style="display:none">0</span></button>
  <button class="ntab" onclick="goSec('users')">Users</button>
  <button class="ntab" onclick="goSec('groups')">Groups</button>
  <button class="ntab" onclick="goSec('bans')">Banned IPs</button>
  <button class="ntab" onclick="goSec('logs')">Logs</button>
</div>

<div id="content">
  <!-- Dashboard -->
  <div class="sec on" id="sec-dash">
    <div style="display:grid;grid-template-columns:1fr 320px;gap:10px;min-height:0">
      <div class="panel"><div class="phdr">Live Log <label style="text-transform:none;font-weight:400;font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" id="asc" checked style="width:auto">Scroll</label></div><div class="logarea" id="logfeed"></div></div>
      <div style="display:flex;flex-direction:column;gap:10px">
        <div class="panel"><div class="phdr">Pending Approvals</div><div id="pend-dash"><div class="empty">None pending</div></div></div>
        <div class="panel"><div class="phdr">Online Users</div><div id="user-quick"><div class="empty">No users</div></div></div>
      </div>
    </div>
  </div>

  <!-- Pending -->
  <div class="sec" id="sec-pend"><div class="panel"><div class="phdr">Pending Approvals <button class="btn bghost" onclick="loadPend()">↻</button></div><div id="pend-full"><div class="empty">None</div></div></div></div>

  <!-- Users -->
  <div class="sec" id="sec-users">
    <div class="panel"><div class="phdr">Connected Users <button class="btn bghost" onclick="loadUsers()">↻</button></div>
    <div style="overflow-x:auto"><table><thead><tr><th>User</th><th>IP</th><th>Joined</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody id="utb"><tr><td colspan="5" class="empty">Loading...</td></tr></tbody></table></div></div>
  </div>

  <!-- Groups -->
  <div class="sec" id="sec-groups"><div class="panel"><div class="phdr">Active Groups <button class="btn bghost" onclick="loadGroups()">↻</button></div><div id="grp-body"><div class="empty">No groups</div></div></div></div>

  <!-- Bans -->
  <div class="sec" id="sec-bans">
    <div class="panel"><div class="phdr">Banned IPs</div>
    <div class="irow"><input id="ban-ip" placeholder="IP address"><input id="ban-dur" placeholder="Seconds (0=permanent)" style="width:180px" value="0"><button class="btn berr" onclick="doBan()">Ban</button></div>
    <table><thead><tr><th>IP Address</th><th>Remaining</th><th>Actions</th></tr></thead>
    <tbody id="bantb"><tr><td colspan="3" class="empty">None</td></tr></tbody></table></div>
  </div>

  <!-- Logs -->
  <div class="sec" id="sec-logs">
    <div class="panel" style="flex:1;display:flex;flex-direction:column;min-height:200px">
      <div class="phdr">Server Logs <div style="display:flex;gap:4px"><button class="btn bghost" onclick="loadLogs()">↻</button><button class="btn bghost" onclick="document.getElementById('fulllog').innerHTML=''">🗑 Clear</button></div></div>
      <div id="fulllog" style="flex:1;overflow-y:auto;background:var(--bg);font-size:11px;padding:8px 10px;font-family:var(--mono)"></div>
    </div>
  </div>
</div>

<div id="bbar">
  <input id="bcast-in" placeholder="📢 Admin broadcast to all users (Enter to send)" onkeydown="if(event.key==='Enter')doBcast()">
  <button class="btn bacc" onclick="doBcast()">Broadcast</button>
  <button class="btn berr" onclick="doShutdown()" title="Shutdown server">⏹ Shutdown</button>
</div>
</div>

<script>
'use strict';
let curSec='dash';
let _startMs = Date.now();

const es = new EventSource('/events');
es.onopen  = ()=>{ document.getElementById('cdot').className='conn-dot'; };
es.onerror = ()=>{ document.getElementById('cdot').className='conn-dot off'; };
es.onmessage = e=>{ try{ onSSE(JSON.parse(e.data)); }catch{} };

function onSSE(d) {
  if (d.type==='log')     { appendLog(d.data); }
  if (d.type==='pending') { loadStats(); loadPend(); showNb(true); }
  if (d.type==='update')  { loadStats(); loadUsers(); loadPend(); loadBanned(); loadGroups(); }
  if (d.type==='alert')   { appendLog({time:'',msg:'⚠ '+d.reason,alert:true}); }
}

function appendLog(e) {
  const f=document.getElementById('logfeed');
  const d=document.createElement('div'); d.className='ll';
  d.innerHTML=`<span class="lt">${esc(e.time||'')}</span><span class="lm${e.alert?' la':''}">${esc(e.msg||'')}</span>`;
  f.appendChild(d);
  if(document.getElementById('asc').checked) f.scrollTop=f.scrollHeight;
  while(f.children.length>500) f.removeChild(f.firstChild);
  const fl=document.getElementById('fulllog');
  const d2=document.createElement('div');
  d2.innerHTML=`<span style="color:var(--t3)">[${esc(e.time||'')}]</span> <span class="${e.alert?'la':''}">${esc(e.msg||'')}</span>`;
  fl.appendChild(d2);
}

async function api(url,body={}) {
  try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return await r.json();}
  catch{return {};}
}

async function loadStats() {
  const r=await fetch('/api/stats'); const s=await r.json();
  document.getElementById('s-a').textContent=s.active||0;
  document.getElementById('s-p').textContent=s.pending||0;
  document.getElementById('s-b').textContent=s.banned||0;
  document.getElementById('s-g').textContent=s.groups||0;
  document.getElementById('s-m').textContent=s.messages||0;
  showNb(s.pending>0);
  _startMs = Date.now() - (s.uptime||0)*1000;
}

setInterval(()=>{
  const s=Math.floor((Date.now()-_startMs)/1000);
  const h=String(Math.floor(s/3600)).padStart(2,'0'),m=String(Math.floor((s%3600)/60)).padStart(2,'0'),sc=String(s%60).padStart(2,'0');
  document.getElementById('hup').textContent=`Uptime: ${h}:${m}:${sc}`;
},1000);

function showNb(v) {
  const nb=document.getElementById('pend-nb');
  nb.style.display=v?'':'none';
}

async function loadPend() {
  const r=await fetch('/api/pending'); const ps=await r.json();
  renderPend(ps,'pend-dash'); renderPend(ps,'pend-full');
  showNb(ps.length>0);
  if(ps.length>0) document.getElementById('pend-nb').textContent=ps.length;
}

function pendHTML(u) {
  return `<div class="pcard">
    <div style="flex:1"><div class="pname">${esc(u.username)}</div><div class="pip">${esc(u.ip)} · ${u.at||''}</div></div>
    <button class="btn bok" onclick="doApprove('${esc(u.username)}')">✓ Approve</button>
    <button class="btn berr" onclick="doDeny('${esc(u.username)}')">✗ Deny</button>
  </div>`;
}

function renderPend(ps, target) {
  const el=document.getElementById(target);
  el.innerHTML=ps.length?ps.map(pendHTML).join(''):'<div class="empty">None pending</div>';
}

async function loadUsers() {
  const r=await fetch('/api/users'); const us=await r.json();
  const tb=document.getElementById('utb');
  const qq=document.getElementById('user-quick');
  if(!us.length){
    tb.innerHTML='<tr><td colspan="5" class="empty">No users online</td></tr>';
    qq.innerHTML='<div class="empty">No users</div>'; return;
  }
  tb.innerHTML=us.map(u=>`<tr>
    <td><b>${esc(u.username)}</b>${u.is_admin?' <span style="color:var(--amber);font-size:10px">★admin</span>':''}</td>
    <td style="font-family:var(--mono);color:var(--t2)">${esc(u.ip)}</td>
    <td>${u.joined||''}</td>
    <td>${u.muted?'<span style="color:var(--amber)">🔇 Muted</span>':'<span style="color:var(--green)">Active</span>'}</td>
    <td class="acts">
      ${!u.is_admin?`<button class="btn bwarn" onclick="doMute('${u.sid}','${esc(u.username)}')">Mute</button>`:''}
      ${u.muted&&!u.is_admin?`<button class="btn bghost" onclick="doUnmute('${u.sid}')">Unmute</button>`:''}
      ${!u.is_admin?`<button class="btn berr" onclick="doKick('${u.sid}','${esc(u.username)}')">Kick</button>`:''}
      ${!u.is_admin?`<button class="btn berr" style="background:#7f1d1d" onclick="doBanIP('${esc(u.ip)}')">Ban IP</button>`:''}
    </td></tr>`).join('');
  qq.innerHTML=us.map(u=>`<div class="pcard">
    <div style="flex:1"><div class="pname">${esc(u.username)}${u.is_admin?' ★':''}</div><div class="pip">${esc(u.ip)}</div></div>
    ${!u.is_admin?`<button class="btn berr" style="font-size:11px" onclick="doKick('${u.sid}','${esc(u.username)}')">Kick</button>`:''}
  </div>`).join('');
}

async function loadGroups() {
  const r=await fetch('/api/groups'); const gs=await r.json();
  const el=document.getElementById('grp-body');
  if(!gs.length){el.innerHTML='<div class="empty">No groups</div>';return;}
  el.innerHTML=gs.map(g=>`<div class="gcard">
    <span style="font-size:18px">📁</span>
    <div style="flex:1"><div class="pname">${esc(g.name)}</div>
    <div class="pip">Owner: ${esc(g.owner)} · Created: ${g.created}</div></div>
    <div style="font-size:11px;color:var(--t2)">${g.count} member${g.count!==1?'s':''}</div>
    <span style="font-size:11px;color:var(--t3)">${g.members.join(', ')}</span>
  </div>`).join('');
}

async function loadBanned() {
  const r=await fetch('/api/banned'); const bs=await r.json();
  const tb=document.getElementById('bantb');
  if(!bs.length){tb.innerHTML='<tr><td colspan="3" class="empty">No bans</td></tr>';return;}
  tb.innerHTML=bs.map(b=>`<tr>
    <td style="font-family:var(--mono)">${esc(b.ip)}</td>
    <td>${b.permanent?'<span style="color:var(--red)">Permanent</span>':b.remaining+'s'}</td>
    <td><button class="btn bok" onclick="doUnban('${esc(b.ip)}')">Unban</button></td>
  </tr>`).join('');
}

async function loadLogs() {
  const r=await fetch('/api/logs'); const ls=await r.json();
  const fl=document.getElementById('fulllog');
  fl.innerHTML=ls.map(l=>`<div><span style="color:var(--t3)">[${l.time}]</span> <span class="${l.alert?'la':''}">${esc(l.msg)}</span></div>`).join('');
  fl.scrollTop=fl.scrollHeight;
}

async function doApprove(u){await api('/api/approve',{username:u});loadStats();loadPend();}
async function doDeny(u){await api('/api/deny',{username:u});loadStats();loadPend();}
async function doKick(sid,u){if(!confirm(`Kick ${u}?`))return;await api('/api/kick',{sid});loadStats();loadUsers();}
async function doMute(sid,u){const m=prompt(`Mute ${u} for how many minutes?`,'10');if(!m)return;await api('/api/mute',{sid,minutes:parseInt(m)||10});loadUsers();}
async function doUnmute(sid){await api('/api/unmute',{sid});loadUsers();}
async function doBanIP(ip){const d=prompt(`Ban ${ip} for how many seconds?\n(Enter 0 for permanent ban)`,'3600');if(d===null)return;await api('/api/ban',{ip,duration:parseInt(d)});loadStats();loadBanned();loadUsers();}
async function doBan(){const ip=document.getElementById('ban-ip').value.trim();const dur=parseInt(document.getElementById('ban-dur').value)||0;if(!ip){alert('Enter IP');return;}await api('/api/ban',{ip,duration:dur});document.getElementById('ban-ip').value='';loadBanned();loadStats();}
async function doUnban(ip){if(!confirm(`Unban ${ip}?`))return;await api('/api/unban',{ip});loadBanned();loadStats();}
async function doBcast(){const msg=document.getElementById('bcast-in').value.trim();if(!msg)return;await api('/api/broadcast',{message:msg});document.getElementById('bcast-in').value='';}
async function doShutdown(){if(!confirm('Shutdown the server? All users will be disconnected.'))return;await api('/api/shutdown',{});}

function goSec(id) {
  curSec=id;
  document.querySelectorAll('.sec').forEach(s=>s.classList.remove('on'));
  document.querySelectorAll('.ntab').forEach(t=>t.classList.remove('on'));
  document.getElementById('sec-'+id).classList.add('on');
  document.querySelectorAll('.ntab').forEach(t=>{ if(t.textContent.toLowerCase().includes(id.slice(0,4))) t.classList.add('on'); });
  if(id==='users')  loadUsers();
  if(id==='pend')   loadPend();
  if(id==='groups') loadGroups();
  if(id==='bans')   loadBanned();
  if(id==='logs')   loadLogs();
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

async function init() {
  await loadStats();
  await loadPend();
  await loadUsers();
  await loadLogs();
  // Show server IPs
  try {
    const r=await fetch('/api/stats'); const s=await r.json();
    document.getElementById('h-ips').textContent=`Port: ${s.port}`;
  } catch{}
}
init();
setInterval(()=>{
  loadStats();
  if(curSec==='users') loadUsers();
  if(curSec==='pend')  loadPend();
  if(curSec==='bans')  loadBanned();
  if(curSec==='groups')loadGroups();
},10000);
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN SERVER
# ══════════════════════════════════════════════════════════════════════════════
class PortaNoxServer:
    def __init__(self, state: State, host: str, port: int):
        self.state   = state
        self.host    = host
        self.port    = port
        self.running = True
        self._sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(100)

    def run(self):
        state = self.state
        ips   = get_local_ips()
        print("\n" + "═"*58)
        print("  PortaNox v3.0 — Professional Secure Chat")
        print("═"*58)
        print(f"  Server IPs detected (= your admin identity):")
        for ip in ips:
            print(f"    🌐  http://{ip}:{self.port}/")
        print(f"\n  Admin panel (server only):  http://localhost:{self.port}/admin")
        print(f"  Chat client (all devices):  http://<any-ip-above>:{self.port}/")
        print(f"\n  Mode: {'OPEN (auto-approve)' if state.open_mode else 'Approval required (admin sees join requests)'}")
        print(f"  No idle timeouts — connections stay alive indefinitely")
        print("═"*58 + "\n")

        state.log(f"[START] PortaNox v3.0 on port {self.port}")
        state.log(f"[ADMIN] Server IPs: {', '.join(ips)}")
        state.log(f"[INFO] Open mode: {state.open_mode}")

        try:
            while self.running:
                conn, addr = self._sock.accept()
                threading.Thread(target=handle_conn,
                                 args=(conn, addr, state), daemon=True).start()
        except OSError:
            if self.running: state.log("[ERROR] Accept loop failed")


def main():
    parser = argparse.ArgumentParser(description="PortaNox v3.0 — Secure LAN Chat Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--open", action="store_true", help="Auto-approve all join requests (no admin needed)")
    args = parser.parse_args()

    state  = State(open_mode=args.open, port=args.port)
    server = PortaNoxServer(state=state, host=args.host, port=args.port)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[Ctrl+C] Shutting down PortaNox...")
        os._exit(0)


if __name__ == "__main__":
    main()
