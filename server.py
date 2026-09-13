#!/usr/bin/env python3
"""
arcanflows-crm-demo — a deliberately tiny "third-party CRM" that integrates the
ArcanFlows phone exactly the way the public docs describe. Stdlib only, one file.

The CRM has its OWN accounts and its own bearer token (deliberately stored by the
page under the same localStorage key a lot of apps use, `access_token`), so you can
see for yourself that the CRM's login and the ArcanFlows session never touch: the
phone's only identity is the session the backend mints for the signed-in CRM user.

  Auth (CRM's own)
    POST /api/auth/register      first account becomes admin, the rest are agents
    POST /api/auth/login         → { access_token, user }
    GET  /api/auth/me            the signed-in CRM user
    POST /api/auth/logout
  Admin (role=admin)
    GET/POST /api/admin/users, PUT/DELETE /api/admin/users/{id}   create CRM users, set role + external_user_id
    GET/PUT  /api/admin/settings                                    the ArcanFlows workspace this CRM talks to (keys, secrets, origin, label)
  Phone (signed-in CRM user)
    POST /api/phone-session        mint a 15-minute session for the signed-in user  (pbx_ key, server-side)
    POST /api/phone-session/renew  renew it                                          (same key)
    GET  /api/calls?range=7d · /api/calls/{id} · /api/calls/{id}/recording · /api/stats · /api/presence · /api/seats
    POST /api/originate            click-to-call from the CRM backend (pbxs_ calls:originate)
    POST /api/link                 provision the signed-in user's seat just in time (admins: any user)
    GET/POST /api/customers        the in-memory customer list caller lookup answers from
    GET  /api/events               what the receiver has seen (for the live log)
  Inbound from ArcanFlows (HMAC-signed, no login)
    POST /api/lookup               caller lookup — 200 with the record for a known number, 404 otherwise
    POST /api/webhooks/phone       phone.* webhooks — verifies X-Webhook-Signature, keeps the last 50
  Getting-started helpers
    GET  /api/101/status · GET/POST /api/101/subscriptions · POST /api/101/lookup-selftest · GET /api/101/recent-recorded

State lives in DATA_DIR (default ./data): users.json, settings.json. Environment
variables seed the first settings.json (PBX, PBXS, WEBHOOK_SECRET, LOOKUP_SECRET,
ARCAN_API, CRM_ORIGIN, WORKSPACE_LABEL) and the first users.json (CRM_USERS +
CRM_SEED_PASSWORD); after that the admin page is the source of truth.
The pbx_ and pbxs_ keys never leave this process. The browser only ever gets a session token.
"""
import hashlib, hmac, json, os, re, secrets, threading, time, urllib.error, urllib.parse, urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(HERE, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
LOCK = threading.Lock()
EVENTS = deque(maxlen=50)
SESSIONS = {}            # crm bearer token → {"user_id", "exp"}
SESSION_TTL = 12 * 3600
CUSTOMERS = json.loads(os.environ.get("CRM_CUSTOMERS", "{}"))   # the CRM's "customer database" for caller lookup (in memory)
SPA_PATHS = ("/", "/index.html", "/contacts", "/deals", "/tickets", "/integration", "/getting-started", "/login", "/register", "/admin")
PHONE_EVENTS = ["phone.call.ringing", "phone.call.answered", "phone.call.completed",
                "phone.call.missed", "phone.call.transferred", "phone.status.changed"]   # (there is no phone.call.started)
SETTING_KEYS = ["api", "origin", "workspace_label", "pbx", "pbxs", "webhook_secret", "lookup_secret"]
SECRET_KEYS = {"pbx", "pbxs", "webhook_secret", "lookup_secret"}


# ----------------------------------------------------------------------------- persistence
def _load(name, default):
    try:
        with open(os.path.join(DATA_DIR, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def _save(name, obj):
    p = os.path.join(DATA_DIR, name)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


SETTINGS = _load("settings.json", None)
if SETTINGS is None:
    SETTINGS = {"api": os.environ.get("ARCAN_API", "https://api.arcanflows.com"),
                "origin": os.environ.get("CRM_ORIGIN", "localhost"),
                "workspace_label": os.environ.get("WORKSPACE_LABEL", ""),
                "pbx": os.environ.get("PBX", ""), "pbxs": os.environ.get("PBXS", ""),
                "webhook_secret": os.environ.get("WEBHOOK_SECRET", ""), "lookup_secret": os.environ.get("LOOKUP_SECRET", "")}
    _save("settings.json", SETTINGS)


def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
    return f"pbkdf2${salt}${h}"


def check_password(pw, stored):
    try:
        _, salt, h = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(pw, salt), stored)


def slug(s):
    s = re.sub(r"[^a-z0-9._-]+", "-", (s or "").strip().lower()).strip("-")
    return s or "user"


USERS = _load("users.json", None)
if USERS is None:
    # First boot: seed from CRM_USERS (same shape the earlier demo used) so an existing
    # workspace mapping keeps working; the first one is the admin.
    seed = json.loads(os.environ.get("CRM_USERS", "{}"))
    pw = os.environ.get("CRM_SEED_PASSWORD", "changeme")
    USERS = {}
    for i, (uid, v) in enumerate(seed.items()):
        USERS[uid] = {"id": uid, "email": v.get("email", f"{uid}@example.com"), "name": v.get("name", uid),
                      "first_name": v.get("first_name", uid), "last_name": v.get("last_name", "-"),
                      "role": "admin" if i == 0 else "agent", "external_user_id": uid,
                      "password_hash": hash_password(pw), "how": v.get("how", ""), "created_at": time.time()}
    _save("users.json", USERS)


def public_user(u):
    return {k: v for k, v in u.items() if k != "password_hash"}


# ----------------------------------------------------------------------------- ArcanFlows client
def arcan(method, path, body=None, key=None, extra=None):
    """One call to ArcanFlows. key=None → the pbxs_ server key; pass SETTINGS['pbx'] to mint."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(SETTINGS["api"].rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + (key or SETTINGS.get("pbxs") or ""))
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    # A real product name, not the library default: Cloudflare's browser-integrity check in
    # front of api.arcanflows.com rejects "Python-urllib/x" with a 403.
    req.add_header("User-Agent", os.environ.get("CRM_USER_AGENT", "arcanflows-crm-demo/1.0 (+https://github.com/windconsul/arcanflows-crm-demo)"))
    for k, v in (extra or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {"error": "http " + str(e.code)}
    except Exception as e:
        return 599, {"error": str(e)}


def sig_ok(secret, body, header):
    if not header or not secret:
        return False
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)


def origin_allowed(allowlist, host):
    """Mirror of ArcanFlows' allow-list rule: empty = any host; exact host; *.suffix matches subdomains only."""
    eff = [a.strip().lower() for a in (allowlist or []) if a and a.strip()]
    if not eff:
        return True
    host = (host or "").lower()
    for a in eff:
        if a == "*" or a == host:
            return True
        if a.startswith("*.") and host.endswith(a[1:]) and len(host) > len(a[1:]):
            return True
    return False


def lookup_answer(raw, sig, record=True):
    """The caller-lookup contract in one place: verify the signature, answer 200 with the
    record for a known number, 404 for anyone else (ArcanFlows then routes normally)."""
    try:
        body = json.loads(raw or b"{}")
    except Exception:
        body = {}
    if not sig_ok(SETTINGS.get("lookup_secret", ""), raw, sig):
        if record:
            with LOCK:
                EVENTS.appendleft({"at": time.time(), "kind": "lookup", "note": "BAD SIGNATURE", "caller": body.get("caller")})
        return 401, {"error": "bad signature"}
    caller = body.get("caller", "")
    rec = CUSTOMERS.get(caller)
    if record:
        with LOCK:
            EVENTS.appendleft({"at": time.time(), "kind": "lookup", "caller": caller, "known": bool(rec)})
    if not rec:
        return 404, {"known": False}
    return 200, dict(rec, known=True)


def probe_scopes():
    """A pbxs_ key has no whoami. Learn its effective scopes with one side-effect-free
    request per scope: 403 = the scope is missing; anything else = granted (the request
    itself is deliberately invalid or empty, so nothing changes)."""
    zero = "00000000-0000-0000-0000-000000000000"
    probes = {
        "calls:read":           ("GET",   "/api/v1/public/phone/server/calls?limit=1", None),
        "stats:read":           ("GET",   "/api/v1/public/phone/server/stats?range=24h", None),
        "presence:read":        ("GET",   "/api/v1/public/phone/server/presence", None),
        "extensions:read":      ("GET",   "/api/v1/public/phone/server/extensions", None),
        "seats:provision":      ("GET",   "/api/v1/public/phone/server/seats", None),
        "webhooks:manage":      ("GET",   "/api/v1/public/phone/server/subscriptions", None),
        "recordings:read":      ("GET",   f"/api/v1/public/phone/server/calls/{zero}/recording", None),
        "calls:write":          ("PATCH", f"/api/v1/public/phone/server/calls/{zero}", {}),
        "calls:originate":      ("POST",  "/api/v1/public/phone/server/calls/originate", {}),
        "status:write":         ("PUT",   f"/api/v1/public/phone/server/extensions/{zero}/status", {}),
        "extensions:provision": ("PUT",   f"/api/v1/public/phone/server/extensions/{zero}", {}),
    }
    out = {}
    for scope, (m, p, b) in probes.items():
        code, _ = arcan(m, p, b)
        out[scope] = "missing" if code == 403 else ("invalid key" if code == 401 else "granted")
    return out


def ensure_subscriptions():
    """Create the phone.* webhook subscriptions that point at THIS backend (idempotent)."""
    url = f"https://{SETTINGS['origin']}/api/webhooks/phone"
    code, subs = arcan("GET", "/api/v1/public/phone/server/subscriptions")
    if code != 200:
        return code, {"error": (subs.get("error") if isinstance(subs, dict) else None) or f"http {code}", "needs_scope": "webhooks:manage"}
    rows = subs if isinstance(subs, list) else (subs.get("subscriptions") or [])
    have = sorted({s.get("event_type") for s in rows if (s.get("webhook_url") or "") == url and s.get("is_active", True)})
    created = []
    for et in PHONE_EVENTS:
        if et in have:
            continue
        c, d = arcan("POST", "/api/v1/public/phone/server/subscriptions",
                     {"name": f"CRM demo → {et}", "event_type": et, "target_type": "webhook", "webhook_url": url, "webhook_secret": SETTINGS.get("webhook_secret", "")})
        created.append({"event_type": et, "status": c, "id": (d.get("id") if isinstance(d, dict) else None), "error": (d.get("error") if isinstance(d, dict) and c >= 400 else None)})
    return 200, {"webhook_url": url, "already": have, "created": created,
                 "warning": None if SETTINGS["origin"] not in ("localhost", "127.0.0.1") else "ArcanFlows cannot reach localhost — deliveries will fail until this demo has a public HTTPS host"}


def masked(v):
    v = v or ""
    return {"set": bool(v), "hint": (v[:5] + "…" + v[-4:]) if len(v) > 12 else ("set" if v else "")}


# ----------------------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "crm-demo/2.0"

    def log_message(self, fmt, *a):
        print(time.strftime("%H:%M:%S"), self.address_string(), fmt % a, flush=True)

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    # --- the CRM's own identity: a bearer token this backend issued at login
    def _me(self):
        a = self.headers.get("Authorization") or ""
        tok = a[7:].strip() if a.startswith("Bearer ") else ""
        s = SESSIONS.get(tok)
        if not s or s["exp"] < time.time():
            SESSIONS.pop(tok, None)
            return None
        return USERS.get(s["user_id"])

    def _require(self, admin=False):
        u = self._me()
        if not u:
            self._json(401, {"error": "sign in to the CRM first", "code": "crm_unauthenticated"})
            return None
        if admin and u.get("role") != "admin":
            self._json(403, {"error": "CRM admins only", "code": "crm_forbidden"})
            return None
        return u

    def _target_user(self, me, body):
        """Admins may act for another CRM user ({user: id}); everyone else acts for themselves."""
        if me.get("role") == "admin" and body.get("user") and body.get("user") in USERS:
            return USERS[body["user"]]
        return me

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        path = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(path.query)
        p = path.path
        if p in SPA_PATHS:
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
            return
        if p == "/health":
            return self._json(200, {"ok": True})
        if p == "/api/config":
            return self._json(200, {"api": SETTINGS["api"], "origin": SETTINGS["origin"], "workspace_label": SETTINGS.get("workspace_label") or "an ArcanFlows workspace",
                                    "configured": bool(SETTINGS.get("pbx") and SETTINGS.get("pbxs")), "has_users": bool(USERS), "known_customers": list(CUSTOMERS.keys())})
        if p == "/api/auth/me":
            me = self._require()
            if not me:
                return
            return self._json(200, {"user": public_user(me)})

        me = self._require()
        if not me:
            return
        if p == "/api/users":
            rows = USERS.values() if me["role"] == "admin" else [me]
            return self._json(200, {"users": {u["id"]: {"name": u["name"], "email": u["email"], "role": u["role"], "external_user_id": u["external_user_id"], "how": u.get("how", "")} for u in rows}})
        if p == "/api/calls":
            rng = (q.get("range") or ["7d"])[0]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls?range={urllib.parse.quote(rng)}&limit=15")
            return self._json(code, d)
        if p == "/api/stats":
            rng = (q.get("range") or ["7d"])[0]
            code, d = arcan("GET", f"/api/v1/public/phone/server/stats?range={urllib.parse.quote(rng)}")
            return self._json(code, d)
        if p == "/api/presence":
            code, d = arcan("GET", "/api/v1/public/phone/server/presence")
            return self._json(code, d)
        if p == "/api/events":
            with LOCK:
                return self._json(200, {"events": list(EVENTS)})
        if p.startswith("/api/calls/") and p.endswith("/recording"):
            cid = p.split("/")[3]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls/{urllib.parse.quote(cid)}/recording")
            return self._json(code, d)
        if p.startswith("/api/calls/") and p.count("/") == 3:
            cid = p.split("/")[3]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls/{urllib.parse.quote(cid)}")
            return self._json(code, d)
        if p == "/api/seats":
            code, d = arcan("GET", "/api/v1/public/phone/server/seats")
            return self._json(code, d)
        if p == "/api/seat-lookup":
            # Before provisioning: does this CRM user's email already own an extension in ArcanFlows?
            # (GET /server/seats/lookup — ArcanFlows ≥ 1.1.12.6; older servers answer 404 and the page degrades.)
            target = self._target_user(me, {"user": (q.get("user") or [""])[0]})
            code, d = arcan("GET", f"/api/v1/public/phone/server/seats/lookup?email={urllib.parse.quote(target['email'])}&external_user_id={urllib.parse.quote(target['external_user_id'])}")
            return self._json(code, d)
        if p == "/api/customers":
            with LOCK:
                return self._json(200, {"customers": CUSTOMERS})

        # --- Getting started helpers
        if p == "/api/101/status":
            _, fp = arcan("GET", f"/api/v1/public/embed/frame-policy?api_key={urllib.parse.quote(SETTINGS.get('pbx', ''))}")
            allowed = fp.get("allowed_origins", []) if isinstance(fp, dict) else []
            return self._json(200, {
                "api": SETTINGS["api"], "origin": SETTINGS["origin"], "workspace_label": SETTINGS.get("workspace_label", ""),
                "pbx": {"prefix_ok": SETTINGS.get("pbx", "").startswith("pbx_"), "found": bool(isinstance(fp, dict) and fp.get("found")), "allowed_origins": allowed, "origin_allowed": origin_allowed(allowed, SETTINGS["origin"])},
                "pbxs": {"prefix_ok": SETTINGS.get("pbxs", "").startswith("pbxs_"), "scopes": probe_scopes()},
                "webhook_secret_set": bool(SETTINGS.get("webhook_secret")), "lookup_secret_set": bool(SETTINGS.get("lookup_secret")),
                "public_https": SETTINGS["origin"] not in ("localhost", "127.0.0.1"),
            })
        if p == "/api/101/subscriptions":
            code, subs = arcan("GET", "/api/v1/public/phone/server/subscriptions")
            rows = subs if isinstance(subs, list) else ((subs.get("subscriptions") or []) if isinstance(subs, dict) else [])
            url = f"https://{SETTINGS['origin']}/api/webhooks/phone"
            return self._json(code, {"webhook_url": url, "wired": sorted({s.get("event_type") for s in rows if (s.get("webhook_url") or "") == url}), "error": subs.get("error") if isinstance(subs, dict) else None})
        if p == "/api/101/recent-recorded":
            target = self._target_user(me, {"user": (q.get("user") or [""])[0]})
            ext_id = target["external_user_id"]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls?external_user_id={urllib.parse.quote(ext_id)}&limit=50")
            if code != 200:
                return self._json(code, d)
            mine = d.get("calls", [])
            rec = next((c for c in mine if c.get("has_recording")), None)
            code2, d2 = arcan("GET", "/api/v1/public/phone/server/calls?limit=100")
            mine_ids = {c["id"] for c in mine}
            other = next((c for c in d2.get("calls", []) if c["id"] not in mine_ids and c.get("has_recording")), None) if code2 == 200 else None
            return self._json(200, {"mine": rec, "mine_total": len(mine), "other": other, "external_user_id": ext_id})

        # --- admin
        if p == "/api/admin/users":
            if not self._require(admin=True):
                return
            return self._json(200, {"users": [public_user(u) for u in USERS.values()]})
        if p == "/api/admin/settings":
            if not self._require(admin=True):
                return
            out = {k: (masked(SETTINGS.get(k)) if k in SECRET_KEYS else SETTINGS.get(k, "")) for k in SETTING_KEYS}
            return self._json(200, {"settings": out, "data_dir": DATA_DIR})
        return self._json(404, {"error": "not found"})

    # ------------------------------------------------------------------ POST / PUT / DELETE
    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        raw = self._body()
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}

        # --- inbound from ArcanFlows: the signature is the credential, no CRM login
        if p == "/api/lookup":
            code, ans = lookup_answer(raw, self.headers.get("X-Webhook-Signature"))
            return self._json(code, ans)
        if p == "/api/webhooks/phone":
            ok = sig_ok(SETTINGS.get("webhook_secret", ""), raw, self.headers.get("X-Webhook-Signature"))
            ev = {"at": time.time(), "kind": "webhook", "sig_ok": ok,
                  "event_type": body.get("event_type") or self.headers.get("X-Event-Type"),
                  "event_id": self.headers.get("X-Event-ID"), "data": (body.get("data") or {})}
            with LOCK:
                EVENTS.appendleft(ev)
            return self._json(200 if ok else 401, {"received": ok})

        # --- the CRM's own auth
        if p == "/api/auth/register":
            email = (body.get("email") or "").strip().lower()
            name = (body.get("name") or "").strip()
            pw = body.get("password") or ""
            if "@" not in email or not name or len(pw) < 6:
                return self._json(400, {"error": "name, a valid email and a password of at least 6 characters are required"})
            if any(u["email"] == email for u in USERS.values()):
                return self._json(409, {"error": "an account with that email already exists"})
            uid = slug(email.split("@")[0])
            base, n = uid, 2
            while uid in USERS:
                uid, n = f"{base}{n}", n + 1
            first, _, last = name.partition(" ")
            with LOCK:
                USERS[uid] = {"id": uid, "email": email, "name": name, "first_name": first, "last_name": last or "-",
                              "role": "admin" if not USERS else "agent", "external_user_id": uid,
                              "password_hash": hash_password(pw), "how": "registered on the CRM", "created_at": time.time()}
                _save("users.json", USERS)
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = {"user_id": uid, "exp": time.time() + SESSION_TTL}
            return self._json(201, {"access_token": tok, "token_type": "crm_bearer", "expires_in": SESSION_TTL, "user": public_user(USERS[uid])})
        if p == "/api/auth/login":
            email = (body.get("email") or "").strip().lower()
            u = next((x for x in USERS.values() if x["email"] == email), None)
            if not u or not check_password(body.get("password") or "", u["password_hash"]):
                return self._json(401, {"error": "wrong email or password"})
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = {"user_id": u["id"], "exp": time.time() + SESSION_TTL}
            return self._json(200, {"access_token": tok, "token_type": "crm_bearer", "expires_in": SESSION_TTL, "user": public_user(u)})
        if p == "/api/auth/logout":
            a = self.headers.get("Authorization") or ""
            SESSIONS.pop(a[7:].strip() if a.startswith("Bearer ") else "", None)
            return self._json(200, {"ok": True})

        me = self._require()
        if not me:
            return

        # --- session mint / renew: the ONLY thing the browser needs from this backend
        if p == "/api/phone-session":
            target = self._target_user(me, body)
            # Declare the host page origin so the token is bound to it; mint by the CRM user id —
            # the CRM never knows extension ids.
            code, d = arcan("POST", "/api/v1/public/phone/session", {"external_user_id": target["external_user_id"], "origin": SETTINGS["origin"]}, key=SETTINGS.get("pbx", ""))
            if isinstance(d, dict):
                d["crm_user"] = {"id": target["id"], "external_user_id": target["external_user_id"], "role": target["role"]}
            return self._json(code, d)
        if p == "/api/phone-session/renew":
            tok = body.get("session_token", "")
            if not tok:
                return self._json(400, {"error": "session_token required"})
            code, d = arcan("POST", "/api/v1/public/phone/session", {"session_token": tok}, key=SETTINGS.get("pbx", ""))
            return self._json(code, d)

        # --- account linking: provision (or refresh) the seat for a CRM user, idempotently
        if p == "/api/link":
            target = self._target_user(me, body)
            if target["id"] != me["id"] and me["role"] != "admin":
                return self._json(403, {"error": "agents can only provision their own seat"})
            code, d = arcan("POST", "/api/v1/public/phone/server/seats", {"external_user_id": target["external_user_id"], "email": target["email"], "first_name": target["first_name"], "last_name": target["last_name"]})
            return self._json(code, d)

        if p == "/api/customers":
            phone = (body.get("phone") or "").strip(); name = (body.get("name") or "").strip()
            if not phone.startswith("+") or not name:
                return self._json(400, {"error": "phone must be E.164 (+…) and name is required"})
            with LOCK:
                CUSTOMERS[phone] = {"display_name": name, "account": body.get("account") or "Demo account", "external_ref": "NW-" + phone[-4:], "tier": body.get("tier") or "gold", "language": body.get("language") or "es"}
            return self._json(200, {"customers": CUSTOMERS})

        if p == "/api/originate":
            target = self._target_user(me, body)
            if not body.get("to"):
                return self._json(400, {"error": "to required"})
            code, d = arcan("POST", "/api/v1/public/phone/server/calls/originate", {"external_user_id": target["external_user_id"], "to": body["to"]})
            return self._json(code, d)

        # --- 101 helpers with side effects
        if p == "/api/101/subscriptions":
            if not self._require(admin=True):
                return
            code, d = ensure_subscriptions()
            return self._json(code, d)
        if p == "/api/101/lookup-selftest":
            caller = body.get("caller") or next(iter(CUSTOMERS), "+15550000000")
            sample = {"event": "caller.lookup", "tenant_id": "<your workspace id>", "caller": caller, "dialed": "+15550001234", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            raw2 = json.dumps(sample).encode()
            sig = "sha256=" + hmac.new(SETTINGS.get("lookup_secret", "").encode(), raw2, hashlib.sha256).hexdigest()
            code, ans = lookup_answer(raw2, sig, record=False)
            bad, _ = lookup_answer(raw2, "sha256=" + "0" * 64, record=False)
            return self._json(200, {"request": {"method": "POST", "url": f"https://{SETTINGS['origin']}/api/lookup",
                                                "headers": {"Content-Type": "application/json", "X-Webhook-Signature": sig, "User-Agent": "ArcanFlows-CallerLookup/1.0"}, "body": sample},
                                    "response": {"status": code, "body": ans}, "tampered_signature_status": bad})

        # --- admin: users
        if p == "/api/admin/users":
            if not self._require(admin=True):
                return
            email = (body.get("email") or "").strip().lower(); name = (body.get("name") or "").strip(); pw = body.get("password") or ""
            role = body.get("role") or "agent"
            if "@" not in email or not name or len(pw) < 6 or role not in ("admin", "agent"):
                return self._json(400, {"error": "name, a valid email, a password (6+) and role admin|agent are required"})
            if any(u["email"] == email for u in USERS.values()):
                return self._json(409, {"error": "an account with that email already exists"})
            uid = slug(body.get("id") or email.split("@")[0])
            if uid in USERS:
                return self._json(409, {"error": f"user id {uid} is taken"})
            ext = (body.get("external_user_id") or uid).strip()
            first, _, last = name.partition(" ")
            with LOCK:
                USERS[uid] = {"id": uid, "email": email, "name": name, "first_name": first, "last_name": last or "-", "role": role,
                              "external_user_id": ext, "password_hash": hash_password(pw), "how": f"created by {me['name']} on the CRM admin page", "created_at": time.time()}
                _save("users.json", USERS)
            return self._json(201, {"user": public_user(USERS[uid])})
        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        p = urllib.parse.urlparse(self.path).path
        try:
            body = json.loads(self._body() or b"{}")
        except Exception:
            body = {}
        me = self._require(admin=True)
        if not me:
            return
        if p == "/api/admin/settings":
            changed = []
            with LOCK:
                for k in SETTING_KEYS:
                    if k in body and body[k] is not None:
                        v = str(body[k]).strip()
                        if k in SECRET_KEYS and v == "":
                            continue          # an empty secret field means "keep"
                        if k == "origin":
                            v = re.sub(r"^https?://", "", v).split("/")[0]
                        if k == "api" and not v.startswith("http"):
                            v = "https://" + v
                        SETTINGS[k] = v
                        changed.append(k)
                if body.get("clear"):
                    for k in body["clear"]:
                        if k in SECRET_KEYS:
                            SETTINGS[k] = ""; changed.append(k)
                _save("settings.json", SETTINGS)
            out = {k: (masked(SETTINGS.get(k)) if k in SECRET_KEYS else SETTINGS.get(k, "")) for k in SETTING_KEYS}
            return self._json(200, {"settings": out, "changed": changed})
        if p.startswith("/api/admin/users/"):
            uid = p.split("/")[4]
            u = USERS.get(uid)
            if not u:
                return self._json(404, {"error": "no such user"})
            with LOCK:
                if body.get("role") in ("admin", "agent"):
                    if uid == me["id"] and body["role"] != "admin":
                        return self._json(400, {"error": "you cannot demote yourself"})
                    u["role"] = body["role"]
                if body.get("external_user_id") is not None:
                    u["external_user_id"] = str(body["external_user_id"]).strip() or u["id"]
                if body.get("name"):
                    u["name"] = body["name"].strip(); u["first_name"], _, last = u["name"].partition(" "); u["last_name"] = last or "-"
                if body.get("password"):
                    if len(body["password"]) < 6:
                        return self._json(400, {"error": "password must be at least 6 characters"})
                    u["password_hash"] = hash_password(body["password"])
                _save("users.json", USERS)
            return self._json(200, {"user": public_user(u)})
        return self._json(404, {"error": "not found"})

    def do_DELETE(self):
        p = urllib.parse.urlparse(self.path).path
        me = self._require(admin=True)
        if not me:
            return
        if p.startswith("/api/admin/users/"):
            uid = p.split("/")[4]
            if uid == me["id"]:
                return self._json(400, {"error": "you cannot delete yourself"})
            with LOCK:
                if USERS.pop(uid, None) is None:
                    return self._json(404, {"error": "no such user"})
                for t in [t for t, s in SESSIONS.items() if s["user_id"] == uid]:
                    SESSIONS.pop(t, None)
                _save("users.json", USERS)
            return self._json(200, {"deleted": uid})
        return self._json(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8088"))
    print(f"crm-demo listening on :{port} → {SETTINGS['api']} as origin {SETTINGS['origin']} · {len(USERS)} CRM user(s) · data in {DATA_DIR}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
