#!/usr/bin/env python3
"""
arcanflows-crm-demo — a deliberately tiny "third-party CRM" that integrates the
ArcanFlows phone exactly the way the public docs describe. Stdlib only, one file.

What the server does (everything a real CRM backend would do):
  GET  /                         the CRM page (static)
  POST /api/phone-session        mint a 15-minute session token for a CRM user  (uses the pbx_ key, server-side)
  POST /api/phone-session/renew  renew a session token                          (same key)
  GET  /api/calls?range=7d       call history through the pbxs_ server key
  GET  /api/stats?range=7d       statistics through the pbxs_ server key
  POST /api/originate            click-to-call from the CRM backend (pbxs_ calls:originate)
  POST /api/lookup               caller-lookup endpoint ArcanFlows can call before routing (returns a record for known numbers only)
  POST /api/webhooks/phone       phone.* webhook receiver — verifies X-Webhook-Signature, keeps the last 50 events
  GET  /api/events               the events the receiver has seen (for the page's live log)
  GET  /api/101/status           the "Getting started" page: key validity, allowed origins, effective pbxs_ scopes
  GET/POST /api/101/subscriptions  which phone.* webhooks point here / create the missing ones
  POST /api/101/lookup-selftest  a signed sample lookup run through this backend's own handler
  GET  /api/101/recent-recorded  a recorded call of the user's seat + one that is not theirs (for the permission demo)

The pbx_ and pbxs_ keys never leave this process. The browser only ever gets a session token.
"""
import hashlib, hmac, json, os, threading, time, urllib.error, urllib.parse, urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = os.environ.get("ARCAN_API", "https://api.arcanflows.com")
PBX = os.environ["PBX"]                      # pbx_… — mints sessions
PBXS = os.environ["PBXS"]                    # pbxs_… — server data key
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]        # shared with the phone.* webhook subscriptions you create
LOOKUP_SECRET = os.environ["LOOKUP_SECRET"]          # shared with the workspace's caller-lookup setting
ORIGIN = os.environ.get("CRM_ORIGIN", "localhost")  # the host page origin you declare at mint (must be on the pbx_ key allowlist)

# The CRM's own users → the ArcanFlows seat they map to. A real CRM would keep this
# in its user table; `external_user_id` is what ArcanFlows maps on its side.
# The CRM's own users. The ONLY thing ArcanFlows needs is the CRM user id (`external_user_id`);
# the workspace maps it to a seat either by an admin setting it on an existing extension, or by
# just-in-time provisioning (a CRM-only agent who never logs into ArcanFlows). Override with
# CRM_USERS='{"alice": {"name": "...", "email": "...", "first_name": "...", "last_name": "...", "how": "..."}}'.
CRM_USERS = json.loads(os.environ.get("CRM_USERS", json.dumps({
    "alice": {"name": "Alice Example", "email": "alice@example.com", "first_name": "Alice", "last_name": "Example",
              "how": "an ArcanFlows admin set External user id = \"alice\" on her existing extension"},
    "bob":   {"name": "Bob Example",   "email": "bob@example.com",   "first_name": "Bob",   "last_name": "Example",
              "how": "just-in-time: the CRM asks ArcanFlows to create his seat the first time"},
})))

# The CRM's "customer database" for caller lookup. Only these numbers are known; every
# other caller gets a 404 so production routing is unaffected for real callers.
CUSTOMERS = json.loads(os.environ.get("CRM_CUSTOMERS", "{}"))

EVENTS = deque(maxlen=50)
LOCK = threading.Lock()


def arcan(method, path, body=None, key=None, extra=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + (key or PBXS))
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
    if not header:
        return False
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)


# The phone events a CRM normally wants. (There is no phone.call.started.)
PHONE_EVENTS = ["phone.call.ringing", "phone.call.answered", "phone.call.completed",
                "phone.call.missed", "phone.call.transferred", "phone.status.changed"]


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
    if not sig_ok(LOOKUP_SECRET, raw, sig):
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
        code, d = arcan(m, p, b)
        out[scope] = "missing" if code == 403 else ("invalid key" if code == 401 else "granted")
    return out


def ensure_subscriptions():
    """Create the phone.* webhook subscriptions that point at THIS backend (idempotent)."""
    url = f"https://{ORIGIN}/api/webhooks/phone"
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
                     {"name": f"CRM demo → {et}", "event_type": et, "target_type": "webhook", "webhook_url": url, "webhook_secret": WEBHOOK_SECRET})
        created.append({"event_type": et, "status": c, "id": (d.get("id") if isinstance(d, dict) else None), "error": (d.get("error") if isinstance(d, dict) and c >= 400 else None)})
    return 200, {"webhook_url": url, "already": have, "created": created,
                 "warning": None if ORIGIN not in ("localhost", "127.0.0.1") else "ArcanFlows cannot reach localhost — deliveries will fail until this demo has a public HTTPS host"}


class H(BaseHTTPRequestHandler):
    server_version = "crm-demo/1.0"

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

    def do_GET(self):
        path = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(path.query)
        # Single-page app: every CRM page path serves the shell; the page is rendered client-side.
        if path.path in ("/", "/index.html", "/contacts", "/deals", "/tickets", "/integration", "/getting-started"):
            with open(os.path.join(os.path.dirname(__file__), "index.html"), "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path.path == "/api/calls":
            rng = (q.get("range") or ["7d"])[0]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls?range={urllib.parse.quote(rng)}&limit=15")
            return self._json(code, d)
        if path.path == "/api/stats":
            rng = (q.get("range") or ["7d"])[0]
            code, d = arcan("GET", f"/api/v1/public/phone/server/stats?range={urllib.parse.quote(rng)}")
            return self._json(code, d)
        if path.path == "/api/presence":
            code, d = arcan("GET", "/api/v1/public/phone/server/presence")
            return self._json(code, d)
        if path.path == "/api/events":
            with LOCK:
                return self._json(200, {"events": list(EVENTS)})
        if path.path.startswith("/api/calls/") and path.path.endswith("/recording"):
            cid = path.path.split("/")[3]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls/{urllib.parse.quote(cid)}/recording")
            return self._json(code, d)
        if path.path.startswith("/api/calls/") and path.path.count("/") == 3:
            cid = path.path.split("/")[3]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls/{urllib.parse.quote(cid)}")
            return self._json(code, d)
        if path.path == "/api/seats":
            code, d = arcan("GET", "/api/v1/public/phone/server/seats")
            return self._json(code, d)
        if path.path == "/api/users":
            return self._json(200, {"users": CRM_USERS})
        if path.path == "/api/customers":
            with LOCK:
                return self._json(200, {"customers": CUSTOMERS})
        if path.path == "/api/config":
            return self._json(200, {"api": API, "origin": ORIGIN, "workspace_label": os.environ.get("WORKSPACE_LABEL", "your ArcanFlows workspace"), "users": {k: {"name": v["name"], "how": v["how"]} for k, v in CRM_USERS.items()}, "known_customers": list(CUSTOMERS.keys())})

        # --- "Getting started" page helpers (each step of the 101 runs one of these)
        if path.path == "/api/101/status":
            # frame policy is anonymous: it tells us whether the pbx_ key exists and which hosts it allows
            _, fp = arcan("GET", f"/api/v1/public/embed/frame-policy?api_key={urllib.parse.quote(PBX)}")
            allowed = fp.get("allowed_origins", []) if isinstance(fp, dict) else []
            return self._json(200, {
                "api": API, "origin": ORIGIN,
                "pbx": {"prefix_ok": PBX.startswith("pbx_"), "found": bool(isinstance(fp, dict) and fp.get("found")), "allowed_origins": allowed, "origin_allowed": origin_allowed(allowed, ORIGIN)},
                "pbxs": {"prefix_ok": PBXS.startswith("pbxs_"), "scopes": probe_scopes()},
                "webhook_secret_set": bool(WEBHOOK_SECRET), "lookup_secret_set": bool(LOOKUP_SECRET),
                "public_https": ORIGIN not in ("localhost", "127.0.0.1"),
            })
        if path.path == "/api/101/subscriptions":
            code, subs = arcan("GET", "/api/v1/public/phone/server/subscriptions")
            rows = subs if isinstance(subs, list) else ((subs.get("subscriptions") or []) if isinstance(subs, dict) else [])
            url = f"https://{ORIGIN}/api/webhooks/phone"
            return self._json(code, {"webhook_url": url, "wired": sorted({s.get("event_type") for s in rows if (s.get("webhook_url") or "") == url}), "error": subs.get("error") if isinstance(subs, dict) else None})
        if path.path == "/api/101/recent-recorded":
            user = (q.get("user") or [""])[0]
            code, d = arcan("GET", f"/api/v1/public/phone/server/calls?external_user_id={urllib.parse.quote(user)}&limit=50")
            if code != 200:
                return self._json(code, d)
            mine = d.get("calls", [])
            rec = next((c for c in mine if c.get("has_recording")), None)
            code2, d2 = arcan("GET", "/api/v1/public/phone/server/calls?limit=100")
            mine_ids = {c["id"] for c in mine}
            other = next((c for c in d2.get("calls", []) if c["id"] not in mine_ids and c.get("has_recording")), None) if code2 == 200 else None
            return self._json(200, {"mine": rec, "mine_total": len(mine), "other": other})
        if path.path == "/health":
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        raw = self._body()
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}

        # --- session mint / renew: the ONLY thing the browser needs from this backend
        if path == "/api/phone-session":
            user = CRM_USERS.get(body.get("user", ""))
            if not user:
                return self._json(404, {"error": "unknown CRM user"})
            # Declare the host page origin so the token is bound to it (the docs' recommendation).
            # Mint by the CRM user id — the CRM never knows extension ids.
            code, d = arcan("POST", "/api/v1/public/phone/session", {"external_user_id": body.get("user"), "origin": ORIGIN}, key=PBX)
            return self._json(code, d)
        if path == "/api/phone-session/renew":
            tok = body.get("session_token", "")
            if not tok:
                return self._json(400, {"error": "session_token required"})
            code, d = arcan("POST", "/api/v1/public/phone/session", {"session_token": tok}, key=PBX)
            return self._json(code, d)

        # --- account linking: provision (or refresh) the seat for a CRM user, idempotently
        if path == "/api/link":
            u = CRM_USERS.get(body.get("user", ""))
            if not u:
                return self._json(404, {"error": "unknown CRM user"})
            code, d = arcan("POST", "/api/v1/public/phone/server/seats", {"external_user_id": body["user"], "email": u["email"], "first_name": u["first_name"], "last_name": u["last_name"]})
            return self._json(code, d)

        # --- the CRM's customer database (in memory): who caller lookup will recognise
        if path == "/api/customers":
            phone = (body.get("phone") or "").strip(); name = (body.get("name") or "").strip()
            if not phone.startswith("+") or not name:
                return self._json(400, {"error": "phone must be E.164 (+…) and name is required"})
            with LOCK:
                CUSTOMERS[phone] = {"display_name": name, "account": body.get("account") or "Demo account", "external_ref": "NW-" + phone[-4:], "tier": body.get("tier") or "gold", "language": body.get("language") or "es"}
            return self._json(200, {"customers": CUSTOMERS})

        # --- click-to-call from the CRM backend
        if path == "/api/originate":
            user = CRM_USERS.get(body.get("user", ""))
            if not user or not body.get("to"):
                return self._json(400, {"error": "user and to required"})
            code, d = arcan("POST", "/api/v1/public/phone/server/calls/originate", {"external_user_id": body.get("user"), "to": body["to"]})
            return self._json(code, d)

        # --- caller lookup: ArcanFlows asks "who is calling?" before routing
        if path == "/api/lookup":
            code, ans = lookup_answer(raw, self.headers.get("X-Webhook-Signature"))
            return self._json(code, ans)

        # --- 101 helpers with side effects
        if path == "/api/101/subscriptions":
            code, d = ensure_subscriptions()
            return self._json(code, d)
        if path == "/api/101/lookup-selftest":
            # Build exactly what ArcanFlows would send, sign it with the shared secret, and run
            # it through this backend's own lookup handler — plus a tampered signature to show
            # the refusal. Nothing is recorded in the live log.
            caller = body.get("caller") or next(iter(CUSTOMERS), "+15550000000")
            sample = {"event": "caller.lookup", "tenant_id": "<your workspace id>", "caller": caller, "dialed": "+15550001234", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            raw2 = json.dumps(sample).encode()
            sig = "sha256=" + hmac.new(LOOKUP_SECRET.encode(), raw2, hashlib.sha256).hexdigest()
            code, ans = lookup_answer(raw2, sig, record=False)
            bad, _ = lookup_answer(raw2, "sha256=" + "0" * 64, record=False)
            return self._json(200, {
                "request": {"method": "POST", "url": f"https://{ORIGIN}/api/lookup",
                            "headers": {"Content-Type": "application/json", "X-Webhook-Signature": sig, "User-Agent": "ArcanFlows-CallerLookup/1.0"},
                            "body": sample},
                "response": {"status": code, "body": ans},
                "tampered_signature_status": bad,
            })

        # --- phone.* webhooks
        if path == "/api/webhooks/phone":
            ok = sig_ok(WEBHOOK_SECRET, raw, self.headers.get("X-Webhook-Signature"))
            ev = {
                "at": time.time(), "kind": "webhook", "sig_ok": ok,
                "event_type": body.get("event_type") or self.headers.get("X-Event-Type"),
                "event_id": self.headers.get("X-Event-ID"),
                "data": (body.get("data") or {}),
            }
            with LOCK:
                EVENTS.appendleft(ev)
            return self._json(200 if ok else 401, {"received": ok})
        return self._json(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8088"))
    print(f"crm-demo listening on :{port} → {API} as origin {ORIGIN}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
