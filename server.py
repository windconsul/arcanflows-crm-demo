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
        if path.path in ("/", "/index.html", "/contacts", "/deals", "/tickets", "/integration"):
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
            if not sig_ok(LOOKUP_SECRET, raw, self.headers.get("X-Webhook-Signature")):
                with LOCK:
                    EVENTS.appendleft({"at": time.time(), "kind": "lookup", "note": "BAD SIGNATURE", "caller": body.get("caller")})
                return self._json(401, {"error": "bad signature"})
            caller = body.get("caller", "")
            rec = CUSTOMERS.get(caller)
            with LOCK:
                EVENTS.appendleft({"at": time.time(), "kind": "lookup", "caller": caller, "known": bool(rec)})
            if not rec:
                return self._json(404, {"known": False})
            return self._json(200, dict(rec, known=True))

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
