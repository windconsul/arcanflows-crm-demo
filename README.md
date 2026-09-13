# arcanflows-crm-demo

A deliberately tiny "third-party CRM" that embeds the **ArcanFlows phone** the way a real
CRM or ERP would: the phone floats over a multi-page app, calls survive navigation,
the CRM knows who is calling before the phone rings, every call event reaches the CRM
backend as a signed webhook, and call history, statistics, presence and recordings are
read through a scoped server key.

It is one Python file (standard library only) and one HTML file. No framework, no build
step. It exists to be read.

```
┌────────────────────────────── browser (your CRM page) ──────────────────────────────┐
│  Dashboard · Contacts · Deals · Tickets · Integration     (client-side routing)     │
│                                                                                     │
│   ┌── floating dock ─────────────┐   phone.js from app.arcanflows.com mounts an     │
│   │  <iframe app.arcanflows.com/ │   iframe here ONCE; pages change underneath it,  │
│   │   embed/phone?session=…>     │   so a live call is never interrupted            │
│   └──────────────────────────────┘                                                  │
└───────────────┬──────────────────────────────────────────────┬──────────────────────┘
                │ 15-minute session token only                 │ fetch /api/… (same origin)
                ▼                                              ▼
      api.arcanflows.com                              server.py (this repo — "the CRM backend")
      ▲   ▲   ▲   ▲                                   holds pbx_ and pbxs_ keys, never the browser
      │   │   │   └── POST …/phone/session  {external_user_id}   ← mint / renew sessions (pbx_)
      │   │   └────── GET  …/phone/server/calls|stats|presence   ← history & KPIs        (pbxs_)
      │   └────────── POST …/phone/server/calls/originate         ← click-to-call        (pbxs_)
      └────────────── POST …/phone/server/seats                   ← just-in-time seats  (pbxs_)
                │
                │  ArcanFlows → your backend (HTTPS, HMAC-signed)
                ├─► POST /api/lookup           "who is calling?" before the call is routed
                └─► POST /api/webhooks/phone   phone.call.ringing / answered / completed / missed …
```

## Start here: the "Getting started" page

Open **Getting started** in the demo's top bar. It is the integration in ten
numbered steps, and every step runs live: the page asks the demo backend, the
backend talks to ArcanFlows with the keys it holds, and you see what was sent
and what came back.

1. Create the two keys and point them at this app (checks key validity, the
   allowed origins, and the `pbxs_` key's *effective* scopes)
2. Link a CRM user to a seat (`external_user_id`)
3. Mint a 15-minute session for the signed-in user
4. Call the browser API with the session — who am I? (`web_capable`)
5. Mount the widget once, outside your pages
6. Subscribe to phone events and receive a signed webhook (creates the
   subscriptions, flips the phone's status, waits for the delivery, verifies
   the signature)
7. Answer "who is calling?" — caller lookup, with a tampered-signature check
8. Read a call and its recording — the two permissions, side by side
9. Renew before expiry; guard against reloads
10. Go to production — the checklist

## What the demo shows

| On the page | What it proves |
|---|---|
| **Integration → Connect phone** | The backend exchanges its `pbx_` key for a 15-minute session for *its own user id*; the phone mounts; renewal is automatic and silent |
| **Account linking** | How a CRM user becomes an ArcanFlows seat (see below), with a live trace of the actual request and answer |
| Navigate Dashboard → Contacts → Deals → Tickets during a call | The phone is mounted once in a floating dock; client-side navigation never touches it |
| **Dashboard → click a call** | Detail through the server key, and the recording playable **two ways** — as this user (ArcanFlows checks they were on the call) and as the backend (tenant-wide) |
| **Contacts → Known customers**, then call in | Caller lookup: ArcanFlows asks this backend who is calling, greets the caller by name, and the page logs the screen-pop |
| **Live event log** (Integration) | Widget events in the browser, plus webhooks and lookups received by the backend with their signature verified |
| Reload during a call | The browser asks first — a full page load destroys the phone; the demo guards against it |

## Two identities, on purpose

The CRM has **its own accounts**: register, sign in, and an admin page to create
users with a role (`admin` or `agent`). The CRM issues its own bearer token and
the page keeps it in this origin's `localStorage` under `access_token`, the
most common key name there is. That token decides who you are *in the CRM*.
The phone knows nothing about it: the backend mints an ArcanFlows session for
the signed-in user's `external_user_id`, and that session is the widget's only
identity. Sign in as a different CRM user and the phone follows; sign out and
the phone is unmounted. Neither token can reach the other's origin.

The admin page also holds the **ArcanFlows workspace** the CRM talks to: API
base, the `pbx_` and `pbxs_` keys, both secrets, the declared origin and a
label. Paste the keys of any tenant and the whole demo points there; *Test
connection* checks the embed key's allow-list and probes the server key's
effective scopes. Nothing about a tenant is in the code.

## Run it

```bash
cp .env.example .env        # optional seeds: keys, secrets, CRM_ORIGIN, CRM_USERS + CRM_SEED_PASSWORD
docker compose up -d        # or: PORT=8088 python3 server.py
open http://localhost:8088  # → /register: the first account becomes the CRM admin
```

State lives in `data/` (`users.json`, `settings.json`, mode 600). Environment
variables only seed the first boot; after that the admin page is the source of
truth. Passwords are PBKDF2-hashed; CRM sessions last 12 hours and live in
memory (a restart signs everyone out of the CRM, never out of ArcanFlows).

ArcanFlows only calls **public HTTPS** URLs for lookups and webhooks, so for those two
features put the demo behind a real hostname (see `Caddyfile.example`). Sessions,
history and click-to-call work from `localhost` as long as `CRM_ORIGIN` matches what the
browser sends and is on the `pbx_` key's allowlist.

## Set-up in ArcanFlows (once, by a workspace admin)

1. **Phone System → Integrations → Embed keys → New key.** Add your page's host to
   *Allowed origins*. Copy the `pbx_` key into `PBX`.
2. **Server keys → New server key** with the scopes you need. The demo uses
   `calls:read stats:read presence:read extensions:read recordings:read calls:originate
   webhooks:manage seats:provision`. Copy it into `PBXS`.
3. **Link users.** On an existing extension set *External user id* to your CRM's user id
   (that is `alice` in the sample config). Users who will only ever use the phone from
   your CRM can be provisioned just in time instead (the *Provision seat* button).
4. **Webhooks** — the backend can create them itself with `webhooks:manage`:
   ```bash
   curl -X POST https://api.arcanflows.com/api/v1/public/phone/server/subscriptions \
     -H "Authorization: Bearer $PBXS" -H "Content-Type: application/json" -A "my-crm/1.0" \
     -d '{"name":"CRM → completed","event_type":"phone.call.completed","target_type":"webhook",
          "webhook_url":"https://crm.example.com/api/webhooks/phone","webhook_secret":"<WEBHOOK_SECRET>"}'
   ```
   Repeat for `phone.call.ringing`, `answered`, `missed`, `transferred`, `phone.status.changed`.
5. **Caller lookup** — Phone System → Integrations → Caller lookup: URL
   `https://crm.example.com/api/lookup`, secret `<LOOKUP_SECRET>`, timeout 800 ms. Unknown
   callers get a `404` from this backend, so routing is unaffected for them; known ones are
   greeted by name and their record pops on the ringing phone.

## How a CRM user is linked to an ArcanFlows user

Every ArcanFlows extension belongs to an ArcanFlows user and carries an optional
**External user id** — "the id this seat is known by in your system". Your backend never
sends emails or extension ids. It mints a session with

```json
{ "external_user_id": "alice", "origin": "crm.example.com" }
```

and ArcanFlows returns the extension that carries `alice`. The id gets onto an extension in
one of two ways:

- **An admin types it** on an existing extension (Phone System → Extensions → edit). This
  is how you link people who already have a seat.
- **Your backend asks for a seat just in time** — `POST /api/v1/public/phone/server/seats`
  with the id, an email and a name (`seats:provision`). ArcanFlows creates a phone-only
  identity and a **new** extension already carrying the id. For agents who only ever use
  the phone from your CRM.

Just-in-time never re-maps an existing extension; attaching a CRM id to someone who
already has a seat is deliberately the admin's decision.

## Who can see a call's details and audio

| Through | Who is asking | What it can see | Link life |
|---|---|---|---|
| Session token (the phone in the browser) — `GET /api/v1/public/phone/calls/{id}`, `…/recording` | one signed-in seat | **only calls that seat was on**; anything else answers `404` | 10 min |
| Server key — `GET /api/v1/public/phone/server/calls/{id}`, `…/recording` (`recordings:read`) | your backend, for the whole workspace | every call: detail, summary, transcript turns, CRM references | 1 hour |

ArcanFlows enforces the per-user rule on the session path. On the server path it is
**your** rule: when your backend fetches a recording tenant-wide, your CRM decides which
of its users may press play. Links are signed and expire; treat one like the audio itself.

## Things a real integration must know

- **Sessions last 15 minutes and are renewed ~3 minutes before expiry** through
  `onRenewToken`. The token gates the API and the realtime socket, not the audio; the
  media session is bounded by the call itself (4 h). A call of any length continues as
  long as renewal works. If renewal fails, the server closes the socket at expiry and the
  phone ends the call after a 10-second grace.
- **A full page load destroys the phone.** Render your pages client-side (as this demo
  does) or keep the phone in a separate window. While a call is live the SDK, and this
  page, register the browser's leave prompt.
- **Send a real `User-Agent` from your server.** The API sits behind Cloudflare, which
  answers `403` to library defaults such as `Python-urllib/3.x`.
- **Signatures.** Webhooks and lookups carry `X-Webhook-Signature: sha256=<hex>`, an
  HMAC-SHA256 of the raw body with the secret you configured. `server.py` verifies both.
- **Deliveries are at-least-once**, retried for about 17 minutes on the phone event
  types; treat every event as a snapshot keyed by `call_id`.

## Messaging (SMS/MMS) — ArcanFlows v1.1.13.x

The same seat that answers calls can text. Nothing here needs a new key: the
`pbx_` session and the `pbxs_` server key gain messaging routes, and the
widget gains a **Messages** tab beside the dialpad.

**In the widget.** Your CRM user sees their own conversations, the shared
inbox (with *Claim*), a reply box with an MMS link and *New*. To open a
prefilled compose from your page (click-to-text), post the twin of the dial
command into the iframe:

```js
iframe.contentWindow.postMessage({ source: 'arcanflows-host', type: 'text', to: '+14045550123' }, ARCANFLOWS_ORIGIN);
```

The widget posts two new events to the host, next to `ring` / `call_started`:
`message_received` (`{ thread_id, message_id, from, to, preview, owner_extension_id, unassigned }`)
and `message_updated` (a thread changed: sent, delivered, claimed, assigned).
Use them to refresh your own view; the truth is always the API.

**From your server (`pbxs_`).** Three scopes, none granted by default:

| Scope | What it allows |
|---|---|
| `messages:read` | `GET /server/messages/threads` (tenant-wide; filter by `external_user_id`, `extension`, `contact`, `status`, `unassigned=1`), `GET /server/messages/threads/{id}`, `GET /server/messages/usage?external_user_id=` |
| `messages:send` | `POST /server/messages` `{ external_user_id, thread_id | to, body, media_urls? }` — sends **as that seat**, never as the key, through the seat's own gate (authorization, allowance, opt-out, quiet hours, quota); refusals name their reason |
| `messages:manage` | `POST /server/messages/threads/{id}/assign` `{ external_user_id }` |

**Webhooks.** Subscribe with `webhooks:manage` to `phone.message.received`
(carries the caller context your lookup endpoint returned), `phone.message.sent`,
`phone.message.delivered`, `phone.message.failed` (carrier code),
`phone.message.opted_out` (mark the contact — nothing can be sent until they
text START) and `phone.user.suspended`. Every payload carries the seat with
its `external_user_id`, exactly like the call events.

## Files

| File | Role |
|---|---|
| `server.py` | the CRM backend: its own accounts and admin settings, session mint/renew, server-key proxies, click-to-call, seat provisioning, caller-lookup endpoint, webhook receiver |
| `index.html` | the CRM: login, register and admin pages, five client-side app pages, Getting started, the floating phone dock, the call drawer, the event log |
| `.env.example` | first-boot seeds, documented |
| `Dockerfile`, `docker-compose.yml`, `Caddyfile.example` | run it anywhere behind HTTPS |

## Endpoints implemented by `server.py`

| Method & path | Talks to | Key |
|---|---|---|
| `POST /api/auth/register` · `/login` · `/logout` · `GET /api/auth/me` | the CRM's own accounts (first registration = admin) | — |
| `GET/POST /api/admin/users` · `PUT/DELETE /api/admin/users/{id}` | CRM users: role, `external_user_id`, password reset | — |
| `GET/PUT /api/admin/settings` | the ArcanFlows workspace (keys masked on read, write-only) | — |
| `POST /api/phone-session` (signed-in user; admins may pass `{user}`) | `POST /api/v1/public/phone/session` `{external_user_id, origin}` | `pbx_` |
| `POST /api/phone-session/renew` `{session_token}` | same route with `{session_token}` | `pbx_` |
| `GET /api/calls?range=7d` · `GET /api/calls/{id}` · `GET /api/calls/{id}/recording` | `/api/v1/public/phone/server/calls…` | `pbxs_` |
| `GET /api/stats?range=7d` · `GET /api/presence` · `GET /api/seats` | `/api/v1/public/phone/server/{stats,presence,seats}` | `pbxs_` |
| `POST /api/originate` `{user, to}` | `POST …/server/calls/originate` `{external_user_id, to}` | `pbxs_` |
| `POST /api/link` `{user}` | `POST …/server/seats` `{external_user_id, email, first_name, last_name}` | `pbxs_` |
| `POST /api/lookup` ← ArcanFlows | answers `{display_name, account, external_ref, tier, language}` or `404` | signed |
| `POST /api/webhooks/phone` ← ArcanFlows | stores the last 50 events for the page's log | signed |
| `GET/POST /api/customers` | the in-memory customer list the lookup answers from | — |
| `GET /api/101/status` | frame policy of the `pbx_` key + one harmless probe per scope to learn what the `pbxs_` key can do | both |
| `GET/POST /api/101/subscriptions` | which `phone.*` subscriptions point at this host / create the missing ones | `pbxs_` |
| `POST /api/101/lookup-selftest` | a signed sample lookup run through this backend's own handler, plus a tampered one | — |
| `GET /api/101/recent-recorded?user=` | a recorded call of the user's seat and one that is not theirs | `pbxs_` |

## Reference documentation

- Phone API quickstart and interactive reference: `https://app.arcanflows.com/documentation/api/phone`
- OpenAPI (phone-only): `https://api.arcanflows.com/api/v1/public/phone/openapi.json`
- Widget loader: `https://app.arcanflows.com/embed/phone.js`

MIT licensed. This is a demonstration, not a product: the customer list is in memory,
there is no authentication on the demo's own pages, and secrets come from `.env`.
