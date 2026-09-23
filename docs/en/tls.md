# Domains and TLS

OSTP can be bound to a domain name and reached over real HTTPS on port 443, with a Let's Encrypt certificate that renews itself. This is optional: plain UDP and UoT on the server's own port (50000 by default) keep working exactly as before.

This is not protocol mimicry. The server has a real certificate for a real domain and terminates real TLS, so what an observer sees is an ordinary HTTPS site. The OSTP stream travels inside that TLS unchanged. To an active prober that isn't a client, the domain looks like a web server that returns 404 (or your own site, if a fallback target is configured).

## What goes over the wire

**OSTP terminates TLS itself** (no web server on the machine, or a client connecting to the OSTP port directly):

```
TCP → TLS 1.3 (certificate for vpn.example.com)
        └─ [u16 length][OSTP datagram] [u16 length][OSTP datagram] …
```

**A web server (nginx / apache / caddy) owns 443:**

```
client ──TLS──► nginx :443 ──loopback TCP──► OSTP 127.0.0.1:50000

inside TLS:
  GET /<secret path> HTTP/1.1          Upgrade: websocket, Connection: Upgrade
  ◄ HTTP/1.1 101 Switching Protocols   (answered by OSTP, relayed by nginx)
  [u16 length][OSTP datagram] …        the same UoT frames as above
```

Only the handshake is WebSocket-shaped, because that is what makes the web server turn a request into a byte tunnel. After the `101` there is no WebSocket framing, just UoT frames. This works through nginx, apache and caddy, which relay bytes blindly after `101`. It does **not** work through CDNs that inspect WebSocket frames.

What an observer sees either way: a TLS handshake with `SNI=vpn.example.com` and `ALPN=http/1.1`, then encrypted records. TLS hides the contents; it does not hide the size and timing of the traffic.

## How the server tells connections apart

Every OSTP TCP listener looks at the first byte of a new connection:

| First byte | Meaning | Handling |
|---|---|---|
| `0x00`–`0x05` | raw UoT (high byte of a frame length ≤ 1535) | UoT, as before |
| `0x16` | TLS ClientHello | TLS with the server's certificate, then classified again |
| `A`–`Z` | HTTP request | `GET <ws_path>` with a valid upgrade → `101` + UoT; anything else → decoy |
| other | anything else | handed to the UoT reader, exactly as before |

The decoy is a bare `404`. If `fallback.enabled` is set, it is instead spliced to `fallback.target`, a real site. Classification has a 10 s deadline and an 8 KiB header limit.

The secret path is compared in constant time. A request for the right path with wrong headers gets the same decoy as any other request.

Connections from loopback are treated as a local web server. Their per-client limit (10 new connections per 10 s) is applied to `X-Real-IP` / `X-Forwarded-For`. Those headers are ignored from any other peer.

## Setting it up

On the server, as root:

```bash
ostp cert issue
```

It asks for:

1. **The domain.** Its A/AAAA record must point at this server. The command checks this and warns on a mismatch.
2. **Who serves 443.** It looks for nginx, apache and caddy:
   - **Found one:** after an explicit yes, it adds a site for the domain.
     - **What goes in:** the secret path is upgraded and proxied to OSTP, `/<webpath>/` reaches the panel (when enabled), and `/.well-known/acme-challenge/` goes to OSTP's ACME responder on `127.0.0.1:50080`. Everything else gets a 404.
     - **How it's applied:** the change is backed up, checked with the server's own config test (`nginx -t`, `apachectl configtest`, `caddy validate`) and reloaded. If either step fails, it is rolled back and the web server is left as it was.
   - **None found:** OSTP itself listens on **443** (TLS only: OSTP, the panel under `/<webpath>/`, 404 otherwise) and **80** (ACME challenges, and a redirect to https for everything else).
3. **The certificate:**
   - **caddy:** keeps issuing and renewing its own certificate; OSTP does not touch it.
   - **nginx, apache, or OSTP's own 443:** Let's Encrypt over HTTP-01. You give an optional contact email, accept the Subscriber Agreement, and can choose the staging CA for a first try. To use your own certificate instead, pass `--cert-path/--key-path`.

Then it issues the certificate, prints the share links and offers to restart the service. Non-interactive:

```bash
ostp cert issue --domain vpn.example.com --email admin@example.com --agree-tos --frontend auto --yes
```

The setup wizard (`ostp setup`, server modes) offers the same step at the end.

| Command | What it does |
|---|---|
| `ostp cert status` | domain, frontend, issuer, expiry, next renewal |
| `ostp cert renew [--force]` | renew now |
| `ostp links` | per key: the TLS link on the domain and the UDP link |
| `ostp uninstall` | also removes the site it added to nginx/apache/caddy |

Ports: open **443/tcp** (and **80/tcp** for Let's Encrypt) in the firewall. `ostp` never changes firewall rules itself.

## Renewal

When `tls.cert` is `"acme"`, the running service keeps the certificate valid.

It issues immediately when:
- there is no certificate yet, or only the self-signed placeholder;
- the certificate is a staging one while config says production, or the other way round;
- the certificate does not name the domain.

Otherwise it renews once a third of the lifetime is left (30 days for a 90-day certificate), or `renew_days_before` days before expiry.

The new certificate is swapped in without a restart. Then `reload_command` runs, so a web-server frontend picks it up.

Failures are logged and retried after 1 h, doubling up to 24 h. Before contacting Let's Encrypt, the server fetches its own challenge URL, so DNS or firewall mistakes fail fast instead of using up Let's Encrypt's failed-validation limit.

Until the first certificate is issued, a self-signed placeholder is served, so TLS and the web server's config test work from the start.

Files live next to the config:
- `certs/<domain>/{fullchain,privkey}.pem` — the key is mode 0600;
- `acme/` — the account, pending challenges, and the lock shared with the CLI.

## Server configuration

```jsonc
"domain": "vpn.example.com",   // used in share links, with or without TLS
"tls": {
  "enabled": true,
  "frontend": "builtin",        // builtin | nginx | apache | caddy
  "ws_path": "/Xk3pQ9aZr2…",     // secret upgrade path (at least 8 characters after "/")
  "cert": "acme",               // acme | manual | none (caddy)
  "cert_path": "…", "key_path": "…",  // default: <config dir>/certs/<domain>/…
  "acme": {
    "email": "admin@example.com",
    "staging": false,
    "directory": null,          // another ACME CA
    "responder": "127.0.0.1:50080",
    "renew_days_before": null
  },
  "https_listen": ["0.0.0.0:443"],  // builtin only
  "http_listen": ["0.0.0.0:80"],    // builtin only
  "public_port": 443,               // port put in share links
  "reload_command": "systemctl reload nginx || nginx -s reload"
}
```

The TLS settings are read at start: restart the service after changing them. `ostp cert issue` offers to. Certificate files are reloaded on their own.

## Clients

Transport options (UoT only):

| Field | Meaning |
|---|---|
| `tls` | wrap UoT in TLS |
| `tls_sni` | TLS server name; defaults to the host in the server address |
| `tls_insecure` | accept any certificate. **Testing only**: anyone on the path could impersonate the server |
| `ws_path` | the upgrade path; required when a web server fronts OSTP |

The certificate is checked against the bundled Mozilla root store. This works the same on Android, Windows and minimal Linux.

SNI and `Host` always use the configured name, not the resolved address, including on the NAT64 fallback.

Inside TLS, junk packets and first-packet fragmentation are skipped (encrypted, they hide nothing).

Share links carry the same options: `ostp://KEY@vpn.example.com:443?type=uot&tls=1&path=%2FXk3p…`. See the Share Links page for every parameter. The Android app and the desktop GUI have the same switches in the profile editor, with "don't verify certificate" marked as insecure.
