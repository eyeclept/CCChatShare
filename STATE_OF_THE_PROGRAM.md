# State of the program

CCChatShare is a finished service for its current design. Assist/TODO.md has no blocking work.

Production host: `https://chatshare.blue-bly.com`. The Flask app runs in a podman container on `172.27.72.60`. cloudflared on that VM is the only ingress.

Latest commits on `master`:

- `7489b81` Secrets scanning + security audit fixes, redeployed and verified
- `e01d00c` Cloudflare Tunnel for CCChatShare, first real chat pushed
- `92f6aff` CCChatShare: Flask app + admin TUI + CLI push, deployed via podman

The repo has no git remote.

## Done work

The Flask app serves `/`, `/c/<slug>`, `/c/<slug>/unlock`, `/c/<slug>/tools`, and `POST /api/chats`.

SQLite in WAL mode holds one `chats` table. The table stores a hash of each access code. Create and regenerate return the plaintext code once.

Auth uses an itsdangerous cookie. The cookie binds to slug, `token_version`, and an `access_code_hash` fingerprint.

`ChatGate` loads only the columns needed for the pre-auth check. The gate query skips markdown until the cookie or code passes.

Flask-Limiter allows 5 failed code attempts per 5 minutes per (visitor IP, slug). The key is `Cf-Connecting-Ip`.

Every push runs detect-secrets before persist. Hits become `[REDACTED:<type>]`. The scanner removes PEM blocks as a whole. The JSON response includes `secrets_redacted`.

The admin TUI lists chats and can regenerate, revoke, or delete.

`deploy/deploy.sh` rsyncs, builds, and restarts the quadlet unit. First boot writes `/opt/ccchatshare/data/secrets.env`.

A three-surface security audit on 2026-07-30 found High and Medium issues. The same session fixed those issues and redeployed.

`tests/` has 45 pytest tests. They cover models, HTTP routes, lockout, cookies, the admin API, and secret redaction.

## Leftover items

The operator deferred these items on purpose. They are not oversights.

- Cloudflare Access on `/api/*`. The admin API is reachable on the public host. The gate today is the bearer token, a 10-per-hour limit, and a 4 MB body cap. A Zero Trust policy would hide `/api/*` from the open internet. That needs Cloudflare Zero Trust access this project does not have configured.

- Digest pin for `FROM python:3.12-slim`. Rebuilds follow the tag. Digest pins need a refresh workflow this repo does not have.

- Host VM policy: passwordless sudo for `eyeclept`, a stale `rocky` sudoers line, Cockpit on `*:9090`. These are VM-wide. They sit outside the project fence.

## Known limits

- After regenerate, revoke, or delete, the TUI table cursor returns to row 0. The action still hits the selected row. Select again before the next key.

- Flask-Limiter counters live in process memory. A container restart clears them.

- `export_chat.py --online` does not print `secrets_redacted`. The server still redacts.

- html5lib inside bleach can drop a tail of HTML on some foreign-content mixes. The render module logs a warning when output shrinks far more than tag strip would explain.

- The CLI is in `~/Documents/Code/Scripts/export_chat.py`, not this tree.

## How far along

Stage label from the project audit: complete-dev-without-todo.

The operator pushed a real chat through this host. The public host, the access-code flow, the admin TUI, and the CLI push path all work.

Assist/TODO.md queues no further feature work.
