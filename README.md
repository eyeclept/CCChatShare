# CCChatShare

CCChatShare hosts a Claude chat behind a private URL and an 8-character access code.

It is a companion to Claude webui share links. Use it for exports from `export_chat.py`, not Claude Code.

A visitor opens `/c/<slug>`. With no valid cookie, the app shows an access-code form. The form hides the chat title. A correct code sets a signed cookie for that chat only. The cookie lasts 180 days. A new access code invalidates every old cookie.

The site has no directory, no listing, and no search.

## How a share works

1. The CLI posts markdown to `POST /api/chats` with a bearer token.
2. The server scans the body for secrets and stores the chat.
3. The response returns a 10-character slug and an 8-character access code.
4. The recipient opens the slug URL and enters the code.

Slugs are 10 lowercase characters. Codes are 8 uppercase characters. Both alphabets drop 0, O, 1, I, and L.

The live public host is `https://chatshare.blue-bly.com`.

## What is in this repo

- `app/` Flask factory, routes, sqlite DAO, cookie helpers, markdown render, secrets scan
- `app/templates/` and `app/static/` HTML plus the newspaper stylesheet
- `admin_tui.py` Textual TUI: new access code, revoke, delete
- `wsgi.py` gunicorn entry
- `Containerfile` and `deploy/` podman quadlet deploy
- `tests/` 45 pytest tests

The push client is not in this repo. It lives at `~/Documents/Code/Scripts/export_chat.py`.

## Storage

One sqlite table named `chats`. Columns: slug, title, access_code_hash, token_version, markdown, tools_markdown, created_at, revoked, view_count, last_viewed_at.

The table stores a hash of the access code. It does not store the plaintext code.

`ChatGate` loads only the columns needed before auth. The gate fetches full markdown after the cookie or code passes.

## Secrets scan

Every `POST /api/chats` body runs through `app/secrets_scan.py` before persist. The scan uses detect-secrets. Hits become `[REDACTED:<type>]`. The scanner strips PEM private-key blocks as a whole. The JSON response includes `secrets_redacted`.

The server is the enforcement point. The client is not trusted to scan first.

## Local run

Full install steps are in SETUP.md.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
SECRET_KEY=dev CCCHATSHARE_ADMIN_TOKEN=dev \
  CCCHATSHARE_DB_PATH=./local-data/ccchatshare.db \
  CCCHATSHARE_COOKIE_INSECURE=1 \
  .venv/bin/python wsgi.py
```

Keep the sqlite file under the project directory. Do not use `/tmp`. That directory is world-writable and a fixed name can be hijacked.

## Admin TUI

Run the TUI inside the production container. SETUP.md has the host and the command.

Keys:

- `r` make a new access code (shown once in a modal)
- `x` toggle revoked or active
- `d` delete the chat (asks for confirm)
- `q` quit

After a change, the table cursor returns to row 0. Select the row again before the next action.

## Docs

- SETUP.md: env vars, local install, podman deploy, Cloudflare tunnel
- STATE_OF_THE_PROGRAM.md: done work, leftover items, known limits
