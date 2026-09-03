# SETUP

This file covers local install, environment variables, production deploy, and the Cloudflare tunnel.

## Requirements

- Python 3.12
- pip
- For production: podman, rsync, ssh to the VM, and a native cloudflared service on that VM

`requirements.txt` pins these Python packages:

- Flask 3.0.3
- Flask-Limiter 3.8.0
- itsdangerous 2.2.0
- Werkzeug 3.0.6
- gunicorn 23.0.0

- Markdown 3.6
- bleach 6.1.0
- textual 0.79.1
- detect-secrets 1.5.0

## Environment variables

Required:

- `SECRET_KEY` signs auth cookies. An empty value stops the process.
- `CCCHATSHARE_ADMIN_TOKEN` gates `POST /api/chats`. An empty value stops the process.

Optional:

- `CCCHATSHARE_DB_PATH` sqlite file. Default `/data/ccchatshare.db`.
- `CCCHATSHARE_HOST` bind host for the Flask dev server. Default `0.0.0.0`.
- `CCCHATSHARE_PORT` bind port. Default `8080`.

- `CCCHATSHARE_COOKIE_INSECURE` set to `1` to drop the cookie Secure flag. Use this only on plain HTTP.
- `LOG_LEVEL` logging level in `wsgi.py`. Default `INFO`.

The process does not invent a secret when one is absent. `load_config()` raises `RuntimeError`.

Request bodies larger than 4 MB get HTTP 413. That cap is a code default, not an env var.

Cookie max age is 180 days. That value is a code default.

## Local install

1. Create a virtualenv in the project root.
2. Install the packages in `requirements.txt`.
3. Set the two required secrets in the shell.
4. Point `CCCHATSHARE_DB_PATH` at a sqlite file under the project directory.
5. Set `CCCHATSHARE_COOKIE_INSECURE=1` for plain HTTP.
6. Run `wsgi.py` with the venv Python.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
SECRET_KEY=dev CCCHATSHARE_ADMIN_TOKEN=dev \
  CCCHATSHARE_DB_PATH=./local-data/ccchatshare.db \
  CCCHATSHARE_COOKIE_INSECURE=1 \
  .venv/bin/python wsgi.py
```

Keep the sqlite file under the project directory. Do not use `/tmp`. That directory is world-writable and a fixed name can be hijacked.

## Tests

pytest is not in `requirements.txt`. Install it, then run the suite.

```bash
.venv/bin/pip install pytest
.venv/bin/pytest tests/
```

The suite has 45 tests. Files: `tests/test_models.py`, `tests/test_routes.py`, `tests/test_security.py`.

## CLI config

The push client reads `~/.config/ccchatshare/config.json`.

```json
{
  "base_url": "https://chatshare.blue-bly.com",
  "api_token": "<CCCHATSHARE_ADMIN_TOKEN>"
}
```

Copy the token from `/opt/ccchatshare/data/secrets.env` after the first container boot.

The client lives at `~/Documents/Code/Scripts/export_chat.py`. It is not in this repo.

```bash
python3 export_chat.py --online
python3 export_chat.py --full --online
```

`--online` still writes the local `.md` file. Then it POSTs to `/api/chats`.

## Production deploy

The target VM is `172.27.72.60` (Rocky Linux). `deploy/deploy.sh` is the path from this workstation.

1. Run `bash deploy/deploy.sh` from the project root.
2. Wait for rsync, `podman build`, quadlet install, and `systemctl restart`.
3. On first boot, read `/opt/ccchatshare/data/secrets.env`.
4. Put `CCCHATSHARE_ADMIN_TOKEN` into `~/.config/ccchatshare/config.json`.

The script:

- rsyncs the tree to `eyeclept@172.27.72.60:/home/eyeclept/ccchatshare-src/`
- skips `.git`, `__pycache__`, `.venv`, `Assist`, `tests`, and secret or db files
- stops if the systemd unit exists and `/opt/ccchatshare/data` is absent
- copies `/opt/ccchatshare/data` to a timestamped backup before restart

- sets the data directory mode to 700
- builds `localhost/ccchatshare:latest` from `Containerfile`
- installs `deploy/ccchatshare.container` at `/etc/containers/systemd/`
- reloads systemd and restarts `ccchatshare.service`

A missing data dir on a later deploy would mint a new `SECRET_KEY` and an empty database. The guard above stops that.

Check logs:

```bash
sudo journalctl -u ccchatshare -n 50
```

## Container

`Containerfile` uses `python:3.12-slim`. The image runs as uid 1000 (`appuser`). The tag is not digest-pinned.

`deploy/entrypoint.sh`:

- sets umask 077
- writes `SECRET_KEY` and `CCCHATSHARE_ADMIN_TOKEN` into `/data/secrets.env` when that file is absent or incomplete
- writes to a temp file, then renames
- sources the file
- execs gunicorn with 1 worker and 4 threads on `0.0.0.0:8080`

Gunicorn must use one worker. Flask-Limiter stores counters in process memory. Extra workers would split the lockout.

Quadlet unit `deploy/ccchatshare.container`:

- publishes `127.0.0.1:8080:8080` only
- bind-mounts `/opt/ccchatshare/data` to `/data` with `:Z,U`
- sets `UserNS=auto` and `NoNewPrivileges=true`

`UserNS=auto` maps container uid 1000 into the host `containers` subuid range (`containers:200000:65536`). Without that map, uid 1000 inside the container is the host `eyeclept` account.

## Cloudflare tunnel

cloudflared runs as a native systemd service on the same VM. It is not in the unit files in this repo.

- Public host is `https://chatshare.blue-bly.com`.
- Tunnel name is `ccchatshare`.
- Tunnel id is `7c656952-b1cd-4fa1-80f4-0a66eb715a3e`.

- Ingress sends `chatshare.blue-bly.com` to `http://localhost:8080`.
- Catch-all returns HTTP 404.
- DNS is a CNAME from `cloudflared tunnel route dns`.

Cloudflare terminates TLS. The Flask app speaks HTTP on loopback.

The limiter keys on `Cf-Connecting-Ip`. Cloudflare sets that header. `request.remote_addr` behind the tunnel is not the visitor.

The `cloudflared` service runs as a dedicated non-root `cloudflared` account. Hardening includes `NoNewPrivileges`, `ProtectSystem=strict`, and `ProtectHome`.

## Admin TUI on the VM

1. SSH to the VM.
2. Exec the TUI in the running container.

```bash
ssh eyeclept@172.27.72.60
sudo podman exec -it ccchatshare python3 admin_tui.py
```

The TUI opens `/data/ccchatshare.db` inside the container.

Keys: `r` new access code, `x` toggle revoked, `d` delete, `q` quit.

## Auth cookie

Cookie name: `ccchat_auth_<slug>`. Path: `/c/<slug>`. Flags: HttpOnly, Secure (default on), SameSite=Lax. Max age: 180 days.

The signed payload holds the slug, `token_version`, and a fingerprint of `access_code_hash`. A regenerate bumps `token_version` and changes the hash. Old cookies then fail.

## Rate limits

- Access-code POST: 5 failures per 5 minutes per (visitor IP, slug). Success does not count.
- `POST /api/chats`: 10 per hour. Bearer token required.
