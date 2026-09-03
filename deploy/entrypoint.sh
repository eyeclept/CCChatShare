#!/usr/bin/env bash
set -euo pipefail

# Restrictive umask before anything touches /data (the bind-mounted host
# directory). The container default umask (0022) made secrets.env (in the
# pre-chmod window) and the sqlite DB file world-readable (0644) on the
# host. 0077 makes every file this process creates private by default.
# The chmod on secrets.env below is now redundant. It stays as defense
# in depth.
umask 077

# Generate secrets if they are missing or incomplete. Check file content,
# not just existence. An interrupted first write (OOM, disk full, or a
# reset mid-heredoc) is then repaired on the next start instead of
# crash-looping. `[ -f ]` alone would see the partial file, skip
# regeneration, and leave config.py's RuntimeError restarting the unit
# every 5 seconds.
if ! grep -q '^CCCHATSHARE_ADMIN_TOKEN=.' /data/secrets.env 2>/dev/null; then
    echo "Generating secrets..."
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    CCCHATSHARE_ADMIN_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

    # Write to a temp file, then rename. Rename is atomic on the same
    # filesystem. A reader or a crash never sees a partial secrets.env
    # under the real name.
    cat > /data/secrets.env.tmp <<EOF
SECRET_KEY=${SECRET_KEY}
CCCHATSHARE_ADMIN_TOKEN=${CCCHATSHARE_ADMIN_TOKEN}
EOF
    chmod 600 /data/secrets.env.tmp
    mv /data/secrets.env.tmp /data/secrets.env
fi

# Load secrets into environment
set -a
source /data/secrets.env
set +a

# Single worker is required. Flask-Limiter stores counters in process memory.
# Multiple workers would split the lockout counters.
exec gunicorn --workers 1 --threads 4 --bind 0.0.0.0:8080 --access-logfile - --error-logfile - wsgi:app
