"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Flask-Limiter instance for the access-code lockout.
    The lockout is 5 tries, then 5 minutes. The code uses the stock library.
    See app/routes_public.py for where the limit is applied.

    The app is reachable only through the cloudflared tunnel.
    deploy/ccchatshare.container publishes 127.0.0.1:8080 only.
    Cloudflare sets Cf-Connecting-Ip to the visitor IP on each tunneled request.
    That header is the limiter key.
    request.remote_addr behind the podman bridge is the bridge gateway.
    That address is the same for every visitor.
    Using it put the whole internet in one rate-limit bucket.
"""
# Imports
import logging

from flask import request
from flask_limiter import Limiter

logger = logging.getLogger(__name__)


# Functions
def get_client_ip() -> str:
    """
    Input:      None (reads flask.request)
    Output:     visitor IP from Cf-Connecting-Ip, else remote_addr, else 127.0.0.1
    Details:
        Prefers Cf-Connecting-Ip. Cloudflare sets that header on every
        tunneled request. request.remote_addr is not the visitor address
        behind cloudflared and the podman loopback hop.
        Uses remote_addr when Cf-Connecting-Ip is absent, so local and
        dev requests that skip Cloudflare still get a usable key.
    """
    return request.headers.get("Cf-Connecting-Ip") or request.remote_addr or "127.0.0.1"


# Global limiter instance. app/__init__.py binds it with limiter.init_app(app).
# Storage is in process memory. deploy/entrypoint.sh runs one gunicorn worker,
# so all requests share one counter. A container restart clears the lockout.
limiter = Limiter(key_func=get_client_ip, default_limits=[])


def unlock_key() -> str:
    """
    Input:      None (reads flask.request via view_args)
    Output:     rate-limit bucket key combining the requester's IP and the
                chat slug being unlocked
    Details:
        Scoping the lockout to (ip, slug) means brute-forcing one chat's
        code does not lock the same visitor out of unlocking a different
        chat.
    """
    slug = request.view_args.get("slug", "") if request.view_args else ""
    return f"{get_client_ip()}:{slug}"
