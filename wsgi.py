"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Gunicorn WSGI entry. The container entrypoint (deploy/entrypoint.sh)
    runs `gunicorn wsgi:app`.
"""
# Imports
import logging
import os
import sys

from app import create_app

logging.basicConfig(
    stream=sys.stdout,
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = create_app()

if __name__ == "__main__":
    # Dev-server fallback only; the container runs gunicorn against `app`.
    app.run(host=app.config["host"], port=app.config["port"])
