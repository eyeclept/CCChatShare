FROM python:3.12-slim

# Create a non-root user with a fixed UID/GID so deploys stay consistent
RUN groupadd -g 1000 appuser && useradd -u 1000 -g 1000 -m appuser

WORKDIR /app

# Copy requirements first so later code copies reuse the pip layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and entrypoint
COPY app/ app/
COPY wsgi.py admin_tui.py ./
COPY deploy/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

# Give the app tree to appuser
RUN chown -R appuser:appuser /app

# Run as non-root
USER appuser

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
