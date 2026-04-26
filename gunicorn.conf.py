"""
Gunicorn config tuned for SSE streaming (EventSource).

Use with:
  gunicorn -c gunicorn.conf.py wsgi:app
"""

# SSE works best with an async worker.
worker_class = "gevent"

# Start with 1 worker to validate streaming behavior.
workers = 1

# Don't kill long-lived SSE connections.
timeout = 0
graceful_timeout = 30

# Keep sockets alive for EventSource reconnects.
keepalive = 75

# Let Gunicorn handle chunked streaming.
preload_app = False

# Logging (stdout/stderr in most hosts).
accesslog = "-"
errorlog = "-"
loglevel = "info"

