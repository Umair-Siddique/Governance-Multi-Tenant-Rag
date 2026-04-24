import logging
import sys

# Configure logging BEFORE app creation so all module-level loggers get a handler.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
)

from app import create_app

app = create_app()

if __name__ == "__main__":
    from waitress import serve
    print("Starting waitress server on http://127.0.0.1:5001", flush=True)
    serve(
        app,
        host="127.0.0.1",
        port=5001,
        threads=8,
        channel_timeout=300,
        recv_bytes=8192,
        send_bytes=1,        # flush every chunk immediately (critical for SSE)
    )