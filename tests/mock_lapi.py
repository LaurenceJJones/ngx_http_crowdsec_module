import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith("/v1/decisions/stream"):
            self.send_error(404)
            return

        try:
            with open(os.getenv("STATE_FILE", "/state/decisions.json"), "rb") as state:
                body = state.read()
            json.loads(body)
        except (OSError, ValueError):
            self.send_error(500)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), Handler).serve_forever()
