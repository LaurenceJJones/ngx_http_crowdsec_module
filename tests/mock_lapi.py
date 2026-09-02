import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.server.server_address[1] == 7422:
            self.appsec()
            return
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

    def do_POST(self):
        self.appsec()

    def appsec(self):
        try:
            with open(os.getenv("APPSEC_STATE_FILE", "/state/appsec.json")) as state:
                payload = json.load(state)
            status = payload.pop("_status", 200)
            body = json.dumps(payload).encode()
        except (OSError, ValueError):
            self.send_error(500)
            return
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if os.getenv("PORT"):
    ThreadingHTTPServer(("0.0.0.0", int(os.environ["PORT"])), Handler).serve_forever()
else:
    threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 7422), Handler).serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
