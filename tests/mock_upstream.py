#!/usr/bin/env python3
"""Minimal POST upstream for AppSec proxy_pass integration tests."""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n:
            self.rfile.read(n)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9000"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
