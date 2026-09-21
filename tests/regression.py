#!/usr/bin/env python3
"""Real nginx regressions with local LAPI/AppSec/upstream servers; stdlib only."""
import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
KEY = "0123456789abcdef" * 4
slow_started = threading.Event()
captcha_started = threading.Event()
uploads = []
upload_lock = threading.Lock()


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path.startswith("/v1/decisions/stream"):
            decisions = []
            if "startup=true" in self.path:
                for ip, kind, duration in [
                    ("198.51.100.1", "ban", "1h"),
                    ("198.51.100.3", "captcha", "1h"),
                    ("198.51.100.4", "ban", "2s"),
                    ("198.51.100.4", "captcha", "1h"),
                    ("203.0.113.0/24", "ban", "2s"),
                    ("203.0.113.0/24", "captcha", "1h"),
                ]:
                    decisions.append(dict(value=ip, type=kind, duration=duration, origin="crowdsec"))
            self.reply(200, json.dumps(dict(new=decisions, deleted=[])).encode())
        elif self.path == "/v1/usage-metrics":
            # Requests continue arriving while the bouncer waits for this ACK.
            time.sleep(0.25)
            with upload_lock:
                uploads.append(json.loads(body))
            self.reply(200, b"{}")
        elif self.path == "/appsec":
            uri = self.headers.get("X-Crowdsec-Appsec-Uri", "")
            if uri.startswith("/slow"):
                slow_started.set()
                time.sleep(0.8)
            if uri.startswith("/waf-captcha"):
                self.reply(403, b'{"action":"captcha"}')
            else:
                self.reply(200, b"{}")
        else:
            self.reply(200, self.command.encode() + b":" + body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

    def reply(self, status, body):
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def token(ip):
    def enc(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")
    payload = dict(sub=ip, iat=int(time.time()), exp=int(time.time()) + 3600,
                   typ="captcha_pass", uri="/é", nonce="regression")
    message = enc(b'{"alg":"HS256","typ":"JWT"}') + b"." + enc(
        json.dumps(payload, ensure_ascii=False).encode())
    return (message + b"." + enc(hmac.digest(bytes.fromhex(KEY), message, hashlib.sha256))).decode()


def main():
    # Optional container-only check: Docker maps the provider name to this TLS
    # handshake sink. No external API calls, certificates, or host-file changes.
    sink = None
    if "--captcha-stall" in sys.argv:
        assert socket.gethostbyname("api.hcaptcha.com") == "127.0.0.1"

        class Stall(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                captcha_started.set()
                time.sleep(6)

        sink = socketserver.ThreadingTCPServer(("127.0.0.1", 443), Stall)
        sink.daemon_threads = True
        threading.Thread(target=sink.serve_forever, daemon=True).start()
    mock = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    port = mock.server_port
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        nginx_port = reserve.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="crowdsec-regression-") as tmp:
        path = Path(tmp)
        path.chmod(0o755)
        config = path / "nginx.conf"
        config.write_text(f"""
load_module {ROOT}/target/release/libngx_http_crowdsec_module.so;
daemon off;
worker_processes 1;
thread_pool default threads=2 max_queue=2;
pid {path}/nginx.pid;
error_log {path}/error.log notice;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {path}/body;
    proxy_temp_path {path}/proxy;
    crowdsec on;
    crowdsec_url http://127.0.0.1:{port};
    crowdsec_api_key regression;
    crowdsec_poll_interval 1;
    crowdsec_usage_metrics_interval 600;
    crowdsec_trusted_proxies 127.0.0.1;
    crowdsec_appsec on;
    crowdsec_appsec_url http://127.0.0.1:{port}/appsec;
    crowdsec_appsec_timeout 2000;
    crowdsec_appsec_failure_action deny;
    crowdsec_ban_template {ROOT}/templates/default.html;
    crowdsec_captcha_provider hcaptcha;
    crowdsec_captcha_site_key regression;
    crowdsec_captcha_secret_key regression;
    crowdsec_captcha_signing_key {KEY};
    crowdsec_captcha_fail_open off;
    crowdsec_captcha_template {ROOT}/templates/captcha.html;
    server {{
        listen 127.0.0.1:{nginx_port} http2;
        location / {{ proxy_pass http://127.0.0.1:{port}; }}
        location /health {{ crowdsec off; return 200 'ok'; }}
        location /metrics {{ crowdsec_metrics on; }}
        location /waf-captcha {{ crowdsec_appsec_always on; proxy_pass http://127.0.0.1:{port}; }}
        location /waf-allow {{ crowdsec_appsec_always on; proxy_pass http://127.0.0.1:{port}; }}
    }}
}}
""")
        nginx = subprocess.Popen(["nginx", "-e", "stderr", "-p", tmp + "/", "-c", str(config)])

        def request(uri="/", method="GET", ip="198.51.100.2", cookie=None, body=None,
                    timeout=5):
            conn = http.client.HTTPConnection("127.0.0.1", nginx_port, timeout=timeout)
            headers = {"X-Forwarded-For": ip}
            if cookie:
                headers["Cookie"] = "crowdsec_captcha=" + cookie
            if body is not None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            try:
                conn.request(method, uri, body, headers)
                response = conn.getresponse()
                return response.status, response.read()
            finally:
                conn.close()

        try:
            for _ in range(100):
                try:
                    if request(ip="198.51.100.1")[0] == 403:
                        break
                except OSError:
                    pass
                if nginx.poll() is not None:
                    raise AssertionError("nginx exited during startup")
                time.sleep(0.05)
            else:
                raise AssertionError("stream decisions never arrived")

            assert request()[0] == 200
            for method in ["POST", "PUT", "PATCH", "DELETE"]:
                status, body = request(method=method, body="hello=world", ip="198.51.100.3",
                                       cookie=token("198.51.100.3"))
                assert (status, body) == (200, f"{method}:hello=world".encode()), (status, body)
            assert b"hcaptcha" in request(ip="198.51.100.3")[1]
            for method in ["GET", "POST"]:
                assert request("/waf-captcha", method, "198.51.100.3",
                               token("198.51.100.3"), "x=y" if method == "POST" else None)[0] == 403
            print("PASS: valid stream captcha sessions preserve methods/bodies; WAF captcha is a ban", flush=True)

            with concurrent.futures.ThreadPoolExecutor() as pool:
                slow_started.clear()
                pending = pool.submit(request, "/slow", "POST", "198.51.100.2", None, "x=y")
                assert slow_started.wait(2)
                start = time.monotonic()
                assert request("/health")[0] == 200
                assert request("/quick")[0] == 200
                assert time.monotonic() - start < 0.6, "verification blocked the nginx event loop"
                assert pending.result() == (200, b"POST:x=y")
            print("PASS: slow AppSec verification leaves the event loop responsive", flush=True)

            http2 = subprocess.check_output([
                "curl", "--silent", "--show-error", "--fail", "--max-time", "5",
                "--http2-prior-knowledge", "--data", "http2=body",
                f"http://127.0.0.1:{nginx_port}/slow-http2",
            ])
            assert http2 == b"POST:http2=body", http2
            print("PASS: asynchronous HTTP/2 request body reaches upstream", flush=True)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                barrier = threading.Barrier(8)

                def overloaded():
                    barrier.wait()
                    return request("/slow-overload")[0]

                pending = [pool.submit(overloaded) for _ in range(8)]
                statuses = [item.result() for item in pending]
                assert 403 in statuses and 200 in statuses, statuses
                assert set(statuses) <= {200, 403}, statuses
            assert request("/health")[0] == 200
            print("PASS: full verification queue uses the failure policy", flush=True)

            if sink:
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    pending = pool.submit(request, "/waf-allow", "POST", "198.51.100.3",
                                          None, "h-captcha-response=invalid", 15)
                    assert captcha_started.wait(2)
                    start = time.monotonic()
                    assert request("/health")[0] == 200
                    assert time.monotonic() - start < 0.6
                    status, body = pending.result()
                    assert status == 200 and b"Verification service unavailable" in body, (status, body)
                print("PASS: slow captcha verification after AppSec stays asynchronous", flush=True)

            slow_started.clear()
            abandoned = socket.create_connection(("127.0.0.1", nginx_port))
            abandoned.sendall(b"GET /slow-abort HTTP/1.1\r\nHost: localhost\r\n\r\n")
            assert slow_started.wait(2)
            abandoned.close()
            time.sleep(1)
            assert request("/health")[0] == 200
            print("PASS: client disconnect during verification", flush=True)

            with concurrent.futures.ThreadPoolExecutor() as pool:
                slow_started.clear()
                pending = pool.submit(request, "/slow-reload")
                assert slow_started.wait(2)
                nginx.send_signal(signal.SIGHUP)
                assert pending.result()[0] == 200
            print("PASS: graceful reload with verification in flight", flush=True)

            for ip in ["198.51.100.4", "203.0.113.7"]:
                assert b"hcaptcha" in request(ip=ip)[1], "expired ban masked live captcha"
            print("PASS: IP and CIDR bans expire independently of captcha", flush=True)

            def flush_metrics():
                with upload_lock:
                    count = len(uploads)
                nginx.send_signal(signal.SIGHUP)
                for _ in range(100):
                    with upload_lock:
                        if len(uploads) > count:
                            break
                    time.sleep(0.05)
                else:
                    raise AssertionError("shutdown metrics were not uploaded")
                # Allow poller election to transfer to the new worker.
                time.sleep(0.4)

            # Reload flushes the old worker's snapshot while its replacement
            # continues incrementing the same shared counters.
            flush_metrics()
            with upload_lock:
                before = sum_dropped()

            def burst():
                for _ in range(80):
                    assert request(ip="198.51.100.1")[0] == 403
                    time.sleep(0.02)

            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(burst)
                time.sleep(0.15)
                flush_metrics()
                pending.result()
            flush_metrics()
            with upload_lock:
                after = sum_dropped()
            assert after - before == 80, (before, after)
            print("PASS: metrics preserve exactly the drops recorded during uploads", flush=True)

            assert request()[0] == 200
            log = (path / "error.log").read_text()
            assert "exited on signal" not in log, log
            print("PASS: reload; no worker crashes", flush=True)
        finally:
            if nginx.poll() is None:
                nginx.send_signal(signal.SIGQUIT)
                try:
                    nginx.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    nginx.kill()
                    nginx.wait()
            print((path / "error.log").read_text() if (path / "error.log").exists() else "no nginx log")
            mock.shutdown()
            if sink:
                sink.shutdown()


def sum_dropped():
    return sum(item["value"] for upload in uploads
               for component in upload["remediation_components"]
               for window in component["metrics"] for item in window["items"]
               if item["name"] == "dropped")


if __name__ == "__main__":
    main()
