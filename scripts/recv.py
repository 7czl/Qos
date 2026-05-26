#!/usr/bin/env python3
"""HTTP PUT/POST receiver for upload rate-limit testing.

Drops all incoming bytes (writes to /dev/null effectively) and prints
periodic throughput stats to stderr. Listens on 0.0.0.0:9999 by default.

Usage:
    python3 recv.py             # listen on :9999
    python3 recv.py 8080        # custom port
"""
import http.server
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999


class Handler(http.server.BaseHTTPRequestHandler):
    def _drain(self):
        n = int(self.headers.get("Content-Length", 0))
        start = time.monotonic()
        received = 0
        chunk_size = 65536
        while n > 0:
            chunk = self.rfile.read(min(chunk_size, n))
            if not chunk:
                break
            received += len(chunk)
            n -= len(chunk)
        elapsed = time.monotonic() - start
        rate = received / elapsed if elapsed > 0 else 0
        sys.stderr.write(
            f"[recv] {received:>12} bytes in {elapsed:6.2f}s -> {rate/1024/1024:7.2f} MB/s "
            f"({rate*8/1_000_000:7.2f} Mbps)\n"
        )
        sys.stderr.flush()
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_PUT(self):
        self._drain()

    def do_POST(self):
        self._drain()

    def log_message(self, fmt, *args):
        # Suppress default access log; we print our own stats.
        pass


if __name__ == "__main__":
    print(f"listening on 0.0.0.0:{PORT} (PUT/POST)", file=sys.stderr)
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
