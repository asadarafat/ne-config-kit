#!/usr/bin/env python3
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    server_version = "nck-stub/1.0"

    def _send(self, code, payload, content_type="application/json"):
        data = payload if isinstance(payload, (bytes, bytearray)) else payload.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, "ok", "text/plain")
            return
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        if self.server.log_path:
            with open(self.server.log_path, "ab") as logf:
                logf.write(body + b"\n")

        if self.path != "/jsonrpc":
            self._send(404, "not found", "text/plain")
            return

        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": [self.server.config_text],
        }
        self._send(200, json.dumps(response))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--config", required=True)
    parser.add_argument("--log", default="")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config_text = f.read().rstrip("\n")

    server = HTTPServer((args.host, args.port), Handler)
    server.config_text = config_text
    server.log_path = args.log or ""

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
