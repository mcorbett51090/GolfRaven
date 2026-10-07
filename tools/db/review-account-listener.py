#!/usr/bin/env python3
"""tools/db/review-account-listener.py: a TEST-ONLY stand-in for GoTrue's admin API, for tools/db/test-review-account-tool.sh.

It listens on 127.0.0.1 (an ephemeral port, written to --portfile), records every request it receives (method, path, the headers the tool is meant to send and the raw body) to --log
as one JSON object per line, and answers like the admin API is assumed to (`[unverified]`: no hosted project here):
  POST /auth/v1/admin/users        creates an auth.users row (id, email) in the harness database and answers 200 {"id": ..., "email": ...}
  PUT  /auth/v1/admin/users/<id>   answers 200 {} (or 500 while the file named by --fail-file exists)
On every PUT it also records what the DATABASE says at that instant (is a review window open? how many review-account rows exist?), which is how the test proves the ORDER: an unban must come after the window is written, a ban
after it ended. The database is reached with `psql` on stdin (standard PG* environment), as service_role. Nothing here is used by the product.
"""
import argparse, json, os, subprocess, sys, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


def psql(sql):
    p = subprocess.run(["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], input="SET ROLE service_role;\n" + sql, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip())
    return p.stdout.strip()


class Handler(BaseHTTPRequestHandler):
    log_path = ""
    fail_file = ""

    def log_message(self, *a):  # silent
        pass

    def _record(self, body, extra):
        rec = {
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "apikey": self.headers.get("apikey"),
            "content_type": self.headers.get("Content-Type"),
            "body_raw": body,
        }
        rec.update(extra)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(rec) + "\n")

    def _send(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def do_POST(self):
        body = self._body()
        self._record(body, {})
        if self.path != "/auth/v1/admin/users":
            return self._send(404, {})
        try:
            email = json.loads(body)["email"]
        except Exception:
            return self._send(400, {"msg": "bad body"})
        uid = str(uuid.uuid4())
        lit = "'" + email.replace("'", "''") + "'"
        psql("INSERT INTO auth.users (id, email) VALUES ('%s', %s)" % (uid, lit))
        self._send(200, {"id": uid, "email": email})

    def do_PUT(self):
        body = self._body()
        window_open = psql("SELECT private.review_window_open_at(clock_timestamp())")
        rows = psql("SELECT count(*) FROM app.app_review_demo_account")
        self._record(body, {"window_open_at_call": window_open, "demo_rows_at_call": rows})
        if self.fail_file and os.path.exists(self.fail_file):
            return self._send(500, {"msg": "forced failure"})
        self._send(200, {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--portfile", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--fail-file", default="")
    a = ap.parse_args()
    Handler.log_path = a.log
    Handler.fail_file = a.fail_file
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    with open(a.portfile, "w") as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
