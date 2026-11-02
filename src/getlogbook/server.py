"""Live local viewer. Loopback only, read-only, per-launch token, Host/Origin checks, strict CSP.

The page polls /api/version and reloads the tree when refs or your private log change, so a `git pull`/`logbook sync`
shows up without a restart. Entry text is only ever rendered with textContent (shared entries are untrusted input).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import capture, recall, tree
from . import git as g

SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


def make_handler(repo, token, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    page = resources.files("getlogbook").joinpath("viewer.html").read_text(encoding="utf-8")

    class H(BaseHTTPRequestHandler):
        server_version = "logbook"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json", extra=None, nonce=None):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            csp = "default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            if nonce:
                csp += f"; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'"
            self.send_header("Content-Security-Policy", csp)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            cookie = self.headers.get("Cookie", "")
            m = re.search(r"logbook=([A-Za-z0-9_-]+)", cookie)
            return bool(m) and hmac.compare_digest(m.group(1), token)

        def do_GET(self):
            if self.headers.get("Host", "") not in allowed_hosts:  # DNS-rebinding guard
                return self._send(403, '{"error":"bad host"}')
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                return self._send(403, '{"error":"bad origin"}')
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/" and q.get("t", [""])[0]:
                if hmac.compare_digest(q["t"][0], token):
                    return self._send(302, "", "text/plain", {"Location": "/", "Set-Cookie": f"logbook={token}; HttpOnly; SameSite=Strict; Path=/"})
                return self._send(403, "bad token", "text/plain")
            if not self._authed():
                return self._send(403, "Open the URL printed by `logbook serve` (it carries a one-time token).", "text/plain")
            repo._derived = None  # the server is long-lived: re-check the per-HEAD cache on every request
            try:
                if u.path == "/":
                    nonce = secrets.token_urlsafe(12)
                    return self._send(200, page.replace("{{NONCE}}", nonce), "text/html", nonce=nonce)
                if u.path == "/api/version":
                    refs = g.try_run(["for-each-ref", "--format=%(objectname) %(refname)", "refs/logbook", "refs/logbook-remote", "refs/heads/logbook"], repo.root)[1]
                    priv = sorted(p.name for p in repo.pdir.glob("*.json")) if repo.pdir.exists() else []
                    head = g.head_sha(repo.root) or ""
                    return self._send(200, json.dumps({"v": hashlib.sha1((refs + "|".join(priv) + head).encode()).hexdigest()[:12]}))
                if u.path == "/api/tree":
                    return self._send(200, json.dumps(tree.build(repo)))
                if u.path == "/api/search":
                    vs, an = tree.all_views(repo)
                    qs = q.get("q", [""])[0][:200]
                    known = recall.known_names(vs)
                    names = {m for m in known if m in recall.tokens(qs)}
                    res = recall.rank(repo, query=qs, names=names, views=vs, anch=an)[:40]
                    return self._send(200, json.dumps([{**v, "score": round(s, 1)} for s, v in res]))
                m = re.match(r"^/api/commit/([0-9a-f]{7,40})$", u.path)
                if m and SHA_RE.match(m.group(1)):
                    rc, o, _ = g.try_run(["show", "--stat", "--format=%H%n%an <%ae>%n%aI%n%n%B", m.group(1)], repo.root)
                    return self._send(200, json.dumps({"text": o[:20000]})) if rc == 0 else self._send(404, '{"error":"no such commit locally"}')
                return self._send(404, '{"error":"not found"}')
            except Exception as ex:
                repo.error(f"server {u.path}: {ex!r}")
                return self._send(500, '{"error":"internal"}')

        def do_POST(self):
            self._send(405, '{"error":"read-only"}')

        do_PUT = do_DELETE = do_PATCH = do_POST

    return H


def serve(repo, port=0, open_browser=False):
    try:
        capture.reconcile(repo)  # one sweep on open: crash recovery + commits that had no hook
    except Exception as ex:
        repo.error(f"serve reconcile: {ex!r}")
    token = secrets.token_urlsafe(24)
    srv = ThreadingHTTPServer(("127.0.0.1", port), lambda *a, **k: None)
    real = srv.server_address[1]
    srv.RequestHandlerClass = make_handler(repo, token, real)
    url = f"http://127.0.0.1:{real}/?t={token}"
    print(f"logbook viewer (loopback only, read-only): {url}", flush=True)  # flush: callers read this through a pipe
    print("Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
