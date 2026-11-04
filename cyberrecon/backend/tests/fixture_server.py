"""A controlled local HTTP server used as a test fixture. No intrusive tests ever hit real targets."""
from __future__ import annotations

import gzip
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Fixture &amp; Co &lt;Home&gt;</title>
<meta name="description" content="A fixture page for tests">
<meta name="generator" content="WordPress 6.4">
<meta property="og:title" content="Fixture OG">
<link rel="canonical" href="/">
<link rel="icon" href="/favicon.ico">
<link rel="stylesheet" href="/wp-content/themes/x/style.css">
<base href="/">
</head><body>
<a href="/about">About</a>
<a href="about">About again</a>
<a href="/missing">Missing page</a>
<a href="/private/area">Disallowed</a>
<a href="https://other-site.example.org/page">External</a>
<a href="https://blog.site.example.org/post">Sub</a>
<a href="mailto:hi@site.example.org">mail</a>
<a href="tel:+100">tel</a>
<a href="javascript:alert(1)">js</a>
<a href="#section">frag</a>
<img src="/img/logo.png"><script src="/static/app.js"></script>
<iframe src="https://widgets.example.net/embed"></iframe>
<form action="/search"></form>
</body></html>"""

ROBOTS = """User-agent: *
Disallow: /private/
Allow: /private/public
Crawl-delay: 2
Sitemap: {origin}/sitemap.xml
"""

SITEMAP = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>{origin}/</loc></url><url><loc>{origin}/about</loc></url>
</urlset>"""

XXE_SITEMAP = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>&xxe;</loc></url></urlset>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.25.3"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence
        pass

    def _send(self, status, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        srv: FixtureServer = self.server.fixture  # type: ignore[attr-defined]
        srv.requests.append((self.command, self.path, self.headers.get("Host", "")))
        origin = srv.origin
        p = self.path.split("?")[0]
        if p == "/":
            self._send(
                200,
                HOME_HTML,
                headers={
                    "X-Powered-By": "PHP/8.2",
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                    "Set-Cookie": "sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
                },
            )
        elif p == "/about":
            self._send(200, "<html><title>About</title></html>")
        elif p == "/robots.txt":
            self._send(200, ROBOTS.format(origin=origin), "text/plain")
        elif p == "/sitemap.xml":
            self._send(200, SITEMAP.format(origin=origin), "application/xml")
        elif p == "/xxe-sitemap.xml":
            self._send(200, XXE_SITEMAP, "application/xml")
        elif p == "/private/area":
            self._send(200, "secret")
        elif p == "/redirect-private":
            self._send(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        elif p == "/redirect-internal-name":
            self._send(302, headers={"Location": f"http://internal-host.example.org:{srv.port}/x"})
        elif p == "/redirect-offsite":
            self._send(302, headers={"Location": "https://elsewhere.example.com/landing"})
        elif p == "/redirect-ok":
            self._send(301, headers={"Location": "/about"})
        elif p == "/redirect-loop":
            self._send(302, headers={"Location": "/redirect-loop"})
        elif p == "/redirect-file":
            self._send(302, headers={"Location": "file:///etc/passwd"})
        elif p == "/big":
            self._send(200, b"A" * 5_000_000, "application/octet-stream")
        elif p == "/gzip-bomb":
            data = gzip.compress(b"0" * 60_000_000, compresslevel=9)
            self._send(200, data, "text/html", {"Content-Encoding": "gzip"})
        elif p == "/slow":
            time.sleep(2.5)
            self._send(200, "late")
        elif p == "/forbidden":
            self._send(403, "nope")
        elif p == "/ratelimited":
            self._send(429, "slow down", headers={"Retry-After": "30"})
        elif p == "/page-with-assets":
            self._send(200, f"<html><head><title>Assets &amp; things</title></head><body style='background:#123;color:#fff'><h1>Screenshot fixture</h1>"
                            f"<img src='http://internal-host.example.org:{srv.port}/pixel.png' width=10 height=10>"
                            f"<img src='http://169.254.169.254/latest/meta-data/x.png' width=10 height=10>"
                            f"<img src='/ok.png' width=10 height=10></body></html>")
        elif p == "/page-with-redirecting-asset":
            self._send(200, "<html><head><title>Redirect asset</title></head><body><img src='/redirect-private' width=10 height=10><h1>ok</h1></body></html>")
        elif p == "/evil-title":
            self._send(200, "<html><head><title><img src=x onerror=alert(1)></title></head><body><a href='/x'>&lt;script&gt;alert(1)&lt;/script&gt;</a></body></html>")
        else:
            self._send(404, "not found")


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # clients disconnect early in size-limit tests
        pass


class FixtureServer:
    def __init__(self):
        self.requests: list[tuple[str, str, str]] = []
        self.httpd = QuietServer(("127.0.0.1", 0), Handler)
        self.httpd.fixture = self  # type: ignore[attr-defined]
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
