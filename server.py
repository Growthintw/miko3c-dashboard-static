import base64
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

USERNAME = os.environ.get("BASIC_AUTH_USER", "")
PASSWORD = os.environ.get("BASIC_AUTH_PASS", "")
REALM = os.environ.get("BASIC_AUTH_REALM", "Miko3C Report")


def _expected_auth_header() -> str:
    token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


class AuthHandler(SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

    def _is_authorized(self) -> bool:
        # If credentials are not set, deny by default to avoid accidental exposure.
        if not USERNAME or not PASSWORD:
            return False
        auth = self.headers.get("Authorization", "")
        return auth == _expected_auth_header()

    def _guard(self) -> bool:
        if self._is_authorized():
            return True
        self.do_AUTHHEAD()
        self.wfile.write(b"Authentication required")
        return False

    def do_GET(self):
        if not self._guard():
            return
        super().do_GET()

    def do_HEAD(self):
        if not self._guard():
            return
        super().do_HEAD()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), AuthHandler)
    server.serve_forever()
