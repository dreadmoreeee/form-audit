import functools
import http.server
import json
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def bad_page():
    return json.loads((FIXTURES / "bad_page.json").read_text(encoding="utf-8"))[0]


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Serves the fixture site and records every request method it sees."""

    log: list = []

    def _record(self):
        self.log.append((self.command, self.path))

    def do_GET(self):
        self._record()
        super().do_GET()

    def do_HEAD(self):
        self._record()
        super().do_HEAD()

    def do_POST(self):
        self._record()
        self.send_response(204)
        self.end_headers()

    do_PUT = do_PATCH = do_DELETE = do_POST

    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def site():
    """Local server on a random free port (bind port 0) serving tests/fixtures/site."""
    log: list = []
    handler = type("Handler", (_Handler,), {"log": log})
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(handler, directory=str(FIXTURES / "site"))
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {"base": f"http://127.0.0.1:{server.server_address[1]}", "log": log}
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def extracted(site):
    """Extract all fixture pages once (one browser session)."""
    try:
        from form_audit.extract import extract_pages

        pages = extract_pages(
            [f"{site['base']}/{name}" for name in ("bad.html", "good.html", "beacon.html")], delay=0, timeout=20
        )
    except Exception as exc:  # Chromium not installed
        pytest.skip(f"headless Chromium unavailable: {exc}")
    return {p["requested_url"].rsplit("/", 1)[1]: p for p in pages}
