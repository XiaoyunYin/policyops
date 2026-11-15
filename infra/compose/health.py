"""Small, standard-library-only container probes; keep application imports out."""

from __future__ import annotations

import argparse
from email.message import Message
from http.client import HTTPException
import json
from pathlib import Path
import stat
import time
from typing import IO
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


HEARTBEAT = Path("/tmp/worker-heartbeat")  # noqa: S108 - private per-container mode-0700 tmpfs
HTTP_TIMEOUT = 2


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: IO[bytes], code: int, msg: str,
                         headers: Message, newurl: str) -> None:
        return None


def http_health(url: str) -> bool:
    # Match httpx trust_env=False / follow_redirects=False, including proxy bypass.
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(url, timeout=HTTP_TIMEOUT) as response:
            if response.status != 200:
                return False
            body = json.load(response)
            return isinstance(body, dict) and body.get("status") == "ok"
    except HTTPError as error:
        error.close()
        return False
    except (HTTPException, OSError, URLError, ValueError):
        return False


def worker_health() -> bool:
    try:
        heartbeat = HEARTBEAT.stat()
        return stat.S_ISREG(heartbeat.st_mode) and time.time() - heartbeat.st_mtime < 25
    except OSError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("health-api", "health-retail", "health-worker"))
    command = parser.parse_args().command
    if command == "health-worker":
        healthy = worker_health()
    else:
        url = ("http://127.0.0.1:8000/api/v1/health/ready" if command == "health-api"
               else "http://127.0.0.1:8001/healthz")
        healthy = http_health(url)
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
