"""Explicit live HTTPS verification. No cloud calls; reports contain checks, never credentials or cookies."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from html.parser import HTMLParser
from http.cookies import SimpleCookie
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit
from uuid import UUID, uuid4, uuid5

import httpx


ROOT = Path(__file__).resolve().parents[1]
PORTS = (22, 80, 443, 2375, 5432, 5556, 8000, 8001, 8080)
DEMO_WORKSPACE = UUID("00000000-0000-0000-0000-000000003801")
ALICE = str(uuid5(DEMO_WORKSPACE, "alice"))


def release_sha(raw: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", raw):
        raise ValueError("expected a full commit SHA")
    return raw


def hostname(raw: str) -> str:
    if len(raw) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", raw):
        raise ValueError("expected a DNS hostname without scheme or port")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in raw.split(".")):
        raise ValueError("invalid DNS label")
    return raw


def report_path(kind: str) -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    base = Path(raw).resolve()
    if not raw or not Path(raw).is_absolute() or base == ROOT or ROOT in base.parents:
        raise ValueError("POLICYOPS_TEMP_DIR must be absolute and outside the checkout")
    folder = base / "deployment"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{kind}-{uuid4().hex}.json"


def security_headers(headers: httpx.Headers) -> dict[str, bool]:
    hsts = headers.get("strict-transport-security", "")
    age = re.search(r"(?:^|;)\s*max-age=(\d+)(?:;|$)", hsts, re.IGNORECASE)
    csp = headers.get("content-security-policy", "")
    return {
        "hsts": age is not None and int(age.group(1)) >= 31536000,
        "csp": "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "object-src 'none'" in csp,
        "frame": headers.get("x-frame-options", "").upper() == "DENY",
        "nosniff": headers.get("x-content-type-options", "") == "nosniff",
        "referrer": headers.get("referrer-policy", "") == "no-referrer",
        "banners": all(not headers.get(name) for name in ("server", "x-powered-by", "x-aspnet-version")),
    }


def cookie_checks(responses: list[httpx.Response]) -> dict[str, bool]:
    found: dict[str, bool] = {}
    expected = ("__Host-policyops_login", "__Host-policyops_session", "__Host-policyops_csrf")
    for response in responses:
        for raw in response.headers.get_list("set-cookie"):
            cookie = SimpleCookie()
            cookie.load(raw)
            for name, value in cookie.items():
                if name in expected and value.value:  # disregard deletion cookies
                    same_site = "strict" if name.endswith("_csrf") else "lax"
                    valid = bool(value["secure"] and value["path"] == "/" and not value["domain"]
                                 and value["samesite"].lower() == same_site)
                    # The CSRF double-submit cookie is intentionally readable by the browser application.
                    valid = valid and (not value["httponly"] if name.endswith("_csrf") else bool(value["httponly"]))
                    found[name] = found.get(name, True) and valid
    return {name: found.get(name, False) for name in expected}


class LoginForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and (values.get("method") or "").lower() == "post":
            self.action = values.get("action", "")
        if tag == "input" and values.get("name"):
            self.fields[str(values["name"])] = values.get("value") or ""


def fetch(client: httpx.Client, method: str, url: str, *, data: dict[str, str] | None = None,
          follow: bool = False, headers: dict[str, str] | None = None) -> httpx.Response:
    """Bound each body and redirect, refuse compression and any redirect off the HTTPS origin."""
    history: list[httpx.Response] = []
    origin = urlsplit(url).netloc
    request_headers = {"Accept-Encoding": "identity", **(headers or {})}
    for _ in range(9):
        with client.stream(method, url, data=data, headers=request_headers) as response:
            if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                raise ValueError("compressed verification response")
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=16384):
                if len(body) + len(chunk) > 262144:
                    raise ValueError("verification response exceeds bound")
                body.extend(chunk)
            result = httpx.Response(response.status_code, headers=response.headers, content=bytes(body),
                                    request=response.request, history=list(history))
        if not follow or not result.is_redirect:
            return result
        target = urljoin(url, result.headers.get("location", ""))
        parts = urlsplit(target)
        if parts.netloc != origin or parts.scheme != "https" or parts.username or parts.password:
            raise ValueError("verification redirect left HTTPS origin")
        history.append(result)
        if result.status_code == 303 or (method == "POST" and result.status_code in (301, 302)):
            method, data = "GET", None
        url = target
    raise ValueError("too many verification redirects")


def proposal_matches(client: httpx.Client, origin: str, seed_path: Path, principal: str, workspace: str) -> bool:
    try:
        with seed_path.open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return False
        seed = json.loads(raw)
        proposal_id = str(UUID(seed["proposal_id"]))
        case_id = str(UUID(seed["case_id"]))
        version, digest = seed["proposal_version"], seed["action_digest"]
        if type(version) is not int or version < 1 or not re.fullmatch(r"[0-9a-f]{64}", digest):
            return False
        response = fetch(client, "GET", f"{origin}/api/v1/proposals/{proposal_id}?version={version}", headers={
            "PolicyOps-Expected-Principal": principal, "PolicyOps-Expected-Workspace": workspace,
        })
        if response.status_code != 200:
            return False
        proposal = response.json()["proposal"]
        return (proposal["proposal_id"] == proposal_id and type(proposal["proposal_version"]) is int
                and proposal["proposal_version"] == version and proposal["scope"]["case_id"] == case_id
                and proposal["action_digest"] == digest)
    except (OSError, httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return False


def probe_ports(host: str, checks: dict[str, bool], failures: dict[str, str],
                allow_admin_ssh: bool) -> dict[str, list[int]]:
    observed: dict[str, list[int]] = {}
    try:
        # Probe every returned address, not just one DNS answer. Fixed, deliberately small port list.
        addresses = sorted({str(item[4][0]) for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        checks["dns_addresses"] = bool(addresses)
        for address in addresses:
            ipaddress.ip_address(address)
            opened = []
            for port in PORTS:
                try:
                    with socket.create_connection((address, port), timeout=1):
                        opened.append(port)
                except OSError:
                    pass
            observed[address] = opened
            expected = {80, 443}
            allowed = (expected, expected | {22}) if allow_admin_ssh else (expected,)
            checks["ports_" + address] = set(opened) in allowed
    except (OSError, ValueError) as error:
        checks["ports"] = False
        failures["ports"] = type(error).__name__
    return observed


def verify(host: str, *, allow_admin_ssh: bool = False, local: bool = False, expect_release: str | None = None,
           seed_path: Path | None = None) -> dict[str, Any]:
    host = hostname(host)
    origin = "https://" + host
    checks: dict[str, bool] = {}
    failures: dict[str, str] = {}
    # Default CA verification and SNI/name checking; no insecure fallback and no proxy/netrc inheritance.
    with httpx.Client(verify=True, trust_env=False, timeout=10, follow_redirects=False,
                      max_redirects=8) as client:
        try:
            root = fetch(client, "GET", origin)
            checks["https_valid_chain"] = root.status_code == 200
            checks.update({"root_" + k: v for k, v in security_headers(root.headers).items()})
            health = fetch(client, "GET", origin + "/api/v1/health/ready")
            checks["health"] = health.status_code == 200 and health.json().get("status") == "ok"
            checks.update({"api_" + k: v for k, v in security_headers(health.headers).items()})
            redirect = fetch(client, "GET", "http://" + host + "/")
            checks["http_redirect"] = (redirect.status_code in (301, 302, 307, 308)
                                       and redirect.headers.get("location") == origin + "/")
            checks["http_banners"] = security_headers(redirect.headers)["banners"]
            if expect_release is not None:
                release = fetch(client, "GET", origin + "/release")
                checks["release"] = (release.status_code == 200
                                     and release.content == release_sha(expect_release).encode())
            login = fetch(client, "GET", origin + "/api/v1/auth/login", follow=True)
            checks.update({"dex_" + k: v for k, v in security_headers(login.headers).items()})
            parser = LoginForm()
            parser.feed(login.text[:262144])
            if parser.action is None:
                raise ValueError("no Dex login form")
            action = urljoin(str(login.url), parser.action)
            if urlsplit(action).netloc != host or urlsplit(action).scheme != "https":
                raise ValueError("login form left expected origin")
            fields = {**parser.fields, "login": "alice@example.invalid", "password": "PolicyOps-public-demo-alice"}
            signed = fetch(client, "POST", action, data=fields, follow=True)
            cookies = cookie_checks([*login.history, login, *signed.history, signed])
            checks.update({"cookie_" + k: v for k, v in cookies.items()})
            me = fetch(client, "GET", origin + "/api/v1/me")
            principal = me.json() if me.status_code == 200 else {}
            checks["login_session"] = (principal.get("principal_id") == ALICE
                                       and principal.get("workspace_id") == str(DEMO_WORKSPACE)
                                       and principal.get("roles") == ["analyst"])
            if seed_path is not None:
                checks["seeded_proposal"] = checks["login_session"] and proposal_matches(
                    client, origin, seed_path, principal["principal_id"], principal["workspace_id"])
        except (httpx.HTTPError, ValueError, TypeError, AttributeError, RecursionError) as error:
            checks["https_auth_sequence"] = False
            failures["https_auth_sequence"] = type(error).__name__  # no URL queries / response text
    observed = {} if local else probe_ports(host, checks, failures, allow_admin_ssh)
    return {"schema": "policyops.deploy-verification/v1", "at": datetime.now(UTC).isoformat(),
            "hostname": host, "passed": bool(checks) and all(checks.values()), "checks": checks,
            "failures": failures, "observed_open_ports": observed,
            "admin_ssh_exception": allow_admin_ssh, "port_scope": [] if local else list(PORTS)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", type=hostname)
    parser.add_argument("--allow-admin-ssh", action="store_true",
                        help="only for a probe originating in the configured admin /32; repeat externally without it")
    parser.add_argument("--local", action="store_true", help="skip the external fixed-port probes")
    parser.add_argument("--expect-release", type=release_sha)
    parser.add_argument("--seed-json", type=Path, help="read and check the exact seeded proposal")
    args = parser.parse_args()
    destination = report_path("verify")  # validate routing before network I/O
    result = verify(args.hostname, allow_admin_ssh=args.allow_admin_ssh, local=args.local,
                    expect_release=args.expect_release, seed_path=args.seed_json)
    destination.write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
    print(f"Verification {'passed' if result['passed'] else 'FAILED'}; report: {destination}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
