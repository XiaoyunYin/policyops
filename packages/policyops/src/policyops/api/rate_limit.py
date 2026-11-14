"""Optional single-process public-demo admission limit; fixed memory and no forwarded-header guessing.

Caddy replaces X-PolicyOps-Client-IP. Only a loopback socket may supply that single IP literal.
At capacity new IPs are refused until the oldest window expires; churn cannot evict live buckets.
This is an availability guard, not identity/authorization or a distributed DDoS defense.
"""

from collections import OrderedDict
from collections.abc import Callable
import ipaddress
import math
import time
from uuid import uuid4

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from policyops_contracts.errors import ErrorCode, ErrorEnvelope


class PublicRateLimit:
    def __init__(self, app: ASGIApp, *, requests: int = 120, seconds: float = 60,
                 max_clients: int = 4096, clock: Callable[[], float] = time.monotonic) -> None:
        if requests < 1 or seconds <= 0 or not math.isfinite(seconds) or max_clients < 1:
            raise ValueError("invalid public rate limit")
        self.app, self.requests, self.seconds = app, requests, seconds
        self.max_clients, self.clock = max_clients, clock
        self.windows: OrderedDict[str, tuple[float, int]] = OrderedDict()

    @staticmethod
    def client_ip(scope: Scope) -> str:
        peer = scope.get("client")
        if peer is None:
            return "unknown"
        try:
            address = ipaddress.ip_address(peer[0])
        except ValueError:
            return "unknown"
        if address.is_loopback:
            forwarded = [v for k, v in scope["headers"] if k.lower() == b"x-policyops-client-ip"]
            if len(forwarded) == 1 and len(forwarded[0]) <= 45:
                try:
                    return str(ipaddress.ip_address(forwarded[0].decode("ascii")))
                except (ValueError, UnicodeError):
                    pass
        return str(address)

    def admit(self, client: str) -> bool:
        now = self.clock()
        while self.windows:
            _, (start, _) = next(iter(self.windows.items()))
            if now - start < self.seconds:
                break
            self.windows.popitem(last=False)
        previous = self.windows.get(client)
        if previous is None:
            if len(self.windows) >= self.max_clients:
                return False
            self.windows[client] = (now, 1)
            return True
        start, count = previous
        if count >= self.requests:
            return False
        self.windows[client] = (start, count + 1)
        return True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Admission contains no awaits: concurrent requests on this event loop share an atomic decision.
        if scope["type"] == "http" and not self.admit(self.client_ip(scope)):
            envelope = ErrorEnvelope(code=ErrorCode.RATE_LIMITED, detail="Please retry later.",
                                     rule_id="api.public_rate_limit", correlation_id=uuid4(), retryable=True)
            await JSONResponse(envelope.model_dump(mode="json"), status_code=429,
                               headers={"Retry-After": str(math.ceil(self.seconds)),
                                        "Cache-Control": "no-store"})(scope, receive, send)
            return
        await self.app(scope, receive, send)
