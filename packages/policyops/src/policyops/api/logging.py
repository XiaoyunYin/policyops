"""Access-log redaction for the API process.

uvicorn's access log records the full request target, which for `/api/v1/auth/callback` includes the one-time
authorization `code` and `state`. Install `RedactQueryFilter` on the `uvicorn.access` logger (`LOG_CONFIG` does,
for `uvicorn --log-config`) so query strings never reach access logs. Cookies and headers are not part of
uvicorn's access line.
"""

from __future__ import annotations

import logging
from typing import Any


class RedactQueryFilter(logging.Filter):
    """Replace the query string of every logged request target with `?[REDACTED]`."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str) and "?" in args[2]:
            record.args = (*args[:2], args[2].split("?", 1)[0] + "?[REDACTED]", *args[3:])
        return True


LOG_CONFIG: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact_query": {"()": "policyops.api.logging.RedactQueryFilter"}},
    "formatters": {"access": {"()": "uvicorn.logging.AccessFormatter",
                              "fmt": '%(client_addr)s - "%(request_line)s" %(status_code)s'}},
    "handlers": {"access": {"class": "logging.StreamHandler", "formatter": "access", "filters": ["redact_query"],
                            "stream": "ext://sys.stdout"}},
    "loggers": {"uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False}},
}
