"""Allowlisted JSON logging for API/worker hosts; no free-form message, argument, target or exception text.

The legacy query filter remains as defense in depth for hosts still using uvicorn's access formatter.
LOG_CONFIG uses SafeJsonFormatter for every handler; changing formatters changes that security boundary.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from policyops.telemetry import correlation
from policyops.telemetry.attributes import clean


class RedactQueryFilter(logging.Filter):
    """Replace the query string of every logged request target with `?[REDACTED]`."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str) and "?" in args[2]:
            record.args = (*args[:2], args[2].split("?", 1)[0] + "?[REDACTED]", *args[3:])
        return True


EVENTS = frozenset({"application_log", "http_access", "worker_job_error", "executor_error", "claim_lost",
                    "api.startup_failed",
                    "review_error", "review_finish_error"})
LIFECYCLE = {
    "Waiting for application startup.": "api.startup_waiting",
    "Application startup complete.": "api.startup_complete",
    "Application startup failed. Exiting.": "api.startup_exiting",
    "Waiting for application shutdown.": "api.shutdown_waiting",
    "Application shutdown complete.": "api.shutdown_complete",
    "Application shutdown failed. Exiting.": "api.shutdown_exiting",
}


class SafeJsonFormatter(logging.Formatter):
    """Never interpolates msg/args/objects or exception text. Unknown extras are discarded.

    This also protects preformatted library errors, raw paths, cookies and SQLAlchemy DSNs.
    Existing SafeErrorFilter may clear exception metadata; it preserves only the type name.
    Startup diagnostics are reconstructed from validated categories; lifecycle text is a fixed literal.
    """

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", None)
        if not isinstance(event, str) or event not in EVENTS:
            event = "http_access" if record.name == "uvicorn.access" else "application_log"
            if isinstance(record.msg, str):
                code = record.msg.split(" ", 1)[0]
                if code in EVENTS:
                    event = code
        fields: dict[str, object] = {"event": event, "severity": record.levelno}
        fields.update(clean(vars(record)))
        phase, category = fields.pop("startup_phase", None), fields.pop("startup_category", None)
        if event == "api.startup_failed" and phase is not None:
            # A rejected category (e.g. a role error containing configured identities) gets a fixed fallback.
            category = category or "StartupError"
            fields.update(startup_phase=phase, startup_category=category,
                          diagnostic=f"API server startup failed at {phase}: {category}")
        if record.name == "uvicorn.error" and type(record.msg) is str and not record.args:
            lifecycle = LIFECYCLE.get(record.msg)
            if lifecycle is not None:
                fields.update(event=lifecycle, diagnostic=record.msg)
        if record.exc_info and record.exc_info[1] is not None:
            fields.update(clean({"exception_type": type(record.exc_info[1]).__name__}))
        if "exception_type" in fields:
            fields["error_code"] = "boundary_error"
        fields.update(correlation())
        return json.dumps(fields, ensure_ascii=True, separators=(",", ":"))


LOG_CONFIG: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"redact_query": {"()": "policyops.api.logging.RedactQueryFilter"}},
    "formatters": {"access": {"()": SafeJsonFormatter}, "default": {"()": SafeJsonFormatter}},
    "handlers": {"access": {"class": "logging.StreamHandler", "formatter": "access", "filters": ["redact_query"],
                            "stream": "ext://sys.stdout"},
                 "default": {"class": "logging.StreamHandler", "formatter": "default",
                             "stream": "ext://sys.stderr"}},
    "loggers": {"uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False}},
    "root": {"handlers": ["default"], "level": "WARNING"},
}
