"""Redaction for anything the harness persists (command lines, environment, captured output, reports).

Patterns cover common credential shapes plus explicitly registered values (fixture passwords, canaries) and
values a caller passes as `extra` (for example the values of secret-named flags in a command's own argv). Masking
a very short exact value would destroy ordinary output, so explicitly known secrets shorter than MIN_SECRET_LENGTH
are refused instead: `register()` raises and the evidence recorder will not run such a command. This is a safety net,
not a guarantee: unknown secret formats can pass, so tests use synthetic values only and never read real
credentials.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import re
import threading


MASK = "[REDACTED]"
MIN_SECRET_LENGTH = 6
SECRET_FLAG = re.compile(
    r"^--?(?:[a-z0-9]+[-_])*(?:password|passwd|pass|secret|token|api[-_]?key|key|credential|auth)$", re.IGNORECASE)
SECRET_ENV = re.compile(r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|CREDENTIAL|PRIVATE_KEY|AUTH|_KEY$)",
                        re.IGNORECASE)
PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)(?<=authorization:)\s*(?:bearer|basic|token)\s+[^\s,;\"']+"),
    re.compile(r"(?i)\b(?:bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?<=://)([^/\s:@]+):([^@\s/]+)(?=@)"),
    re.compile(r"(?i)(?<=\bpassword=)[^\s&;\"'\]\[]+"),
    re.compile(r"(?i)(?<=\bpassword )'[^']*'"),
)

_lock = threading.Lock()
_known: set[str] = set()


def require_maskable(values: Iterable[str], what: str) -> None:
    """Raise ValueError (without the value) if a non-empty secret is too short to be masked safely."""
    if any(0 < len(value) < MIN_SECRET_LENGTH for value in values):
        raise ValueError(f"{what} is shorter than {MIN_SECRET_LENGTH} characters and could not be masked safely")


def register(*values: str) -> None:
    """Treat these exact values as secrets wherever they appear (e.g. a generated fixture password).

    Non-empty values shorter than MIN_SECRET_LENGTH are refused with ValueError; nothing is registered then.
    """
    require_maskable(values, "a registered secret")
    with _lock:
        _known.update(value for value in values if value)


def forget(*values: str) -> None:
    with _lock:
        _known.difference_update(values)


def redact_text(text: str, extra: Iterable[str] = ()) -> str:
    with _lock:
        values = _known | {value for value in extra if len(value) >= MIN_SECRET_LENGTH}
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, MASK)
    for pattern in PATTERNS:
        if pattern.groups == 2:
            text = pattern.sub(lambda match: f"{match.group(1)}:{MASK}", text)
        else:
            text = pattern.sub(MASK, text)
    return text


def contains_secret(text: str, extra: Iterable[str] = ()) -> bool:
    """Whether redaction would change `text` (a known value or a credential pattern is present)."""
    return redact_text(text, extra) != text


def secret_values_in_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """The values of secret-named flags (`--token=v`, `--token v`), which redact_argv masks."""
    values: list[str] = []
    take_next = False
    for arg in argv:
        if take_next:
            values.append(arg)
            take_next = False
            continue
        flag, sep, value = arg.partition("=")
        if SECRET_FLAG.match(flag):
            if sep:
                values.append(value)
            else:
                take_next = True
    return tuple(values)


def secret_values_in_environment(env: Mapping[str, str]) -> tuple[str, ...]:
    """Values of secret-named variables in an environment the caller supplied explicitly."""
    return tuple(value for name, value in env.items() if SECRET_ENV.search(name))


def redact_argv(argv: Sequence[str], extra: Iterable[str] = ()) -> tuple[str, ...]:
    extra = tuple(extra)
    result: list[str] = []
    mask_next = False
    for arg in argv:
        if mask_next:
            result.append(MASK)
            mask_next = False
            continue
        flag, sep, _value = arg.partition("=")
        if SECRET_FLAG.match(flag):
            if sep:
                result.append(f"{flag}={MASK}")
            else:
                result.append(arg)
                mask_next = True
            continue
        result.append(redact_text(arg, extra))
    return tuple(result)


def redact_environment(env: Mapping[str, str], names: Iterable[str]) -> tuple[tuple[str, str], ...]:
    """Selected variables only (an explicit allowlist), with secret-looking names masked."""
    return tuple((name, MASK if SECRET_ENV.search(name) else redact_text(env[name]))
                 for name in sorted(set(names)) if name in env)
