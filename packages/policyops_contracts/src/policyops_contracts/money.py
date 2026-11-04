"""Exact money: integer minor units plus currency; never floats.

Upstream tau2 retail stores prices, payment amounts and gift-card balances as
Python floats. `money_from_upstream` converts one such value exactly or refuses:
the shortest repr of the float must already have at most two decimal places
(true for every value in the pinned DB). bool, NaN, infinities, strings and
values with more precision are rejected; nothing is rounded. Conversion uses
exact integer arithmetic, so the thread's decimal context cannot alter it.
"""

from decimal import Decimal, InvalidOperation
import math
from typing import Annotated, Literal

from pydantic import Field

from policyops_contracts.base import WireModel


MINOR_PER_UNIT = 100
MAX_MINOR = 10**12
Currency = Literal["USD"]


class MoneyError(ValueError):
    """A value cannot be represented exactly as money."""


class Money(WireModel):
    amount_minor: Annotated[int, Field(ge=-MAX_MINOR, le=MAX_MINOR)]
    currency: Currency = "USD"

    def __add__(self, other: "Money") -> "Money":
        self._same_currency(other)
        return Money(amount_minor=self.amount_minor + other.amount_minor, currency=self.currency)

    def __sub__(self, other: "Money") -> "Money":
        self._same_currency(other)
        return Money(amount_minor=self.amount_minor - other.amount_minor, currency=self.currency)

    def __neg__(self) -> "Money":
        return Money(amount_minor=-self.amount_minor, currency=self.currency)

    def _same_currency(self, other: "Money") -> None:
        if other.currency != self.currency:
            raise MoneyError("currency mismatch")

    def to_decimal(self) -> Decimal:
        # String construction is exact regardless of the ambient decimal context (division is not).
        return Decimal(f"{self.amount_minor}E-2")

    def display(self) -> str:
        """Deterministic display form, e.g. "$1,234.50" or "-$3.00"."""
        sign = "-" if self.amount_minor < 0 else ""
        units, minor = divmod(abs(self.amount_minor), MINOR_PER_UNIT)
        return f"{sign}${units:,}.{minor:02d}"


ZERO = Money(amount_minor=0)


def money_from_upstream(value: object, currency: Currency = "USD") -> Money:
    """Exact conversion of an upstream JSON number (int or float dollars) to minor units."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise MoneyError(f"upstream money must be a number, not {type(value).__name__}")
    if isinstance(value, float) and not math.isfinite(value):
        raise MoneyError("upstream money must be finite")
    if isinstance(value, int):
        amount = value * MINOR_PER_UNIT
    else:
        # Decimal(str) is exact under any context; the arithmetic below is integer-only, so neither
        # the ambient precision nor the rounding mode can change the result.
        try:
            sign, digits, exponent = Decimal(repr(value)).as_tuple()
        except InvalidOperation as exc:  # pragma: no cover - repr of a finite float always parses
            raise MoneyError("upstream money is not a decimal number") from exc
        if not isinstance(exponent, int):  # pragma: no cover - finite values only
            raise MoneyError("upstream money must be finite")
        if exponent < -2:
            raise MoneyError(f"upstream money {value!r} has more than two decimal places")
        coefficient = int("".join(map(str, digits)) or "0")
        if exponent + 2 > 20:
            raise MoneyError("upstream money is out of range")
        amount = (-1 if sign else 1) * coefficient * 10 ** (exponent + 2)
    if abs(amount) > MAX_MINOR:
        raise MoneyError("upstream money is out of range")
    return Money(amount_minor=amount, currency=currency)
