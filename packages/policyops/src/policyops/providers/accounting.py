"""In-process evidence retained after a failed accounting transaction; no durable outbox."""

class AccountingUnconfirmed[Report](RuntimeError):
    """Stop dispatch and retain normalized available usage. The reserved cost stays conservatively held."""

    def __init__(self, report: Report) -> None:
        self.report = report
        super().__init__("Usage is unconfirmed; reserved cost remains held.")
