"""SQL helpers shared by the retail revisions: the tenant/case row-level security policy and the downgrade guard."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import Connection, text


SCOPE = ("tenant_id = nullif(current_setting('retail.tenant_id', true), '')::uuid "
         "AND case_id = nullif(current_setting('retail.case_id', true), '')::uuid")


class DataLossRefused(RuntimeError):
    """A retail downgrade would drop rows (state, receipts or outcomes); restore a consistent backup instead."""


def scoped_policy(table: str, *, select_insert_only: bool = False) -> str:
    """Enable and force RLS on `retail.<table>`; the runtime sees and writes only its transaction's tenant and case.
    Unset settings match nothing."""
    statements = [f"ALTER TABLE retail.{table} ENABLE ROW LEVEL SECURITY",
                  f"ALTER TABLE retail.{table} FORCE ROW LEVEL SECURITY"]
    if select_insert_only:
        statements += [f"CREATE POLICY {table}_read ON retail.{table} FOR SELECT TO retail_runtime USING ({SCOPE})",
                       f"CREATE POLICY {table}_write ON retail.{table} FOR INSERT TO retail_runtime "
                       f"WITH CHECK ({SCOPE})"]
    else:
        statements.append(f"CREATE POLICY {table}_scope ON retail.{table} FOR ALL TO retail_runtime "
                          f"USING ({SCOPE}) WITH CHECK ({SCOPE})")
    return ";\n".join(statements) + ";"


def refuse_populated(connection: Connection, tables: Sequence[str]) -> None:
    """Refuse the downgrade if any table has a row. The migrator owns the tables but FORCE RLS would hide every row
    from it, so FORCE is lifted for the count only and restored; a refusal rolls the whole revision back."""
    for table in tables:
        connection.execute(text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
        populated = connection.execute(text(f"SELECT EXISTS (SELECT 1 FROM {table})")).scalar()  # noqa: S608
        connection.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        if populated:
            raise DataLossRefused(f"{table} holds rows; a retail downgrade is refused (restore a consistent backup)")
