"""Server-only customer bindings for demo seeds.

For each allowlisted dev seed, read the customer from the task's reference
actions on a fresh upstream retail environment: the result of its identity
lookup, if any, and the owners of every user and order those actions name
(read-only tool calls only; no reference write is executed). Exactly one
customer must result. The result is written to a private file outside the repository;
it is never committed, logged or given to the runtime agent. Seeds whose
references name no customer are reported unavailable rather than inferred from
scenario text.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from policyops_evals.projection import Purpose, SplitGuard
from policyops_evals.sources import SourceTree
from policyops_evals.upstream_runtime import prepare


LOOKUPS = ("find_user_id_by_email", "find_user_id_by_name_zip")


def derive_bindings(tree: SourceTree, calibration: Mapping[str, Any], guard: SplitGuard) -> dict[str, Any]:
    prepare(tree.root)
    from tau2.registry import registry

    constructor = registry.get_env_constructor("retail")
    tasks = {task.id: task for task in registry.get_tasks_loader("retail")(task_split_name="base")}
    bindings: dict[str, Any] = {}
    unavailable: dict[str, str] = {}
    for seed in calibration["seeds"]:
        task_id = seed["upstream_task_id"]
        guard.require("retail", task_id, Purpose.DEMO)
        actions = list(tasks[task_id].evaluation_criteria.actions or [])
        environment = constructor()
        environment.set_state(initialization_data=None, initialization_actions=None, message_history=[])
        lookup = next((action for action in actions if action.name in LOOKUPS), None)
        customers: set[str] = set()
        if lookup is not None:
            customers.add(str(environment.make_tool_call(tool_name=lookup.name, requestor=lookup.requestor,
                                                         **lookup.arguments)))
        for action in actions:
            arguments = action.arguments
            if "user_id" in arguments:
                customers.add(str(environment.make_tool_call(tool_name="get_user_details", requestor="assistant",
                                                             user_id=arguments["user_id"]).user_id))
            if "order_id" in arguments:
                customers.add(str(environment.make_tool_call(tool_name="get_order_details", requestor="assistant",
                                                             order_id=arguments["order_id"]).user_id))
        if len(customers) != 1:
            unavailable[seed["seed_id"]] = ("no customer-scoped reference action" if not customers
                                            else "reference actions name more than one customer")
            continue
        derivation = f"reference {lookup.name} replayed" if lookup is not None else "owner of the reference resources"
        bindings[seed["seed_id"]] = {"upstream_task_id": task_id, "user_id": customers.pop(),
                                     "derivation": f"{derivation} on the pinned retail DB"}
    return {"visibility": "server-only; do not commit, log or expose to the runtime agent",
            "allowlist_sha256": calibration["allowlist"]["digest"], "bindings": bindings,
            "unavailable": dict(sorted(unavailable.items()))}
