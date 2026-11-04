"""Pinned upstream identity and the repository paths PolicyOps consumes.

Values here are reviewed constants, not configuration: changing the upstream
revision means a new acquisition, new manifests and a new review.
"""

from policyops_evals import TAU2_COMMIT


REPOSITORY_URL = "https://github.com/sierra-research/tau2-bench.git"
COMMIT = TAU2_COMMIT
# Root tree of COMMIT, read from the fetched commit object and re-derived from
# every verified tree/blob object during acquisition.
TREE = "f6b4756d287ca59e654d76545e8d6dfb8618a020"

LICENSE = "LICENSE"
README = "README.md"
PYPROJECT = "pyproject.toml"

DATA = "data/tau2"
RETAIL_DIR = f"{DATA}/domains/retail"
RETAIL_TASKS = f"{RETAIL_DIR}/tasks.json"
RETAIL_POLICY = f"{RETAIL_DIR}/policy.md"
RETAIL_DB = f"{RETAIL_DIR}/db.json"
RETAIL_UPSTREAM_SPLITS = f"{RETAIL_DIR}/split_tasks.json"
RETAIL_ISSUES_DIR = f"{RETAIL_DIR}/task_issues"
RETAIL_50 = f"{DATA}/task_subsets/retail_50.json"
RETAIL_114 = f"{DATA}/task_subsets/retail_114.json"
TEXT_BENCHMARK = f"{DATA}/benchmarks/text.json"
# English language pack: the text-v1 retail binding replaces same-ID registry
# tasks with these reviewed versions (multilingual/runtime.py _binding_tasks).
EN_PACK = f"{DATA}/multilingual/en/pack.yaml"
EN_RETAIL_TASKS = f"{DATA}/multilingual/en/retail_tasks_en.json"
EN_RETAIL_METADATA = f"{DATA}/multilingual/en/retail_metadata_en.json"

BANKING_DIR = f"{DATA}/domains/banking_knowledge"
# The upstream loader (banking_knowledge/environment.py get_tasks) reads one file
# per task from tasks/; the aggregated tasks.json is not read by upstream code.
BANKING_TASKS_DIR = f"{BANKING_DIR}/tasks"
BANKING_TASKS_AGGREGATE = f"{BANKING_DIR}/tasks.json"
BANKING_DOCUMENTS_DIR = f"{BANKING_DIR}/documents"
BANKING_DB = f"{BANKING_DIR}/db.json"
BANKING_97 = f"{DATA}/task_subsets/banking_knowledge_97.json"
BANKING_BENCHMARK = f"{DATA}/benchmarks/banking.json"

# Byte digest of the released subset; it also appears in upstream
# task_subsets/store.py SHIPPED_SUBSET_SHA256 and benchmarks/text.json.
RETAIL_50_SHA256 = "dc7490f023d1bf9c345edf9c37a8e658298ac3a5be884e012bfb271b3678f2be"
RETAIL_EN_TEXT_BINDING = "e73f190f6820db05b0baa8472505f4676d3c40114bae0fe93f5fbd56d8321bf3"

# Files and directory prefixes whose bytes PolicyOps reads. Every file under a
# prefix is part of the consumed scope (and of the pinned SHA-256 list).
CONSUMED_FILES = (
    LICENSE, README, PYPROJECT,
    RETAIL_TASKS, RETAIL_POLICY, RETAIL_DB, RETAIL_UPSTREAM_SPLITS,
    RETAIL_50, RETAIL_114, TEXT_BENCHMARK, EN_PACK, EN_RETAIL_TASKS, EN_RETAIL_METADATA,
    BANKING_TASKS_AGGREGATE, BANKING_DB, BANKING_97, BANKING_BENCHMARK,
)
CONSUMED_PREFIXES = (RETAIL_ISSUES_DIR + "/", BANKING_TASKS_DIR + "/", BANKING_DOCUMENTS_DIR + "/")


def is_consumed(path: str) -> bool:
    return path in CONSUMED_FILES or path.startswith(CONSUMED_PREFIXES)
