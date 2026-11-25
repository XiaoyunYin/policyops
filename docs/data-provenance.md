# Data provenance, rights audit and splits

PolicyOps evaluates against public τ²-bench data at commit
`19f13ea3f5fba8b4c4d272d1353590f29dc53062` (root tree
`f6b4756d287ca59e654d76545e8d6dfb8618a020`). The data is fetched to a local
directory outside this repository and never committed. The reviewed metadata
derived from it lives in [`evals/manifests/tau2-19f13ea3/`](../evals/manifests/tau2-19f13ea3/):

| Manifest | Contents |
|---|---|
| `source.json` | Commit, tree, digest of the full 2,217-entry tree inventory, SHA-256/Git blob of the 815 consumed files |
| `retail-split.json` | 114-task frame, 50 held-out IDs (upstream `retail_50`), 64 dev IDs (the complement), digests, strata |
| `banking-split.json` | Label validation, `tasks.json` comparison, groups and the 39 dev / 58 test split |
| `rights-audit.json` | Per-file categories and marker counts for consumed files; bounded scan of the rest |
| `retail-audit.json` | Dev/holdout scoring profile, upstream issue annotations, reviewed-scenario replacements, near-duplicate check |
| `upstream-verification.json` | Results of pinned upstream code run against the acquisition |
| `corpus-tokens.json` | Extraction digests, sizes and tokenizer-specific counts |
| `retail-calibration.json` | Dev demo/tuning allowlist (46 of 64), 18 sourced exclusions, mutation/read-only tags, neutral metadata-only seeds; see [architecture.md](architecture.md) |
| `ingest-corpora.json` | Ingestion source manifest (`policyops.ingest-manifest/v1`): per corpus the document keys, paths, Git blobs, SHA-256 digests and sizes, license scope, render and rendered-list digest; no document text. See [Ingestion manifest](#ingestion-manifest) |

Each manifest except `ingest-corpora.json` carries `manifest_sha256` over its canonical JSON, so an edit that is not
regenerated is detected. The ingestion manifest is instead bound by the SHA-256 of its exact bytes, which the
ingestion command requires from its caller, and `ingest_manifest --check` compares it with a fresh rebuild.

## Commands

All commands run in the evaluator environment (`evals/`). They never call a model, simulator, judge or embedding API.
Every data, cache and output directory must lie outside the checkout.

```powershell
# Live (network): fetch the pinned commit into a new, empty directory.
python -B scripts/devenv.py uv --project evals run --frozen policyops-evals data fetch --dest D:\path\outside\tau2-fetch
# Offline: re-verify an acquisition and compare a fresh rebuild with the committed manifests.
python -B scripts/devenv.py uv --project evals run --frozen policyops-evals data verify --acquired D:\path\outside\tau2-fetch
python -B scripts/devenv.py uv --project evals run --frozen policyops-evals data upstream-check --acquired D:\path\outside\tau2-fetch --check
# Network on first use (tiktoken vocabulary download into --cache), offline once cached:
python -B scripts/devenv.py uv --project evals run --frozen policyops-evals data tokens --acquired D:\path\outside\tau2-fetch --cache D:\path\outside\tiktoken --extract D:\path\outside\extracted --check
# Offline, no data needed (also covered by the evaluator tests):
python -B scripts/devenv.py uv --project evals run --frozen policyops-evals data check-manifests
```

`build` (without `--check`) rewrites the source, split, rights and audit manifests. On first use `tokens` downloads
the two tiktoken vocabularies into `--cache` (network); tiktoken checks them against the SHA-256 values in its
installed package, and later runs are offline.

## Ingestion manifest

`ingest-corpora.json` is generated from the committed `source.json`, `corpus-tokens.json` and `rights-audit.json`
only: no acquisition tree, document text or network is needed.

```powershell
# Offline: rebuild from the committed manifests and compare with the committed file (no data, no model).
python -B scripts/devenv.py uv --project evals run --frozen python -B -m policyops_evals.ingest_manifest --check
```

Running it without `--check` rewrites the file. It lists two corpora, both under the root MIT grant described below:

| Corpus | Domain | Render | Documents | Source |
|---|---|---|---:|---|
| `tau2-banking-knowledge` | `banking_knowledge` | `tau2-banking/v1` (`## <title>`, blank line, content, as the data audit's `render_document`) | 698 | every consumed `banking_knowledge/documents/*.json`, keyed by file stem |
| `tau2-retail-policy` | `retail` | `identity` (the decoded file) | 1 | the retail `policy.md` |

Each document's path, Git blob, SHA-256 and size come from `source.json`, the license scope statement is the rights
audit's verbatim. The rendered-list digest is the SHA-256 of the sorted per-document rendered-body SHA-256 hex
strings (sorted by document key) joined by LF: it is the data audit's for banking, and for retail the list has one string, so
the digest is the SHA-256 of the ASCII policy-file digest and is distinct from that file digest. The retail file
digest itself is cross-checked against the data audit's `retail_policy_sha256`. The source revision (repository, commit, tree and source-manifest
digest) belongs to the manifest: a future revision gets its own manifest and values.

At import time the ingestion command re-verifies each listed file against these values (size, SHA-256, Git blob,
strict UTF-8, rendered-list digest) before anything is written; see [architecture.md](architecture.md#corpus-ingestion).
The imported bodies exist only in the operator's own PostgreSQL database for one workspace, never in Git. The rights
position is unchanged: the root MIT license is the only explicit grant, and it does not establish the provenance of
every data file. Neither this manifest nor ingestion establishes retrieval quality. Retail model/cost outcomes
are measured separately in [evaluation](evaluation.md), using full policy context.

## Acquisition integrity

`data fetch` runs `git fetch --depth=1` for the commit into a bare repository with an isolated configuration (no
global config, hooks, submodules, prompts or non-HTTPS protocols). Nothing is checked out. Every commit, tree and
blob object read back is re-hashed in Python, and file bytes are written from the object store without line-ending
conversion. Unsafe or case-colliding paths are rejected. The acquisition keeps the raw commit object, the inventory
and the target bytes of the tree's single symlink.

Verification does not trust the inventory. The saved commit object must hash to the pinned commit and name the
pinned tree. Every file is re-hashed from its bytes, all tree objects are rebuilt from those blob IDs, and the
rebuilt root must equal the pinned tree. Regular files can never be declared "unmaterialized": only the symlink
(target re-hashed) and submodules (none here) may be absent. A changed file therefore fails even if every recorded
hash is rewritten consistently. Two independent fetches produced the same inventory digest
(`bd678f7082b88c8889afed105b86864d71545097a1fc1d1972821a068153090e`) and byte-identical manifests.

The evaluator environment must also contain the commit's exact source bytes, because upstream fingerprints
installed code. With Git for Windows' default `core.autocrlf=true`, uv's dependency checkout once installed tau2 with
CRLF line endings. Python behavior was unchanged, but the English retail binding revision differed from the
published pin. `scripts/devenv.py` now passes `core.autocrlf=false` to child Git processes through
`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`, without changing any Git configuration file. `upstream-check` hashes the
actual bytes of every `tau2/` file listed in the installed wheel's RECORD against that RECORD entry and the commit
blob, and fails on any difference. It makes no claim about files the RECORD does not list (for example bytecode or
later additions). The evaluator also uses its own versioned uv cache and virtual environment
(`cache/uv-evals-raw-v1`, `venvs/evals-raw-v1` under `POLICYOPS_TEMP_DIR`). Older `cache/uv` and `venvs/evals`
installs that hold a CRLF tau2 checkout are never reused, migrated or deleted.

Upstream loaders open JSON without an explicit encoding, so on a non-UTF-8 Windows locale `get_tasks` silently skips
`task_100.json`. The evaluator therefore requires Python UTF-8 mode (`PYTHONUTF8=1`, set by `scripts/devenv.py`) and
refuses to run upstream checks without it.

## Rights and provenance audit

The only explicit grant found in the pinned repository is the root MIT `LICENSE` (Copyright (c) 2025 Sierra
Research; reproduced in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)) together with `license = "MIT"` in its
`pyproject.toml`. The audit:

- scans every consumed file (815: 698 banking documents, 100 task-definition files, 2 simulated databases, the
  retail policy, the license, 2 upstream metadata files, 8 subset/benchmark/language-pack files and 3 upstream review
  trajectories)
  over its full content. It counts license, copyright, SPDX, named-license, rights-reserved, URL and e-mail
  markers; matched text is never copied. No consumed file other than `LICENSE` carries a license or copyright
  marker. 93 contain e-mail-like strings and 2 contain URLs;
- for the 1,401 materialized files PolicyOps does not use, checks notice-like file names and license markers in the
  first 64 KiB only. This is not an exhaustive rights review of those files. It flags, among others, upstream
  `src/tau2/voice/audio_native/launa/THIRD_PARTY_NOTICES.md`, which ships inside the installed tau2 package.
  Any image that redistributes the package must keep that file as well as the root license;
- assigns each consumed file a category and a PolicyOps decision. No upstream data file, task payload or document text is redistributed in Git; the only
  upstream text in the repository is the license reproduced in THIRD_PARTY_NOTICES.md. Retail
  review trajectories are neither redistributed nor used as fixtures, and no manifest copies the contributor e-mail
  address found in their issue metadata.

Remaining uncertainty: the repository does not say how the retail database records, task scenarios or banking
documents were authored, or whether any text derives from third-party material. Names, addresses and e-mail-like
strings are presumed fictional benchmark content, but this cannot be proven. URLs inside data files were not
followed or audited. Dependency license inventories and their redistribution limits are described in
[third-party notices](../THIRD_PARTY_NOTICES.md).

The historical help desk import test derives its CSV, server-side bindings and reconciliation oracle at test
time from the hash-verified retail database. It keeps these generated files under the external test root.
Application unit tests use a small authored fixture. [Historical import](integration.md#historical-ticket-import)

## Retail split (64 dev / 50 held out)

The held-out set is every task ID in upstream `task_subsets/retail_50.json`. Its byte SHA-256,
`dc7490f023d1bf9c345edf9c37a8e658298ac3a5be884e012bfb271b3678f2be`, equals the value pinned in upstream
`benchmarks/text.json` and `task_subsets/store.py`. It is a stratified draw (`write_profile`, seed 42) from the
114-task frame (`f05763b3…`). Dev is the complement of 64 tasks in upstream order. Upstream `verify_subset`
re-derives the draw from the canonical frame without error, and `binding_revision` recomputes the English text-v1
retail binding `e73f190f…`. Upstream's own 74/40 split is recorded but not used.

What the audit found (`retail-audit.json`, `upstream-verification.json`):

- Under the English text-v1 binding, all 50 held-out tasks use reviewed user scenarios from
  `multilingual/en/retail_tasks_en.json` (only `user_scenario` differs; evaluation criteria are identical). No dev
  task has a reviewed replacement, so dev runs use the registry scenarios from `tasks.json`.
- All three upstream issue annotations (tasks 4, 5, 7; status open) are dev tasks.
- Scoring profile: every held-out task uses `DB + NL_ASSERTION`, with 16 non-empty and 34 empty assertion lists. In
  dev, 62 use `DB + NL_ASSERTION` and 2 use `DB`; 24 have assertions, and 38 list `NL_ASSERTION` without any.
- Replaying dev reference actions twice in fresh upstream environments gives the same final database hash for all
  64 tasks (tool outputs and error sequences are not compared). 9 tasks (2, 3,
  4, 35, 37, 46, 54, 55, 67) contain at least one reference action that raises `ValueError` (failed lookups), and 6
  (10, 12, 24, 57, 62, 67) leave the database unchanged; tasks 24 and 57 have no reference actions. Held-out
  reference actions are never replayed.
- Many scenarios are templated variants of adjacent IDs. 12 dev tasks have a held-out scenario with character
  5-gram Jaccard ≥ 0.7 (20 at ≥ 0.5, max 0.913, dev 62 vs held-out 63). Tuning on those dev tasks is close to
  tuning on their held-out neighbours. The split is fixed by upstream, so this is disclosed rather than repaired;
  the committed demo/tuning allowlist excludes these neighbours.

During the source audit, holdout reads were limited to IDs, `reward_basis`, whether NL assertions exist, issue annotations, scenario text for
the similarity check, and a whole-record equality comparison with the reviewed replacement (reported as field names
only). That audit did not replay held-out reference actions or inspect assertion text individually.
The later registered retail study uses the upstream evaluator to score them; see [evaluation](evaluation.md).

## Banking knowledge labels and grouped split (39 dev / 58 test)

The canonical tasks are the 97 `tasks/task_*.json` files that upstream `get_tasks` loads; the aggregated
`tasks.json` is not read by upstream code. `required_documents` holds document IDs equal to JSON file stems. The
canonical labels have **218** distinct IDs and **0** unmatched, against 698 document files. Tasks require 1–30
documents (mean 9.8866; 70 require more than 5). The most frequent document appears in 44 tasks. The aggregate
`tasks.json` differs for 13 tasks (in 7 of them `required_documents`) and yields the earlier census of 215 IDs (mean
9.7835). Three IDs occur only in the canonical labels; none occur only in the aggregate. Upstream's loader returns
exactly the same ordered labels per task.

These are task-level labels for a whole multi-turn trajectory, not per-turn or per-chunk relevance judgments.

The offline retrieval metric engine reads these labels for the 39 development tasks only. It takes the dev IDs from the committed split manifest (checking its digest and count and that dev and test do not overlap), then opens exactly those pinned task files, verifies each against its recorded SHA-256 and keeps only the task ID and its required documents. Test-split and aggregate payloads are not opened, and the labels never enter the application runtime, prompts, records or logs. Coverage counts a labelled document as covered when it appears among the documents actually delivered across a trajectory; documents merely considered as candidates are reported separately and are not headline coverage. The frequent-document and grouping facts above are why the metrics also report a document-weighted view and a scenario-group sensitivity; neither turns task-level labels into per-turn relevance.

Grouping: tasks are linked when their required-document sets have Jaccard ≥ 0.5 or their user-scenario texts share
≥ 0.5 of their character 5-grams, and connected components become groups, so near-duplicates under this
heuristic never straddle dev and test (semantic duplicates it misses are not validated). This gives 41 groups (20 singletons;
the largest has 8 tasks). Groups are ordered by SHA-256 of `"42|banking_knowledge|<group id>"`; a group joins dev
while dev stays within round(0.4 × 97) = 39 tasks. The result is 39 dev tasks in 19 groups and 58 test tasks in 22
groups. Thresholds and seed were fixed before any retrieval run. The document corpus is shared by design: 83
required documents occur in both splits, 53 only in dev, 82 only in test, and 480 are never required.

## Extracted text and token counts

Banking documents render as upstream `format_full_knowledge_base` renders each one (`## <title>\n\n<content>`),
joined by `\n\n---\n\n` in sorted file-stem order. Upstream iterates an unsorted directory listing, so its order is
platform-dependent. The joined corpus is 861,972 UTF-8 bytes (SHA-256 `da4ee293…`); the 698 source files total
932,122 bytes. The retail policy is 6,699 bytes (SHA-256 `2c9652af…`).

| Text | cl100k_base | o200k_base |
|---|---:|---:|
| Retail policy | 1,401 | 1,402 |
| Banking corpus, joined | 181,320 | 179,847 |
| Banking documents, per document (min / median / max) | 68 / 202 / 1,955 | 68 / 201 / 1,953 |

Counts come from installed tiktoken 0.14.0. Its model table maps `text-embedding-3-small` to `cl100k_base`, so those
are exact embedding-input counts for this text. It maps neither `gpt-6-luna` nor `claude-haiku-5-5`, so the
o200k_base column is a tokenizer-specific measurement, not a count for either model. Provider counts come from
`POST /v1/responses/input_tokens` (OpenAI) and `POST /v1/messages/count_tokens` (Anthropic). Both need credentials,
and the offline `tokens` command calls neither. A separate reviewer probe of the Anthropic endpoint for
`claude-haiku-5-5` on the same extracted bytes returned request-level estimates of 1,934 (policy) and 295,659
(corpus) input tokens, each sent as one user message. Those are not bare-text tokenizations or full agent prompts,
and they do not show that the model can use that much context. No OpenAI count has been measured.

Three kinds of token figures must not be conflated. First, local counts: the counts above are of raw extracted text,
and a retrieval step's budget (default 4096) is a local cl100k count of the whole formatted evidence string, headers and
separators included. Second, a provider's count endpoint returns a preflight estimate of a request's input tokens, for
the exact serialized request that was counted. Third, the usage a provider returns with an actual response is the billing
evidence. The local counts are neither of the other two, and a count-endpoint result is not the billed amount. None of
these is evidence of retrieval quality or of what a model can use.

## MultiDoc2Dial v1.0

The additional document-grounded QA dataset is **MultiDoc2Dial v1.0** (IBM), by Song Feng, Siva Sankalp Patel,
Hui Wan and Sachindra Joshi. Cite *MultiDoc2Dial: Modeling Dialogues Grounded in Multiple Documents*, EMNLP 2021
([paper](https://arxiv.org/abs/2109.12595), [dataset homepage](https://doc2dial.github.io/multidoc2dial/)).
The accepted provenance review found conflicting licensing metadata: the Hugging Face YAML tag says Apache-2.0,
while its licensing section and the Doc2Dial card say [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/).
PolicyOps treats the data as CC BY 3.0, retains attribution, and describes its transformations here. The conflict
is disclosed rather than interpreted as an additional Apache grant.

The archive obtained from doc2dial.github.io on 2026-11-14 is 6,868,509 bytes, SHA-256
`f0c034c249663d7b3cb08b19cf2cc2c3d101372485be982621d4711931a1ce00`. This identifies archive bytes, not an upstream
Git commit. The [manifest](../evals/manifests/multidoc2dial-v1/manifest.json) pins each consumed member and records
source identities, algorithms, tokenizer, rights, domain/act counts and compact audit summaries. It lists sorted
dialogue IDs for dev, retrieval, answers and full context, retaining their design hashes. The G8 pool is defined
by rule, counts and hashes, without listing its IDs. No document or dialogue text or per-query qrels are published.
Source archives, derived text stores, human replies and execution traces remain private.

The offline [builder](../evals/src/policyops_evals/datasets/multidoc2dial.py) reads the ZIP directly, without
extracting files or executing HTML. It checks archive/member SHA-256, an explicit member allowlist, safe relative
paths, regular-file types, bounded sizes, compression ratios and duplicate names. Apple resource forks are ignored
after structural safety checks. The dummy official test member is not parsed. Document/span identities, exact
text slices and every reference are checked; unknown references fail the build.

`md2d.title-runs/v1` sorts documents by domain/document ID and spans by start/end/integer span ID, then keeps
maximal consecutive runs of equal titles. Bodies are exact source slices; headings join the first span's parent
titles and title with ` > `. Repeated titles in separate runs retain separate identities. The result is **4,110
passages**, including **537 heading-only runs**, from 488 documents. Passage IDs bind domain, original document ID
and one-based run ordinal, with separate content hashes. Matching the paper's passage count does not establish
identical upstream preprocessing.

Queries target agent turns immediately after user turns, excluding `respond_no_solution`: **21,451 train / 4,201
validation** queries. The train count differs from the paper by two; the denominator is disclosed rather than
adjusted. `respond_no_solution` is not treated as an unanswerable label. Every eligible target here has references,
so natural-unanswerable accuracy is **N/A**. Target references map to deduplicated passage IDs; the mapper supports
multiple spans, passages, documents and domains even though each eligible target in this pin maps to one passage.

Retrieval inputs contain the current user turn and at most four previous individual turns, newest first, using
`user:`/`agent:` labels separated by ` [SEP] `. The oldest history is dropped first above 1,024 local cl100k tokens;
an overlong current utterance fails rather than being silently shortened. Generation history contains the same
retained turns chronologically. A last-user-turn-only variant is also materialized. Target replies, acts and qrels
are stored separately from model inputs. The tokenizer is the existing offline, hash-pinned cl100k vocabulary with
tiktoken 0.14.0; its complete identity is in the manifest. These counts are not provider request or billing counts.

The official validation split serves as sealed test because the official test file is a dummy. Dialogue ranking
uses SHA-256 of `g0/v1|20261114|{domain}|{dial_id}`. Dev takes the first 80 train dialogues (500 queries); G8 starts
with the remaining 3,394 (20,951 queries). Retrieval takes the first 300 validation dialogues (1,940 queries).
Within retrieval, prefix `g0/answers/v1` selects 200 dialogues (1,302 queries); within answers, `g0/full/v1` selects
six (42 queries). Each ranking breaks ties by domain/ID. The answer set has 1,038 responding turns (the three
`respond_solution` variants) and 264 clarification turns (`query_condition`). Cohorts and their four design hashes
reproduce the accepted design without using model outcomes.

Exact UTF-8 query-hash audits compare dev, the G8 pool and **all** validation queries. G8 training excludes 1,713
query IDs sharing either a rendered retrieval input or last-user-turn input with another partition, leaving
**19,238 eligible training queries**. This does not change frozen cohort membership. The manifest records the
exclusion count and sorted query-ID hash, plus cross-partition group counts and hashes (37 retrieval-input
groups, 196 last-turn groups). Passage overlap
is audited by body and heading-plus-body hash (872 and 911 groups respectively); shared source passages are
intentional corpus reuse and alone do not exclude training queries. These exact-match checks do not detect all
semantic overlap, and public benchmark/model-training contamination cannot be excluded. Human grounding qrels
may omit other valid evidence, and human replies are not exact-match answer-correctness labels.

An independent coordinator probe of 200 random queries found every gold span inside a qrel passage body
(zero misses). Three target replies also occurred in the inputs because the human agent had said the same text
earlier in the dialogue. This natural repetition is a data property, not pipeline target leakage; the probe
does not establish exhaustive corpus coverage.

The compact public manifest binds full derivations with SHA-256: the complete passage identity/span/content-hash
list (canonical JSON sorted by passage ID), all qrels (canonical JSONL sorted by query ID, each with sorted
passage IDs), sorted query-ID lists for every cohort, and the sorted G8 exclusion list. Canonical JSON uses
sorted keys, ASCII escaping and compact separators. JSONL and ID lists include a trailing LF; canonical JSON
lists do not. Exact private `passages.jsonl`, `queries.jsonl` and `references.jsonl` byte hashes are also pinned.
The four registerable cohorts (`dev`, `retrieval`, `answers`, `full_context`) publish their sorted `query_ids`
alongside `query_ids_sha256`; both the dataset verifier and QA contract check their agreement. The G8 pool
remains hash-only. Dialogue IDs are also listed for the four registerable cohorts.
Downstream consumers read per-query qrels from private `references.jsonl` and verify its manifest-bound hash.
The committed manifest uses compact JSON with a trailing LF, targets at most 300 KB and must stay below 1 MB.

To materialize privately, run through the configured development environment:

```text
python -B scripts/devenv.py uv --project evals run --offline --frozen -- python -B -m policyops_evals.datasets.multidoc2dial build --archive <private-archive.zip> --out <new-directory-under-POLICYOPS_TEMP_DIR>
```

The command verifies the complete derivation against the committed manifest before writing `passages.jsonl`,
`queries.jsonl`, `references.jsonl` and a private manifest copy. Output must be a new directory below the absolute
`POLICYOPS_TEMP_DIR` and outside the repository; existing output is never overwritten. Set
`POLICYOPS_MD2D_ARCHIVE` to the private archive path to enable the real-archive test, which rebuilds and compares
every field, count and hash of the manifest. Default synthetic tests require no dataset download or provider calls.
