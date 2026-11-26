# Local Zammad integration

The opt-in Compose overlay connects a disposable Zammad instance to the fictional retail demo. PolicyOps imports
customer articles into a workspace case and posts a fixed internal note after the retail simulator commits an
approved action. The browser shows imported messages as **Help desk ticket**. Operators inspect delivery status
through the database and worker logs. This connector is disabled in the deployment profile.

## Field mapping

| Source | Fields | Use |
|---|---|---|
| Secret file | `connection_id`, `workspace_id`, `signing_secret`, `api_token`, `api_origin`, `allowed_group_ids`, `integration_user_id`, `writeback_enabled`, optional `max_event_age_seconds` | Select the tenant before database access and constrain reads and note authority. Give each installation a distinct ID and signing secret. Use a new connection ID when replacing the installation. |
| Wake-up | Raw body with `ticket_id` and UTC `updated_at`, `X-Hub-Signature: sha1=<hex>`, optional `X-Zammad-Delivery` | Verify the HMAC before parsing. Deduplicate by workspace, connection and SHA-256 of the exact body. The unsigned delivery ID is diagnostic. |
| Ticket read | `id`, `group_id`, `customer_id`, `state_id`, `updated_at` | Require an allowed group and a server-seeded binding for the requester ID. Retain group and state on the link and order snapshots by `(updated_at, max article ID)`. |
| Articles read | `id`, `ticket_id`, `internal`, `sender`, `created_by_id`, `content_type`, `body`, `created_at` | Import public customer plain text. Use a deterministic placeholder for HTML or invalid/oversized plain text. Ignore internal and integration-authored articles. |
| Note create | `ticket_id`, `internal: true`, `type: note`, `content_type: text/plain`, fixed subject and body | Create a status notification. The versioned body contains a fixed sentence and an operation ID. |
| Receipt | Matching article `id` and `created_at` | Record a real returned article. A match requires the exact ticket, internal flag, integration author, operation marker and body digest. Record all matching IDs when duplicates are observed. |

Articles and ticket metadata come from the fixed API origin. The worker rereads ticket fields around the article
scan to reject an observed change. All network calls run outside the workspace transaction. Within the transaction
the lock order is inbox, ticket link, case. An older snapshot cannot regress the stored mark. The connector leaves
the PolicyOps case status to the current case workflow. Bindings come from fictional fixture IDs and establish an
association only. The simulator's in-run authentication, operator consent and distinct reviewer approval still
apply. Imported text, including “yes”, is excluded from consent by the service and the database.

The outcome projection enqueues the note with its local message in one transaction. The worker looks up a matching
article before sending, checks that the ticket remains in an allowed group with the same requester, then commits
a dispatch checkpoint before POST. A connection failure proven to precede request bytes permits a retry under
the same operation ID. Possible dispatch permits lookup only, including when a worker dies after the checkpoint.
That can leave an `unconfirmed` outcome if the remote commit remains unobservable. The retail result stands
regardless of notification state.

## Fault matrix

| Condition | Expected observation |
|---|---|
| Unknown connection, wrong/repeated signature or modified body | 404 or 401 and zero new inbox rows |
| Signed ticket timestamp outside the allowed age or more than five minutes ahead | 400 and zero new inbox rows |
| Same raw body with a different delivery ID, including concurrent deliveries | 202 on both requests and one inbox row |
| Different wake-ups for an older or already applied snapshot | `stale`, with the case and watermark unchanged |
| Disallowed group, unknown or changed requester | `rejected_mapping`, typed reason and system audit, with no new case |
| More than 256 KiB per response, more than 200 articles or an invalid scan | `incomplete_scan`, with no partial projection. A verified redelivery of the same body can revive the row up to three times |
| Webhook echo of the connector's internal note | No imported message |
| Inbound GET outage | Pending with bounded backoff, then `failed` if the attempt budget runs out. A verified redelivery of the same body resets the attempt budget up to three times. Applied events and typed remote rejections stay terminal |
| Write-back GET outage or POST connect failure | Pending with bounded backoff, then one note if the service recovers within budget |
| Unexpected worker step error | The worker continues. The affected inbound event or pending write-back is marked `failed` with `internal_error`. A dispatching write-back is marked `unconfirmed` with zero resends. If recording fails, the lease expires normally |
| POST commits and the response is lost | Lookup-only recovery records the existing article, with zero resends |
| Possibly sent and bounded lookups miss | `unconfirmed`, with zero resends |
| Spoofed operation marker or a duplicate match | Customer-authored article cannot match. Multiple genuine matches retain every matching ID. |
| 401, 403, 404 or 422 from Zammad | Typed terminal failure |
| Delivery deadline | Failed before possible dispatch or unconfirmed afterward |

The inbound cap is 64 KiB. The default signed ticket age is 24 hours. Ticket time is not a signed send time, and
the age and dedupe checks do not establish replay protection. Scans use 3-second HTTP phase timeouts, a response
read budget and identity encoding. The inbox allows eight claims. The write-back window is 15 minutes with up to
twelve pending claims and three reconciliation lookups, spaced at least eight seconds after a possible send.
The connector requires the server's by-ticket result to include the whole article list. Over-cap or malformed
scans fail closed. The service does not fetch attachments, extract HTML, change Zammad ticket state, post public
replies or post refusals. The demo does not establish production integration, requester identity, throughput,
exactly-once remote delivery, or wire equivalence beyond confirmed captures.

## Historical ticket import

Use a **disposable workspace**. Each newly accepted ticket opens a case. The Compose CLI requires
`POLICYOPS_ENV=local`, `POLICYOPS_HELPDESK=1`, and a configured connection with `writeback_enabled=false`.
The connection selects the workspace and installation. Seed requester bindings on the server before importing.
The CLI uses the verified app runtime role and makes zero HTTP requests. Signed webhooks continue to provide
incremental sync for the same connection.

### Export format v1

Use strict UTF-8 with the exact header below. Each physical line contains one complete cumulative snapshot
from the same Zammad installation and ID space. Use LF or CRLF. Encode line breaks inside article bodies as
JSON escapes and quote the array as a CSV field. Ticket and group IDs, requester IDs, and state IDs are positive
integers up to 2⁵³ − 1. Use UTC timestamps with `Z` or `+00:00` and up to six fractional digits. The array uses the
article fields in the [field mapping](#field-mapping). An empty snapshot uses `[]`.

```csv
policyops_helpdesk_v1_ticket_id,group_id,customer_id,state_id,updated_at,articles_json
42,7,11,2,2026-10-31T00:00:00Z,"[{""id"":1,""ticket_id"":42,""internal"":false,""sender"":""Customer"",""created_by_id"":11,""content_type"":""text/plain"",""body"":""yes"",""created_at"":""2026-10-30T00:00:00Z""}]"
```

The file limit is 64 MiB and 50,000 records. The encoded record limit is 1 MiB, including its line ending. The
decoded articles field admits up to 200 articles and 256 KiB of JSON. Header, encoding, or file limit failures
refuse the archive. A malformed or over-limit record receives a redacted rejection. Batches parse outside SQL
transactions and normally hold up to 16 records or 2 MiB of encoded input. An oversized line beyond the batch
budget is accounted for individually using its digest.

### Plan, import, and report

Use the disposable Compose setup described below, with a dedicated write-back-disabled connection. Place the
export in the worker's private temporary directory. These commands assume its path is `/tmp/tickets.csv`.
Set the actual export timestamp and preserve the digest returned by `plan`.

```powershell
$compose = @('-f','compose.yaml','-f','infra/compose/helpdesk.yaml')
$importer = @('exec','-T','worker','python','-B','infra/compose/helpdesk_import.py')
$connection = 'zammad-history'
$exportedAt = '2026-11-01T00:00:00Z'
$plan = docker compose @compose @importer plan --connection $connection --file /tmp/tickets.csv --exported-at $exportedAt
if ($LASTEXITCODE -ne 0) { throw 'Plan failed' }
$sha = ($plan | ConvertFrom-Json).file_sha256
docker compose @compose @importer run --connection $connection --file /tmp/tickets.csv --exported-at $exportedAt --sha256 $sha
docker compose @compose @importer report --connection $connection --sha256 $sha
```

`plan` validates the input and counts structurally valid and rejected rows without writing. The export timestamp
must be within five minutes of database time or earlier. Records with `updated_at` later than the export timestamp
are rejected. The operator is responsible for accurate file timestamps and source ordering. An incorrect timestamp
in the past can appear valid.

`run` verifies the file digest before writing. Resume with the same bytes, export timestamp, connection and digest.
The destination and allowed-group mapping are pinned for the run. Keep requester bindings stable. A different digest
requires a new plan and starts a separate run. A session advisory lock serializes importers per workspace and
connection. Each batch commits case changes, ledger rows and the versioned cursor together. The first commit also
creates the run and its one audit event. An uncertain commit triggers a fresh read of the durable cursor. A
completed rerun returns the existing report. Report rows contain the record ordinal, ticket ID when identified,
disposition and typed reason. Remove the worker's temporary archive after the run or retain the original privately
for resumption.

### Ordering and reconciliation

Both callers project under the same ticket lock, including first creation. The watermark is UTC ticket
`updated_at` followed by the maximum article ID, including ignored articles and using zero for an empty list.
The import ledger records `skipped_stale` for a lower mark and `duplicate` for an equal mark with the same projected
fields and customer messages. An import with divergent projected content at an equal mark is quarantined as
`snapshot_conflict`. A higher import mark that drops or changes a projected message is quarantined as
`incompatible_history`. The webhook inbox retains its N11 states and lease semantics. The audit and typed
quarantines for historical rows live in the import run and ledger.

Compatible import and webhook snapshots converge on the greatest delivered watermark when the snapshots are
complete and cumulative, article identities and contents are immutable, bindings stay stable, and equal marks
agree. The projected link fields and customer-message identities and digests are comparable across delivery
orders. Case IDs, ingestion timestamps, sequence numbers and case versions are local operational fields.
Imported text stays in `helpdesk_ticket` messages, including the literal “yes”, and is excluded from consent.
The importer leaves the case workflow status to PolicyOps.

### Fixture and acceptance

The PostgreSQL tests run the importer as the app runtime role. The oracle test generates the CSV and an
independent expected projection at test time using the hash-verified τ² retail `db.json` from the frozen evaluator
installation. The generator writes to a private output directory, and its separate server-side bindings are seeded
before import. See [data provenance](data-provenance.md#rights-and-provenance-audit).

```powershell
python -B scripts/devenv.py uv sync --project evals --frozen
python -B scripts/devenv.py uv run --frozen pytest -m postgres tests/integration/test_helpdesk_import.py
```

For a workstation measurement, set `POLICYOPS_N14_WORKSTATION_HARDWARE` to the workstation CPU, memory and local
PostgreSQL setup and run the same command with `-k pinned_retail_fixture -s`. This selects the full eligible retail
fixture and prints the hardware, fixture size and SHA-256, batch limits, committed row count and elapsed time. The
result describes that workstation run.

## Offline checks

Use the frozen development environment and an external temporary root as in the project setup.

```powershell
python -B scripts/devenv.py uv run --frozen pytest tests/unit/test_helpdesk.py
# Coordinator only. Requires the pinned owned PostgreSQL QA container and the frozen evaluator environment.
python -B scripts/devenv.py uv sync --project evals --frozen
python -B scripts/devenv.py uv run --frozen pytest -m postgres tests/integration/test_helpdesk_contract.py tests/integration/test_app_privileges.py --tb=short
```

The PostgreSQL test uses the real runtime roles and simulator with `httpx.MockTransport` for Zammad. The
proposal is scripted. No model is called. The fake ticket and article fields and the rendered webhook body
follow sanitized captures from one disposable local Zammad instance on 2026-11-25
(`zammad-docker-compose` `v17.5.10`, image `ghcr.io/zammad/zammad:7.2.3-0019`). Fixture values are fictional.
The REST timestamps include milliseconds. The rendered webhook carries an integer `ticket_id` and a UTC
`updated_at` with whole seconds.
[Tickets API](https://docs.zammad.org/en/latest/api/ticket/index.html) · [Articles API](https://docs.zammad.org/en/latest/api/ticket/articles.html) · [Webhook payload](https://admin-docs.zammad.org/en/latest/manage/webhook/payload.html)

## Coordinator smoke on disposable stacks

1. Use an unmodified checkout of upstream `zammad-docker-compose` tag `v17.5.10` and record the image digests.
   The 2026-11-25 smoke used this tag and `ghcr.io/zammad/zammad:7.2.3-0019` on one local instance. Allocate
   at least 4 GB of memory to this stack. Connect nginx, the scheduler and the Rails API server to the
   disposable bridge. The scheduler sends webhooks, and the API server resolves the endpoint when saving
   it. Zammad 7.2 permits private addresses for webhook endpoints, so this bridge needs no allowlist.
   [Upstream tagged releases](https://github.com/zammad/zammad-docker-compose/releases) · [Compose setup](https://docs.zammad.org/en/latest/install/docker-compose.html)

   ```powershell
   # Set $upstream and $zammadProject to the disposable checkout and its project name.
   $zammadComposeTag = 'v17.5.10'
   $actualTag = git -C $upstream describe --tags --exact-match HEAD
   if ($LASTEXITCODE -ne 0 -or $actualTag -ne $zammadComposeTag) { throw 'Unexpected upstream tag' }
   $env:VERSION = '7.2.3-0019'
   $env:NGINX_EXPOSE_PORT = '127.0.0.1:8081'
   $env:ELASTICSEARCH_ENABLED = 'false'
   $env:RESTART = 'no'
   $zammadCompose = @('-p',$zammadProject,'--project-directory',$upstream,
     '-f',"$upstream/docker-compose.yml",'-f',"$upstream/scenarios/disable-elasticsearch-service.yml",
     '-f',"$upstream/scenarios/disable-backup-service.yml")
   docker compose @zammadCompose up -d
   $zammadWeb = docker compose @zammadCompose ps -q zammad-nginx
   $zammadSender = docker compose @zammadCompose ps -q zammad-scheduler
   $zammadApi = docker compose @zammadCompose ps -q zammad-railsserver
   # Set POLICYOPS_ZAMMAD_NETWORK to a unique bridge name for this run.
   docker network create --internal $env:POLICYOPS_ZAMMAD_NETWORK
   docker network connect --alias zammad-nginx $env:POLICYOPS_ZAMMAD_NETWORK $zammadWeb
   docker network connect $env:POLICYOPS_ZAMMAD_NETWORK $zammadSender
   docker network connect $env:POLICYOPS_ZAMMAD_NETWORK $zammadApi
   ```

2. Set up Zammad's administrator and API token through the local UI or use the Rails runner below on a fresh,
   healthy instance. Keep the admin token on the host. Provisioning expects fresh objects and returns the
   allowed and disallowed group IDs, integration user ID and fictional requester ID. Give the integration user
   its own API token in the UI or with the second Rails runner snippet.
   [REST authentication](https://docs.zammad.org/en/latest/api/intro.html) · [Groups API](https://docs.zammad.org/en/latest/api/group.html) · [Users API](https://docs.zammad.org/en/latest/api/user.html) · [Roles API](https://docs.zammad.org/en/latest/api/role.html)

   Rails logs go to stdout and can contain sensitive values. Capture only the marked token line, write the
   value to a private external file, and keep command output and the token value out of transcripts and logs.

   ```powershell
   # Set $adminTokenFile and $integrationTokenFile inside the private external run directory.
   function Save-ZammadSmokeToken($ruby, $destination) {
     $tokenLine = @($ruby | docker compose @zammadCompose exec -T zammad-railsserver bundle exec rails r - 2>$null |
       Where-Object { $_ -cmatch '^POLICYOPS_SMOKE_MARKER=[A-Za-z0-9_-]{24,256}$' })
     if ($LASTEXITCODE -ne 0 -or $tokenLine.Count -ne 1) { throw 'Zammad token creation failed' }
     [IO.File]::WriteAllText($destination, $tokenLine[0].Substring('POLICYOPS_SMOKE_MARKER='.Length))
   }

   $adminRuby = @'
   Setting.set('system_init_done', true)
   login = 'policyops-smoke-admin'
   user = User.find_by(login: login) || User.create!(login: login, firstname: 'Smoke', lastname: 'Admin',
     email: 'policyops-smoke-admin@example.invalid', password: SecureRandom.hex(24), active: true,
     created_by_id: 1, updated_by_id: 1)
   user.roles = Role.where(name: ['Admin', 'Agent'])
   token = Token.create!(action: 'api', persistent: true, user_id: user.id, name: 'PolicyOps smoke admin',
     preferences: { permission: ['admin', 'ticket.agent'] })
   puts "POLICYOPS_SMOKE_MARKER=#{token.token}"
   '@
   Save-ZammadSmokeToken $adminRuby $adminTokenFile
   ```

   ```powershell
   $zammadOrigin = 'http://127.0.0.1:8081'
   $provisioned = python -B scripts/devenv.py uv run --frozen python -B infra/compose/helpdesk_seed.py provision --admin-origin $zammadOrigin --admin-token-file $adminTokenFile
   if ($LASTEXITCODE -ne 0) { throw 'Zammad provisioning failed' }
   $fixture = $provisioned | ConvertFrom-Json
   $requesterId = $fixture.requester_id

   # Optional token creation for the provisioned integration user.
   $integrationRuby = @'
   user = User.find_by!(login: 'policyops-n11')
   token = Token.create!(action: 'api', persistent: true, user_id: user.id, name: 'PolicyOps smoke integration',
     preferences: { permission: ['ticket.agent'] })
   puts "POLICYOPS_SMOKE_MARKER=#{token.token}"
   '@
   Save-ZammadSmokeToken $integrationRuby $integrationTokenFile
   ```

3. Follow [local Compose operations](operations.md#start-and-stop) using a fresh PolicyOps project and external
   secret directory. Create the mounted JSON file `$env:POLICYOPS_SECRETS_DIR/helpdesk` with the following shape.
   Use a generated signing secret and the integration user's token, the demo workspace ID, and the numeric IDs
   from `provision`. Populate `allowed_group_ids` with `$fixture.group_id` and `integration_user_id` with
   `$fixture.integration_user_id`. Use the web service's internal port in `api_origin`.

   For the historical import check in step 6, add a second entry to `connections` before starting PolicyOps.
   Copy the workspace, allowed group, API origin, integration user and API token from the first entry. Set
   `connection_id` to `zammad-history`, generate a distinct `signing_secret`, and set `writeback_enabled` to
   `false`. This connection starts with no linked tickets or inbound webhook events.

   ```json
   {"connections":[{"connection_id":"zammad-n11","workspace_id":"00000000-0000-0000-0000-000000003801",
   "signing_secret":"<generated signing secret>","api_token":"<integration user token>",
   "api_origin":"http://zammad-nginx:8080","allowed_group_ids":[1],"integration_user_id":1,
   "writeback_enabled":true}]}
   ```

   ```powershell
   $compose = @('-p',$env:COMPOSE_PROJECT_NAME,'-f','compose.yaml','-f','infra/compose/helpdesk.yaml')
   $connection = 'zammad-n11'
   $settingsFile = Join-Path $env:POLICYOPS_SECRETS_DIR 'helpdesk'
   docker compose @compose up -d --build --wait
   docker compose @compose exec -T worker python -B infra/compose/helpdesk_seed.py bind --connection $connection --requester-id $requesterId
   python -B scripts/devenv.py uv run --frozen python -B infra/compose/helpdesk_seed.py wire --admin-origin $zammadOrigin --admin-token-file $adminTokenFile --settings-file $settingsFile --connection $connection --receiver-port $env:POLICYOPS_HTTP_PORT --disallowed-group-id $fixture.disallowed_group_id
   if ($LASTEXITCODE -ne 0) { throw 'Zammad wiring failed' }
   ```

   The first smoke verified this REST configuration with manual wiring. The webhook uses
   `customized_payload: true` and `custom_payload` with the JSON template
   `{"ticket_id":"#{ticket.id}","updated_at":"#{ticket.updated_at.iso8601}"}`. Zammad parses the template
   before interpolation, emits `ticket_id` as an integer, and renders the timestamp as RFC 3339 UTC.
   The trigger uses `activator: "action"`, `execution_condition_mode: "always"` and
   `{"ticket.group_id":{"operator":"is","value":["<allowed group ID>","<disallowed group ID>"]}}` as
   `condition`. The seed reads allowed IDs from the connection and appends the provisioned
   `--disallowed-group-id` so both fixture groups emit deliveries. Keep only the allowed group in the
   connection's allowlist. Confirm the integration user can read both groups and write only in the allowed
   group. If the management interface differs on another release, configure the same endpoint, signing
   secret, template and trigger in the admin UI.
   [Webhook settings](https://admin-docs.zammad.org/en/latest/manage/webhook.html) · [Triggers](https://admin-docs.zammad.org/en/latest/manage/trigger.html)

4. Create a ticket with one public plain-text article as the fictional requester in the allowed group. Wait for
   the real trigger to land as `applied`. Set the numeric ticket ID in `$ticketId`. Save the raw accepted
   minimal body and sanitized database snapshot. Keep all smoke data under the external run root.

   ```powershell
   $env:POLICYOPS_HELPDESK_SMOKE = '1'
   $env:POLICYOPS_HELPDESK_SMOKE_SETTINGS = $settingsFile
   $env:POLICYOPS_HELPDESK_SMOKE_CONNECTION = $connection
   $env:POLICYOPS_HELPDESK_SMOKE_POLICYOPS_ORIGIN = "http://127.0.0.1:$env:POLICYOPS_HTTP_PORT"
   $env:POLICYOPS_HELPDESK_SMOKE_ZAMMAD_ORIGIN = $zammadOrigin
   $env:POLICYOPS_HELPDESK_SMOKE_CAPTURE = "$env:POLICYOPS_TEMP_DIR/zammad-trigger.json"
   $env:POLICYOPS_HELPDESK_SMOKE_BEFORE = "$env:POLICYOPS_TEMP_DIR/zammad-before.json"
   $env:POLICYOPS_HELPDESK_SMOKE_AFTER_REPLAY = "$env:POLICYOPS_TEMP_DIR/zammad-after-replay.json"
   $env:POLICYOPS_HELPDESK_SMOKE_REJECTED = "$env:POLICYOPS_TEMP_DIR/zammad-rejected.json"
   $env:POLICYOPS_HELPDESK_SMOKE_OUTAGE = "$env:POLICYOPS_TEMP_DIR/zammad-outage.json"
   $env:POLICYOPS_HELPDESK_SMOKE_AFTER_OUTCOME = "$env:POLICYOPS_TEMP_DIR/zammad-outcome.json"
   $invoke = @('exec','-T','worker','python','-B','infra/compose/helpdesk_seed.py')
   docker compose @compose @invoke capture --connection $connection --ticket-id $ticketId | Set-Content -Encoding UTF8 $env:POLICYOPS_HELPDESK_SMOKE_CAPTURE
   docker compose @compose @invoke inspect --connection $connection --ticket-id $ticketId | Set-Content -Encoding UTF8 $env:POLICYOPS_HELPDESK_SMOKE_BEFORE
   python -B scripts/devenv.py uv run --frozen pytest -m helpdesk tests/integration/test_helpdesk_smoke.py -k real_trigger_replay
   docker compose @compose @invoke inspect --connection $connection --ticket-id $ticketId | Set-Content -Encoding UTF8 $env:POLICYOPS_HELPDESK_SMOKE_AFTER_REPLAY
   ```

5. Create a second ticket for the same requester in the disallowed group. Wait for `rejected_mapping` and save its
   inspection using the second ticket ID. Prepare the scripted proposal on the imported allowed case. Use Alice
   in the browser to enter the customer's simulation consent. Stop the upstream Zammad web service before Bob
   approves. Verify the retail simulator committed and the connector tried and left the notification pending.
   Save that inspection before restarting the upstream web service. Wait for `succeeded`.

   ```powershell
   docker compose @compose @invoke inspect --connection $connection --ticket-id $disallowedTicketId | Set-Content -Encoding UTF8 $env:POLICYOPS_HELPDESK_SMOKE_REJECTED
   $caseId = (Get-Content -Raw $env:POLICYOPS_HELPDESK_SMOKE_BEFORE | ConvertFrom-Json).case_id
   docker compose @compose @invoke prepare --case-id $caseId
   docker compose @zammadCompose stop zammad-nginx
   # After approval and a stopped-service attempt
   docker compose @compose @invoke inspect --connection $connection --ticket-id $ticketId | Set-Content -Encoding UTF8 $env:POLICYOPS_HELPDESK_SMOKE_OUTAGE
   docker compose @zammadCompose start zammad-nginx
   # After Zammad is available and the notification is succeeded
   docker compose @compose @invoke inspect --connection $connection --ticket-id $ticketId | Set-Content -Encoding UTF8 $env:POLICYOPS_HELPDESK_SMOKE_AFTER_OUTCOME
   docker compose @compose exec -T worker python -B infra/compose/scenario.py inspect --case-id $caseId
   python -B scripts/devenv.py uv run --frozen pytest -m helpdesk tests/integration/test_helpdesk_smoke.py -k 'not real_trigger_replay'
   ```

6. Run the historical import check after the allowed ticket and its internal outcome note are settled.
   This check is pending the coordinator rerun. Fetch the real ticket and its complete article list
   for `$ticketId`, encode a single v1 CSV row, and stream the unchanged bytes to the worker's private
   tmpfs. Use the separate `zammad-history` connection configured in step 3.

   ```powershell
   $historyConnection = 'zammad-history'
   $archive = Join-Path $env:POLICYOPS_TEMP_DIR 'zammad-history.csv'
   $exportScript = @'
   import csv
   from datetime import UTC, datetime
   import json
   from pathlib import Path
   import sys
   from urllib.request import ProxyHandler, Request, build_opener

   origin, ticket_id, token_file, destination = sys.argv[1:]
   headers = {"Authorization": "Token token=" + Path(token_file).read_text(encoding="ascii").strip()}
   opener = build_opener(ProxyHandler({}))

   def get(resource):
       with opener.open(Request(f"{origin}/api/v1/{resource}", headers=headers), timeout=5) as response:
           return json.load(response)

   ticket = get(f"tickets/{int(ticket_id)}")
   articles = get(f"ticket_articles/by_ticket/{int(ticket_id)}")
   article_fields = ("id", "ticket_id", "internal", "sender", "created_by_id", "content_type", "body", "created_at")
   snapshot = [{name: article[name] for name in article_fields} for article in articles]
   with Path(destination).open("w", newline="", encoding="utf-8") as export:
       writer = csv.writer(export, lineterminator="\n")
       writer.writerow(["policyops_helpdesk_v1_ticket_id", "group_id", "customer_id", "state_id", "updated_at", "articles_json"])
       writer.writerow([ticket[name] for name in ("id", "group_id", "customer_id", "state_id", "updated_at")]
                       + [json.dumps(snapshot, ensure_ascii=False)])
   print(datetime.now(UTC).isoformat().replace("+00:00", "Z"))
   '@
   $exportedAt = $exportScript | python -B - $zammadOrigin $ticketId $adminTokenFile $archive
   if ($LASTEXITCODE -ne 0) { throw 'Zammad CSV export failed' }
   [Convert]::ToBase64String([IO.File]::ReadAllBytes($archive)) |
     docker compose @compose exec -T worker python -B -c 'import base64, sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(base64.b64decode(sys.stdin.buffer.read().strip(), validate=True))' /tmp/zammad-history.csv |
     Out-Null
   if ($LASTEXITCODE -ne 0) { throw 'Worker archive transfer failed' }

   docker compose @compose @invoke bind --connection $historyConnection --requester-id $requesterId
   if ($LASTEXITCODE -ne 0) { throw 'Historical requester binding failed' }
   $importer = @('exec','-T','worker','python','-B','infra/compose/helpdesk_import.py')
   $plan = docker compose @compose @importer plan --connection $historyConnection --file /tmp/zammad-history.csv --exported-at $exportedAt
   if ($LASTEXITCODE -ne 0) { throw 'Historical import plan failed' }
   $planned = $plan | ConvertFrom-Json
   if ($planned.records_total -ne 1 -or $planned.valid -ne 1) { throw 'Expected one valid historical snapshot' }
   $sha = $planned.file_sha256
   docker compose @compose @importer run --connection $historyConnection --file /tmp/zammad-history.csv --exported-at $exportedAt --sha256 $sha
   if ($LASTEXITCODE -ne 0) { throw 'Historical import run failed' }
   docker compose @compose @importer report --connection $historyConnection --sha256 $sha
   if ($LASTEXITCODE -ne 0) { throw 'Historical import report failed' }
   docker compose @compose @invoke inspect --connection $historyConnection --ticket-id $ticketId
   if ($LASTEXITCODE -ne 0) { throw 'Historical import inspection failed' }
   ```

   Expect the report to show `completed`, one `accepted` row with reason `case_created`, and no quarantines or
   rejections. Expect the inspection to show a case with one imported customer message, zero webhook events
   and zero write-backs. Retain a sanitized report and inspection under the external run root.

7. Check the upstream request header names and timestamp interpolation and compare the sanitized ticket and
   article response fields to the fake. Strip tokens, signatures and unrelated fields before retaining captures.
   Keep a mismatch as a repair item with a minimal sanitized response. Tear down the two disposable projects
   using their explicit project names and remove their dedicated bridge and external secrets after the containers
   stop. Follow [local cleanup](operations.md#start-and-stop) for PolicyOps.
