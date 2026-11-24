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

## Offline checks

Use the frozen development environment and an external temporary root as in the project setup.

```powershell
python -B scripts/devenv.py uv run --frozen pytest tests/unit/test_helpdesk.py
# Coordinator only. Requires the pinned owned PostgreSQL QA container and the frozen evaluator environment.
python -B scripts/devenv.py uv sync --project evals --frozen
python -B scripts/devenv.py uv run --frozen pytest -m postgres tests/integration/test_helpdesk_contract.py tests/integration/test_app_privileges.py --tb=short
```

The PostgreSQL test uses the real runtime roles and simulator with `httpx.MockTransport` for Zammad. The
proposal is scripted. No model is called. The fake's ticket fixture follows the Tickets API and its articles
fixture follows the Ticket Articles API. The wake-up fixture is an independently authored minimal template
based on the webhook documentation. These fixtures precede confirmation against the real service.
[Tickets API](https://docs.zammad.org/en/latest/api/ticket/index.html) · [Articles API](https://docs.zammad.org/en/latest/api/ticket/articles.html) · [Webhook payload](https://admin-docs.zammad.org/en/latest/manage/webhook/payload.html)

## Coordinator smoke on disposable stacks

1. Select and record an upstream `zammad-docker-compose` release tag and image digests. Use an unmodified checkout
   of that tag, the upstream scenario for disabling Elasticsearch, and a host loopback-only web port. Set
   `ELASTICSEARCH_ENABLED=false`. Allocate at least 4 GB of memory to this stack. Create a disposable bridge for
   the web service and the Zammad process that sends webhooks. Give the web service alias `zammad-nginx` and set
   `POLICYOPS_ZAMMAD_NETWORK` to the bridge name. Confirm which upstream service sends webhooks for the pinned
   release. Configure a private-address allowlist for the local receiver if the release requires one.
   [Upstream tagged releases](https://github.com/zammad/zammad-docker-compose/releases) · [Compose setup](https://docs.zammad.org/en/latest/install/docker-compose.html)

   ```powershell
   # Set $upstream, $zammadComposeTag and $zammadProject to the disposable checkout, reviewed tag and project.
   git -C $upstream describe --tags --exact-match HEAD
   $env:ELASTICSEARCH_ENABLED = 'false'
   $zammadCompose = @('-p',$zammadProject,'--project-directory',$upstream,
     '-f',"$upstream/docker-compose.yml",'-f',"$upstream/scenarios/disable-elasticsearch-service.yml")
   docker compose @zammadCompose up -d
   $zammadWeb = docker compose @zammadCompose ps -q zammad-nginx
   $zammadSender = docker compose @zammadCompose ps -q zammad-scheduler
   docker network create --internal $env:POLICYOPS_ZAMMAD_NETWORK
   docker network connect --alias zammad-nginx $env:POLICYOPS_ZAMMAD_NETWORK $zammadWeb
   docker network connect $env:POLICYOPS_ZAMMAD_NETWORK $zammadSender
   ```

   Compare the reported tag to `$zammadComposeTag` before startup. Edit only external local environment or
   invocation settings when setting the loopback port and administrative access.
2. Set up Zammad's administrator and store a temporary admin API token in an external file. Run provisioning
   to obtain the group, integration user and fictional requester IDs. Use the local UI to give the integration
   user its own API token. Keep the admin token on the host. Provisioning expects fresh objects.
   [REST authentication](https://docs.zammad.org/en/latest/api/intro.html) · [Groups API](https://docs.zammad.org/en/latest/api/group.html) · [Users API](https://docs.zammad.org/en/latest/api/user.html) · [Roles API](https://docs.zammad.org/en/latest/api/role.html)

   ```powershell
   $zammadOrigin = 'http://127.0.0.1:8081'
   python -B scripts/devenv.py uv run --frozen python -B infra/compose/helpdesk_seed.py provision --admin-origin $zammadOrigin --admin-token-file $adminTokenFile
   ```

3. Follow [local Compose operations](operations.md#start-and-stop) using a fresh PolicyOps project and external
   secret directory. Create the mounted JSON file `$env:POLICYOPS_SECRETS_DIR/helpdesk` with the following shape.
   Use a generated signing secret and the integration user's token, the demo workspace ID, and the numeric IDs
   printed by provisioning. Use the web service's internal port in `api_origin`.

   ```json
   {"connections":[{"connection_id":"zammad-n11","workspace_id":"00000000-0000-0000-0000-000000003801",
   "signing_secret":"<generated signing secret>","api_token":"<integration user token>",
   "api_origin":"http://zammad-nginx:8080","allowed_group_ids":[1],"integration_user_id":1,
   "writeback_enabled":true}]}
   ```

   ```powershell
   $compose = @('-f','compose.yaml','-f','infra/compose/helpdesk.yaml')
   $connection = 'zammad-n11'
   $settingsFile = Join-Path $env:POLICYOPS_SECRETS_DIR 'helpdesk'
   docker compose @compose up -d --build
   docker compose @compose exec -T worker python -B infra/compose/helpdesk_seed.py bind --connection $connection --requester-id $requesterId
   python -B scripts/devenv.py uv run --frozen python -B infra/compose/helpdesk_seed.py wire --admin-origin $zammadOrigin --admin-token-file $adminTokenFile --settings-file $settingsFile --connection $connection --receiver-port $env:POLICYOPS_HTTP_PORT
   ```

   The management REST JSON and trigger interpolation need verification on the selected release. If its
   management interface differs, configure the webhook and trigger in the Zammad admin UI using the same URL,
   signing secret and payload. The template is `{"ticket_id":#{ticket.id},"updated_at":"#{ticket.updated_at}"}`.
   Configure a ticket-create/update trigger that can fire for both fixture groups. The trigger's result must have
   exactly the two fields and a UTC RFC3339 timestamp. Confirm the integration user can read both fixture groups
   and write only in the allowed group.
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

6. Check the upstream request header names and timestamp interpolation and compare the sanitized ticket and
   article response fields to the fake. Strip tokens, signatures and unrelated fields before retaining captures.
   Keep a mismatch as a repair item with a minimal sanitized response. Tear down the two disposable projects
   using their explicit project names and remove their dedicated bridge and external secrets after the containers
   stop. Follow [local cleanup](operations.md#start-and-stop) for PolicyOps.
