# Workplace Security Group Chat MVP

This local hackathon component receives suspicious privileged-request alerts,
posts a targeted verification question into a workplace group chat, and records
the named person's `Yes`, `No`, or `Unsure` response in local SQLite history.

The MVP implements chat, OpenAI context analysis, the complete human verification
flow, and outbound coordinator callback delivery. OpenAI analysis is stored as
structured Pydantic data and is informational only; it can never authorize an
admin request.

After a human responds, the backend sends a summarized, idempotent callback to
the configured coordinator. Callback failure never removes or rolls back the
human response, and failed deliveries can be retried manually.

Each analysis contains grounded `observed_facts` with message IDs, authors,
facts, and relevance; plus `relevant_message_ids`, `inference`,
`unresolved_issue`, `verification_target`, `verification_question`,
`context_confidence`, `context_status`, and a sanitized optional `ai_error`.
The target and question are deterministically derived from the alert before
storage.

## Security boundary

- Chat messages provide context only. Travel or VPN messages are never authorization.
- Verification target and question are derived from the network alert, not chat text.
- AI-reported message IDs are rejected unless they were included in the supplied context.
- Human verification is posted even when the OpenAI API is unavailable.
- Coordinator callbacks contain a context summary and relevant IDs, never full chat history.
- A stable callback ID is reused for retries and sent as the idempotency key.
- The identity selector is a demo convenience, not authentication.
- Chat and security-event history is stored locally as plaintext SQLite data;
  protect the database file and do not commit it.
- Do not use this MVP to approve or execute privileged actions.

## Setup

Python 3.9 or newer is supported; Python 3.11 or newer is recommended.

```bash
make install
cp .env.example .env
```

Set `OPENAI_API_KEY` and `OPENAI_MODEL` in `.env`. Keep `.env` local; it is
ignored by Git. Without a usable AI configuration, alerts are still persisted
and verified, with `analysis_status: "failed"`, a valid assessment whose
`context_status` is `"ai_unavailable"`, and a sanitized error category.

Set `COORDINATOR_RESPONSE_URL` to the coordinator endpoint that receives human
responses. If it is missing or unavailable, the response remains stored and the
event records a failed callback that can be retried.

`DATABASE_PATH` controls the local SQLite file and defaults to `chat_history.db`.
The database persists messages, events, AI context, human responses, current
callback state, and every callback attempt across backend restarts. SQLite files
are excluded from Git.

## Run

Start the backend in one terminal:

```bash
make backend
```

Start the UI in another:

```bash
make ui
```

FastAPI runs at `http://localhost:8003` and Streamlit prints its local URL when
it starts. Interactive API documentation is available at
`http://localhost:8003/docs`.

The lightweight SignalRoom UI normally opens at `http://localhost:8501`. It has
a workplace-chat layout with a channel sidebar, demo identity selector, message
timeline, security verification cards, AI context details, and response buttons.
Use the refresh button to retrieve messages posted by another browser or service.

### One-command demo

After `make install` and optional OpenAI configuration, run the complete local
demo with:

```bash
make demo
```

The demo runner starts or reuses the backend, posts a relevant VPN/travel message
and a random selection of background chat, submits a network alert, starts or
reuses Streamlit, opens the UI in your default browser, and prints the event
details. It intentionally leaves
the human verification unanswered. Open `http://localhost:8501`, respond as
Sicily, and press Ctrl+C in the demo terminal when finished. Existing history is
preserved, and the runner stops only services that it started.

For a repeatable message selection or a different message count:

```bash
.venv/bin/python scripts/demo.py --seed 42 --messages 8
```

## Try the flow

Post an ordinary context message:

```bash
curl -X POST http://localhost:8003/messages \
  -H 'Content-Type: application/json' \
  -d '{"author":"Sicily","content":"I am traveling and expect to use a VPN."}'
```

Post a network alert:

```bash
curl -X POST http://localhost:8003/network-alerts \
  -H 'Content-Type: application/json' \
  -d '{
    "alert_id":"monitor-42",
    "actor":"Sicily",
    "request_summary":"grant database-admin to deployment-bot",
    "target_resource":"production database",
    "source_ip":"203.0.113.10",
    "network_risk_score":0.94
  }'
```

The response contains an event ID, and the chat displays a security message with
response buttons. The same response can be submitted directly:

```bash
curl -X POST http://localhost:8003/security-events/EVENT_ID/human-response \
  -H 'Content-Type: application/json' \
  -d '{"responder":"Sicily","response":"Unsure"}'
```

If coordinator delivery fails, retry the same stable callback ID with:

```bash
curl -X POST \
  http://localhost:8003/security-events/EVENT_ID/coordinator-callback/retry
```

The coordinator receives only these fields:

- `callback_id`, also sent as the `Idempotency-Key` header
- `event_id`, `account_user`, `responded_by`, and `human_response`
- `responded_at`, `context_summary`, and `relevant_message_ids`
- `network_risk_score`

A JSON coordinator response may provide `final_coordinator_decision`,
`final_decision`, or `decision`; the value is stored on the event when present.

## Endpoints

- `GET /health`
- `GET /messages`
- `POST /messages`
- `POST /network-alerts`
- `GET /security-events/{event_id}`
- `POST /security-events/{event_id}/human-response`
- `POST /security-events/{event_id}/coordinator-callback/retry`

## Tests

```bash
make test
```

The endpoint, AI, and coordinator tests use isolated temporary SQLite databases
and mocked network clients. The test suite makes no external API calls and does
not modify the developer's history database.
The command prints every test name and result, a short summary for skipped or
failed tests, and the ten slowest test durations.

## Project layout

- `backend.py` — FastAPI routes
- `ui.py` — Streamlit chat interface
- `models.py` — Pydantic request and response contracts
- `store.py` — thread-safe SQLite persistence and callback audit history
- `ai_context.py` — grounded Responses API structured-output integration
- `coordinator.py` — async summarized callback delivery
- `tests/test_backend.py` — endpoint tests
- `tests/test_coordinator.py` — mocked coordinator delivery tests
- `tests/test_store.py` — restart-persistence and audit-history tests
