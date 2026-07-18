# Workplace Security Group Chat MVP

This local hackathon component receives suspicious privileged-request alerts,
posts a targeted verification question into a workplace group chat, and records
the named person's `Yes`, `No`, or `Unsure` response.

The MVP implements chat, OpenAI context analysis, and the complete human
verification flow. Coordinator callback delivery remains deferred. OpenAI
analysis is stored as structured Pydantic data and is informational only; it can
never authorize an admin request.

Each completed analysis contains `observed_facts`, `relevant_message_ids`,
`inference`, `unresolved_issue`, `verification_target`, `verification_question`,
and `context_confidence`. The target and question are deterministically replaced
with values derived from the alert before storage.

## Security boundary

- Chat messages provide context only. Travel or VPN messages are never authorization.
- Verification target and question are derived from the network alert, not chat text.
- AI-reported message IDs are rejected unless they were included in the supplied context.
- Human verification is posted even when the OpenAI API is unavailable.
- The identity selector is a demo convenience, not authentication.
- Storage is process-local and is erased whenever the backend restarts.
- Do not use this MVP to approve or execute privileged actions.

## Setup

Python 3.9 or newer is supported; Python 3.11 or newer is recommended.

```bash
make install
cp .env.example .env
```

Set `OPENAI_API_KEY` and `OPENAI_MODEL` in `.env`. Keep `.env` local; it is
ignored by Git. Without a usable AI configuration, alerts are still persisted
and verified, with `analysis_status: "failed"` and an understandable error.

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

## Try the flow

Post an ordinary context message:

```bash
curl -X POST http://localhost:8003/messages \
  -H 'Content-Type: application/json' \
  -d '{"author":"Alice","content":"I am traveling and expect to use a VPN."}'
```

Post a network alert:

```bash
curl -X POST http://localhost:8003/network-alerts \
  -H 'Content-Type: application/json' \
  -d '{
    "alert_id":"monitor-42",
    "actor":"Alice",
    "request_summary":"grant database-admin to deployment-bot",
    "target_resource":"production database",
    "source_ip":"203.0.113.10"
  }'
```

The response contains an event ID, and the chat displays a security message with
response buttons. The same response can be submitted directly:

```bash
curl -X POST http://localhost:8003/security-events/EVENT_ID/human-response \
  -H 'Content-Type: application/json' \
  -d '{"responder":"Alice","response":"Unsure"}'
```

## Endpoints

- `GET /health`
- `GET /messages`
- `POST /messages`
- `POST /network-alerts`
- `GET /security-events/{event_id}`
- `POST /security-events/{event_id}/human-response`

## Tests

```bash
make test
```

The endpoint and AI tests use an isolated in-memory store and mocked OpenAI
clients. The test suite makes no external API calls.

## Project layout

- `backend.py` — FastAPI routes
- `ui.py` — Streamlit chat interface
- `models.py` — Pydantic request and response contracts
- `store.py` — thread-safe in-memory storage
- `ai_context.py` — grounded Responses API structured-output integration
- `tests/test_backend.py` — endpoint tests
