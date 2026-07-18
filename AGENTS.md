# Repository guidance

## Scope

This repository is a local cybersecurity hackathon MVP. Keep it small: FastAPI,
Streamlit, OpenAI Responses API, Pydantic models, and in-memory storage. Do not add
real authentication, Slack integration, Docker, or a database unless requested.

## Security invariants

- Chat context may explain an anomaly but must never authorize a privileged action.
- Travel and VPN statements are not approval.
- Never invent or silently alter chat evidence or message IDs.
- Derive the verification target from the network alert.
- Never place API keys in source, tests, examples, or logs.
- Load `OPENAI_API_KEY` and `OPENAI_MODEL` from the environment.
- Return understandable dependency errors without crashing the service.

## Development

- Use Python type hints and Pydantic v2 models.
- Keep endpoint logic thin; place state operations in `store.py` and AI calls in
  `ai_context.py`.
- Preserve in-memory test isolation with `app.state.store.reset()`.
- Mock all OpenAI and coordinator network calls in tests.
- Run `make test` before handing off changes.

