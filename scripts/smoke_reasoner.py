from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.normalizers import normalize_network_event
from app.policy import PolicyLoader
from app.reasoners import create_openai_reasoner
from app.settings import Settings


async def run() -> None:
    root = Path(__file__).resolve().parents[1]
    settings = Settings.load(root / ".env")
    if settings.reasoner_mode != "openai" or not settings.openai_api_key:
        raise SystemExit("The project .env must contain OPENAI_API_KEY for this smoke test")
    event_data = json.loads((root / "fixtures" / "drop_vpn_https.json").read_text())
    event = normalize_network_event(event_data)
    evidence = PolicyLoader(root / "config").build_evidence(event)
    reasoner = create_openai_reasoner(
        api_key=settings.openai_api_key,
        model=settings.openai_model,
        max_output_tokens=settings.llm_max_output_tokens,
    )
    result = await reasoner.analyze(evidence, event_type=event.event_type)
    print(result.analysis.model_dump_json(indent=2))
    print(
        json.dumps(
            {
                "provider": result.provider,
                "model": result.model,
                "prompt_version": result.prompt_version,
                "latency_ms": round(result.latency_ms, 2),
                "usage": (
                    {
                        "input_tokens": result.usage.input_tokens,
                        "output_tokens": result.usage.output_tokens,
                        "total_tokens": result.usage.total_tokens,
                    }
                    if result.usage
                    else None
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(run())

