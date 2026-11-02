"""OSINT agent -- Pydantic AI adapter.

Researches the public footprint of the malware family / actor behind an incident
and shares it with the room. Advises only: it has no action tools and no
recruitment tools (platform allowlist = send_message only).

Run locally:
    python -m agents.osint.main
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from thenvoi import Agent, AdapterFeatures
from thenvoi.adapters import PydanticAIAdapter

from agents.osint.tools import pydantic_ai_tools
from shared.band_logging import LoggingPreprocessor, attach_sdk_logging
from shared.config import load_agent, render_prompt
from shared.logging import get_logger, log_event
from shared.sdk_patches import apply_sdk_patches


AGENT_NAME = "osint"
PROMPT_PATH = Path(__file__).with_name("prompt.md")


async def main() -> None:
    log = get_logger(AGENT_NAME)
    attach_sdk_logging(AGENT_NAME)
    apply_sdk_patches()  # band-sdk 0.2.11 ack-loop fixes (see shared/sdk_patches.py)
    log_event(log, "boot", "loading config")

    creds = load_agent(AGENT_NAME)
    log_event(log, "config", f"framework={creds.framework} account={creds.account}")

    model = os.getenv("OSINT_MODEL", "openai:gpt-4o")
    custom_section = render_prompt(PROMPT_PATH)

    adapter = PydanticAIAdapter(
        model=model,
        custom_section=custom_section,
        additional_tools=pydantic_ai_tools(),
        # PLATFORM tools only. Speaking is all this agent may do.
        features=AdapterFeatures(include_tools=["thenvoi_send_message"]),
    )
    agent = Agent.create(
        adapter=adapter,
        agent_id=creds.agent_id,
        api_key=creds.api_key,
        preprocessor=LoggingPreprocessor(log),
    )

    log_event(log, "connect", f"running Band agent loop (model={model})")
    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
