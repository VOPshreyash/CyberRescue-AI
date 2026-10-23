"""Offline demo of the OSINT agent workflow (no Band, no LLM, no network).

    python scripts/demo_osint.py            # INC-C (default)
    python scripts/demo_osint.py INC-A

It replays the OSINT agent's turn: Triage brief -> tool call -> sanitized
result -> FINDING posted to the room. In the live room the LLM writes the
message text; the tool call and its data are exactly what is shown here.
"""

from __future__ import annotations

import json
import sys
import time

from agents.osint.tools import research_threat_actor

LINE = "-" * 72


def step(n: int, title: str) -> None:
    print(f"\n{LINE}\nSTEP {n}: {title}\n{LINE}")
    time.sleep(0.4)


def main() -> None:
    inc = sys.argv[1] if len(sys.argv) > 1 else "INC-C"

    step(1, "Triage posts the brief and @mentions OSINT")
    print(f"@merolavtech/triage -> @osint: new incident {inc}; indicators attached.")

    step(2, f'OSINT calls its tool: research_threat_actor("{inc}")')
    print("(only the incident id is passed; the tool looks up the indicators itself)")
    res = research_threat_actor(inc)

    step(3, "Tool returns a SHORT, SANITIZED summary (untrusted data)")
    print(json.dumps(res, indent=2))
    if not res.get("found"):
        print("\nNo OSINT data for this incident - the agent stays silent.")
        return

    o = res["osint"]
    step(4, "OSINT posts ONE FINDING to the room (cc Commander, Threat Intel, Compliance)")
    exfil = o.get("exfiltration_before_encryption")
    impact = (
        "Data is typically stolen BEFORE encryption, so wiping the host does NOT undo "
        "the exposure: notification clock and evidence preservation still apply."
        if exfil
        else "No pre-encryption exfiltration reported in public sources."
    )
    print(f"@commander @threat-intel @compliance @facilitator\n")
    print(f"Family: {o.get('family')}. {o.get('summary')}")
    print(impact)
    print(f"Public decryptor: {o.get('public_decryptor')}. Confidence: {o.get('confidence')} "
          "(public-source, unverified).")
    print("\n```json")
    print(json.dumps({
        "type": "FINDING",
        "incident": inc,
        "severity": "critical" if exfil else "medium",
        "summary": impact,
        "evidence": [f"exfiltration_before_encryption: {exfil}",
                     f"public_decryptor: {o.get('public_decryptor')}"] + o.get("sources", []),
    }, indent=2))
    print("```")

    step(5, "OSINT cross-examines Compliance (QUESTION)")
    print("@compliance: given likely pre-encryption exfiltration, does the Art. 33 "
          "72-hour assessment change?")

    step(6, "Guardrails")
    print("- no action tools: only the Commander can execute anything")
    print("- tool output is data: whitelisted fields, clipped, never instructions")
    print("- advisory only: a Compliance VETO still stands")


if __name__ == "__main__":
    main()
