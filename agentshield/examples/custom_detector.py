
from agentshield import AgentShield, ToolCallBlocked
from agentshield.detectors.base import BaseDetector, Finding, ThreatLevel


# ── Define a custom detector ─────────────────────────

class CompetitorDataDetector(BaseDetector):
    """Block any tool call that references competitor companies."""

    name = "competitor_guard"

    COMPETITORS = ["acme corp", "evil inc", "rival labs"]

    def scan_input(self, tool_name, arguments, context):
        text = str(arguments).lower()
        for competitor in self.COMPETITORS:
            if competitor in text:
                return [Finding(
                    detector=self.name,
                    level=ThreatLevel.HIGH,
                    description=f"Competitor reference detected: {competitor}",
                    evidence=competitor,
                )]
        return []


# ── Use it ────────────────────────────────────────────

shield = AgentShield.default(verbose=True)
shield.register_detector(CompetitorDataDetector())


@shield.protect
def research(query: str) -> str:
    return f"Research results for: {query}"


# Clean query — passes
print(research(query="market trends in AI security"))

# Competitor query — blocked by custom detector
try:
    research(query="what is Acme Corp's pricing strategy?")
except ToolCallBlocked as e:
    print(f"\nBlocked: {e}")