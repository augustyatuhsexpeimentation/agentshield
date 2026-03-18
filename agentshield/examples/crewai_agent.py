#!/usr/bin/env python3
"""
Example: Using AgentShield with CrewAI (reference — no CrewAI dependency needed).
"""

print("""
🛡️ AgentShield + CrewAI Integration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Step 1: Define CrewAI tools normally
from crewai_tools import tool

@tool("DatabaseSearch")
def search_database(query: str) -> str:
    \"\"\"Search the company database.\"\"\"
    return db.execute(query)

# Step 2: Wrap with AgentShield
from agentshield.integrations.crewai import shield_crewai_tools

protected = shield_crewai_tools(
    tools=[search_database],
    policy_path="policies/strict.yaml",
)

# Step 3: Use in your CrewAI agents
from crewai import Agent, Task, Crew

researcher = Agent(
    role="Research Analyst",
    tools=protected,   # <-- AgentShield-protected tools
    llm=llm,
)

# Every tool call by the agent now passes through AgentShield.
# Attacks are blocked, PII is redacted, everything is logged.
""")