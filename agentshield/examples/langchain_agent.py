
# NOTE: This example requires `pip install langchain-core langchain-openai`
# It's shown here for reference — the integration pattern works with any
# LangChain tool.

print("""
🛡️ AgentShield + LangChain Integration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Step 1: Define your tools normally
from langchain.tools import tool

@tool
def search_database(query: str) -> str:
    \"\"\"Search the product database.\"\"\"
    return db.execute(query)

@tool
def read_file(path: str) -> str:
    \"\"\"Read a file from disk.\"\"\"
    return open(path).read()

# Step 2: Wrap with AgentShield
from agentshield.integrations.langchain import shield_tools

protected_tools = shield_tools(
    tools=[search_database, read_file],
    policy_path="policies/default.yaml",
)

# Step 3: Use protected_tools in your agent
from langchain.agents import create_openai_tools_agent, AgentExecutor
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o")
agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

# Now every tool call goes through AgentShield automatically!
# SQL injection, prompt injection, PII — all blocked before
# the tool function is ever executed.
""")