# Architecture

## How AgentShield Works

AgentShield is a security proxy layer that sits between AI agents and the tools they call. Every tool invocation passes through a 4-stage pipeline:

```
Agent Tool Call
       │
       ▼
┌─────────────────┐
│  1. POLICY      │  Is this tool allowed for this agent?
│     ENGINE      │  Are the arguments within constraints?
└────────┬────────┘
         │ (if allowed)
         ▼
┌─────────────────┐
│  2. SECURITY    │  Prompt injection? PII? Command injection?
│     DETECTORS   │  Data exfiltration? Tool poisoning?
└────────┬────────┘
         │ (if clean or redacted)
         ▼
┌─────────────────┐
│  3. RATE        │  Is this agent calling too fast?
│     LIMITER     │  Sliding window per tool per agent.
└────────┬────────┘
         │ (if within limits)
         ▼
┌─────────────────┐
│  4. EXECUTE     │  Run the actual tool.
│     + SCAN      │  Scan output for PII/exfiltration.
│     OUTPUT      │  Log everything.
└─────────────────┘
```

## Key Design Decisions

**Zero-trust by default.** The default policy action is `deny`. Only explicitly allowed tools pass. This is safer than an allowlist-by-default approach.

**Framework-agnostic.** AgentShield works via a Python decorator (`@shield.protect`) or programmatic API (`shield.intercept()`). No dependency on any specific agent framework.

**Minimal latency.** The entire pipeline runs in <5ms for typical payloads. All regex patterns are pre-compiled. No network calls in the critical path.

**Audit everything.** Every interception decision is logged as a JSON-lines entry with timestamp, action, threats, latency, and policy decisions. Never lose visibility into what your agents are doing.

**Detectors are pluggable.** Each detector implements a simple interface (`scan_input`, `scan_output`, `modify_arguments`). Custom detectors can be registered at runtime.

## Components

| Component | File | Purpose |
|-----------|------|---------|
| Interceptor | `core/interceptor.py` | Orchestrates the pipeline |
| Policy Engine | `core/policy.py` | Evaluates YAML rules |
| Session Manager | `core/session.py` | Rate limiting state |
| Detector Pipeline | `detectors/base.py` | Chains detectors together |
| Prompt Injection | `detectors/prompt_injection.py` | 15+ injection patterns |
| PII Scanner | `detectors/pii_scanner.py` | 8 entity types + redaction |
| Command Injection | `detectors/command_injection.py` | Shell/code injection |
| Data Exfiltration | `detectors/data_exfiltration.py` | URL/blob/size analysis |
| Tool Poisoning | `detectors/tool_poisoning.py` | MCP description scanning |
| Audit Logger | `audit/logger.py` | JSON-lines logging |