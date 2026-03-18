# Policy Reference

AgentShield policies are YAML files that define security rules for your agents.

## Structure

```yaml
version: "1.0"              # Schema version
name: "my-policy"           # Human-readable name
description: "..."          # Optional description
default_action: deny        # "allow" or "deny" when no rule matches

agents:                     # Per-agent rules
  default: ...              # Fallback for unnamed agents
  my_agent: ...             # Rules for a specific agent_id

tools:                      # Per-tool argument constraints
  read_file: ...
  search_database: ...

detectors:                  # Detector on/off and behavior
  prompt_injection: ...
  pii_scanner: ...

alerts:                     # Alerting configuration (V2)
  enabled: false
```

## Agent Rules

```yaml
agents:
  default:
    allowed_tools:          # Only these tools can be called
      - "web_search"
      - "read_file"
    denied_tools:           # These are always blocked (overrides allow)
      - "execute_shell"
      - "delete_*"          # Wildcards supported
    rate_limits:
      "*":                  # Global limit for all tools
        max_calls: 100
        window_seconds: 60
      "web_search":         # Per-tool limit
        max_calls: 20
        window_seconds: 60
```

**Wildcards:** Use `*` for glob matching. `delete_*` matches `delete_file`, `delete_user`, etc.

**Priority:** Deny rules always win over allow rules.

**Fallback:** If an agent_id isn't listed, the `default` config is used.

## Tool Rules

```yaml
tools:
  read_file:
    denied_paths:           # Block access to sensitive paths
      - "/etc/**"
      - "**/.ssh/**"
      - "**/.env"

  search_database:
    denied_operations:      # Block dangerous SQL operations
      - "DROP"
      - "DELETE"
      - "TRUNCATE"

  execute_shell:
    denied_patterns:        # Block dangerous command patterns
      - "rm -rf"
      - "curl * | bash"
```

## Detector Configuration

```yaml
detectors:
  prompt_injection:
    enabled: true           # Turn on/off
    action: deny            # deny | warn | log

  pii_scanner:
    enabled: true
    action: redact          # deny | redact | warn | log

  command_injection:
    enabled: true
    action: deny

  data_exfiltration:
    enabled: true
    action: deny

  tool_poisoning:
    enabled: true
    action: deny
```

## Environment Variables

Policies support `${ENV_VAR}` expansion:

```yaml
alerts:
  channels:
    - type: webhook
      url: "${AGENTSHIELD_WEBHOOK_URL}"
```

## Validation

Always validate before deploying:

```bash
agentshield validate policies/my-policy.yaml
```