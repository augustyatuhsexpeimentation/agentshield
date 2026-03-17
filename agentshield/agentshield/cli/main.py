"""
agentshield.cli.main
~~~~~~~~~~~~~~~~~~~~
Command-line interface for AgentShield.

Usage:
    agentshield validate policies/default.yaml
    agentshield scan --tool read_file --arg path=/etc/passwd
    agentshield audit summary --log agentshield_audit.jsonl
    agentshield audit query --action deny --limit 20
    agentshield audit export --format csv --output report.csv
"""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
@click.version_option(package_name="agentshield")
def cli() -> None:
    """🛡️ AgentShield — Security firewall for AI agents."""
    pass


# ── validate ──────────────────────────────────────────

@cli.command()
@click.argument("policy_path", type=click.Path(exists=True))
def validate(policy_path: str) -> None:
    """Validate a YAML policy file for errors."""
    from agentshield.core.policy import PolicyEngine, PolicyValidationError

    try:
        policy = PolicyEngine.from_yaml(policy_path)
    except (PolicyValidationError, FileNotFoundError, Exception) as e:
        console.print(f"[red]❌ Failed to load policy:[/red] {e}")
        sys.exit(1)

    issues = policy.validate()

    if issues:
        console.print(f"[yellow]⚠️  {len(issues)} issue(s) found:[/yellow]")
        for issue in issues:
            console.print(f"   • {issue}")
        sys.exit(1)
    else:
        console.print(
            f"[green]✅ Policy '{policy.name}' is valid.[/green]"
        )


# ── scan ──────────────────────────────────────────────

@cli.command()
@click.option("--tool", required=True, help="Tool name to simulate")
@click.option("--arg", multiple=True, help="Arguments as key=value pairs")
@click.option("--agent", default="default", help="Agent ID")
@click.option("--policy", default="policies/default.yaml", help="Policy file path")
def scan(tool: str, arg: tuple, agent: str, policy: str) -> None:
    """Simulate a tool call and show what AgentShield would do."""
    from agentshield import AgentShield

    # Parse key=value arguments
    arguments: dict[str, str] = {}
    for a in arg:
        if "=" in a:
            k, v = a.split("=", 1)
            arguments[k] = v
        else:
            console.print(f"[red]Invalid arg format: {a} (use key=value)[/red]")
            sys.exit(1)

    shield = AgentShield.from_policy(policy, verbose=False)
    result = shield.intercept(tool, arguments, agent_id=agent)

    # Display result
    console.print()
    console.print(f"  Tool:   [bold]{tool}[/bold]")
    console.print(f"  Agent:  {agent}")
    console.print(f"  Args:   {arguments}")
    console.print()

    if result.blocked:
        console.print(f"  [red bold]🚫 BLOCKED[/red bold]  ({result.latency_ms:.1f}ms)")
    elif result.was_modified:
        console.print(f"  [yellow bold]✏️ MODIFIED[/yellow bold]  ({result.latency_ms:.1f}ms)")
    else:
        console.print(f"  [green bold]✅ ALLOWED[/green bold]  ({result.latency_ms:.1f}ms)")

    if result.threats_detected:
        console.print()
        console.print("  Threats:")
        for t in result.threats_detected:
            lvl = t.get("level", "?")
            det = t.get("detector", "?")
            desc = t.get("description", "?")
            console.print(f"    [{lvl}] ({det}) {desc}")

    console.print()


# ── audit ─────────────────────────────────────────────

@cli.group()
def audit() -> None:
    """Query and export audit logs."""
    pass


@audit.command()
@click.option("--log", default="agentshield_audit.jsonl", help="Audit log path")
def summary(log: str) -> None:
    """Show aggregate audit statistics."""
    from agentshield.audit.storage import AuditStorage
    from agentshield.audit.exporters import to_summary_report

    store = AuditStorage.from_jsonl(log)
    report = to_summary_report(store.summary())
    console.print(report)


@audit.command()
@click.option("--log", default="agentshield_audit.jsonl", help="Audit log path")
@click.option("--action", default=None, help="Filter: allow/deny/modify")
@click.option("--tool", default=None, help="Filter by tool name")
@click.option("--agent", default=None, help="Filter by agent ID")
@click.option("--limit", default=20, help="Max records to show")
def query(log: str, action: str, tool: str, agent: str, limit: int) -> None:
    """Query audit log with filters."""
    from agentshield.audit.storage import AuditStorage

    store = AuditStorage.from_jsonl(log)
    records = store.query(
        action=action, tool_name=tool, agent_id=agent, limit=limit,
    )

    if not records:
        console.print("[dim]No records found.[/dim]")
        return

    table = Table(title=f"Audit Log ({len(records)} records)")
    table.add_column("Time", style="dim", width=20)
    table.add_column("Action", width=8)
    table.add_column("Tool", width=20)
    table.add_column("Agent", width=12)
    table.add_column("Threats", width=8, justify="right")
    table.add_column("ms", width=8, justify="right")

    for r in records:
        action_style = {
            "allow": "[green]ALLOW[/green]",
            "deny": "[red]DENY[/red]",
            "modify": "[yellow]MODIFY[/yellow]",
        }.get(r.action, r.action)

        table.add_row(
            r.timestamp[:19],
            action_style,
            r.tool_name,
            r.agent_id,
            str(r.threats_count),
            f"{r.latency_ms:.1f}",
        )

    console.print(table)


@audit.command(name="export")
@click.option("--log", default="agentshield_audit.jsonl", help="Audit log path")
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="csv")
@click.option("--output", "-o", default=None, help="Output file (stdout if omitted)")
@click.option("--action", default=None, help="Filter: allow/deny/modify")
def export_cmd(log: str, fmt: str, output: str, action: str) -> None:
    """Export audit records to CSV or JSON."""
    from agentshield.audit.storage import AuditStorage
    from agentshield.audit import exporters

    store = AuditStorage.from_jsonl(log)
    records = store.query(action=action, limit=10000)

    if fmt == "csv":
        data = exporters.to_csv(records)
    else:
        data = exporters.to_json(records)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(data)
        console.print(f"[green]✅ Exported {len(records)} records to {output}[/green]")
    else:
        click.echo(data)


if __name__ == "__main__":
    cli()