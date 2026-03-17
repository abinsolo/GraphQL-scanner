import os
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def generate(url, out, introspection, endpoints, injections, auth_results):
    console.rule("[bold yellow]Phase 5 - Report Generation")

    vulns = []
    if introspection:
        vulns.append("Introspection Enabled")
    for name, result in injections:
        if result:
            vulns.append(name)
    for query, result in auth_results:
        if result:
            vulns.append(f"Auth Bypass: {query[:40]}")

    report = f"""# GraphQL Scanner Report
**Target:** {url}
**Date:** {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary
| Check | Result |
|-------|--------|
| Introspection | {"VULNERABLE" if introspection else "Safe"} |
| Endpoints Found | {len(endpoints)} |
| Injection Issues | {sum(1 for _, r in injections if r)} |
| Auth Bypass Issues | {sum(1 for _, r in auth_results if r)} |

## Vulnerabilities Found
{chr(10).join(f"- {v}" for v in vulns) if vulns else "- None found"}

## Endpoints Discovered
{chr(10).join(f"- {e}" for e in endpoints) if endpoints else "- None found"}

## Next Steps
1. Use found endpoints for manual testing
2. If introspection enabled - enumerate all types and fields
3. Test authenticated endpoints with stolen/forged tokens
4. Check batch queries for rate limit bypass
5. Test field suggestions for sensitive field names
"""

    os.makedirs(out, exist_ok=True)
    report_path = f"{out}/REPORT.md"
    with open(report_path, "w") as f:
        f.write(report)

    color = "red" if vulns else "green"
    status = f"{len(vulns)} VULNERABILITIES FOUND" if vulns else "NO VULNERABILITIES FOUND"

    console.print(Panel.fit(
        f"[bold {color}]{status}[/bold {color}]\n\n" +
        "\n".join(f"[red][!] {v}" for v in vulns) +
        f"\n\n[yellow]Report -> {report_path}[/yellow]",
        title="[bold cyan]GraphQL Scanner Results[/bold cyan]",
        border_style=color
    ))
