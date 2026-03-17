import requests
from rich.console import Console

console = Console()

def run(url, headers=None):
    console.rule("[bold yellow]Phase 3 - Injection Testing")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)

    results = []

    # Test 1 - Field suggestion (info leak)
    try:
        resp = requests.post(url,
            json={"query": "{ user { INVALIDFIELD } }"},
            headers=h, timeout=10)
        if "Did you mean" in resp.text or "suggestion" in resp.text.lower():
            console.log("[bold red][!] Field suggestion enabled - information leak[/bold red]")
            results.append(("Field Suggestion", True))
        else:
            console.log("[green][+] Field suggestion disabled[/green]")
            results.append(("Field Suggestion", False))
    except Exception as e:
        console.log(f"[red]Field suggestion test error: {e}[/red]")

    # Test 2 - Batch query abuse
    try:
        batch = [{"query": "{ __typename }"}] * 10
        resp = requests.post(url, json=batch, headers=h, timeout=10)
        if resp.status_code == 200 and isinstance(resp.json(), list):
            console.log("[bold red][!] Batch queries accepted - DoS risk[/bold red]")
            results.append(("Batch Query Abuse", True))
        else:
            console.log("[green][+] Batch queries not supported[/green]")
            results.append(("Batch Query Abuse", False))
    except:
        results.append(("Batch Query Abuse", False))

    # Test 3 - Deep recursion
    try:
        deep = "{ a" + "{ b" * 15 + " }" * 15 + " }"
        resp = requests.post(url,
            json={"query": deep},
            headers=h, timeout=10)
        if resp.status_code == 200:
            console.log("[bold red][!] Deep query accepted - no depth limit[/bold red]")
            results.append(("No Query Depth Limit", True))
        else:
            console.log("[green][+] Query depth limited[/green]")
            results.append(("No Query Depth Limit", False))
    except:
        results.append(("No Query Depth Limit", False))

    return results
