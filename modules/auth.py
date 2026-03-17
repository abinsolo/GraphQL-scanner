import requests
from rich.console import Console

console = Console()

COMMON_QUERIES = [
    '{ users { id email password } }',
    '{ user(id: 1) { id email role } }',
    '{ me { id email role isAdmin } }',
    '{ admin { id email } }',
    '{ allUsers { edges { node { id email } } } }',
]

def run(url, headers=None):
    console.rule("[bold yellow]Phase 4 - Auth Bypass & IDOR Testing")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)

    results = []

    for query in COMMON_QUERIES:
        try:
            resp = requests.post(url,
                json={"query": query},
                headers=h, timeout=10)
            data = resp.json()
            if "data" in data and data["data"] and any(
                v is not None for v in data["data"].values()
            ):
                console.log(f"[bold red][!] Unauthenticated data leak: {query[:50]}[/bold red]")
                results.append((query[:50], True))
            elif "errors" in data:
                console.log(f"[green][+] Blocked: {query[:50]}[/green]")
                results.append((query[:50], False))
        except Exception as e:
            console.log(f"[yellow][-] Endpoint not reachable — skipping query[/yellow]")

    return results
