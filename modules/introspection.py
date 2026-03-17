import requests
import json
from rich.console import Console

console = Console()

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}
"""

def run(url, headers=None):
    console.rule("[bold yellow]Phase 1 - Introspection Check")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    try:
        resp = requests.post(url,
            json={"query": INTROSPECTION_QUERY},
            headers=h, timeout=15)
        data = resp.json()
        if "data" in data and data["data"] and "__schema" in data["data"]:
            console.log("[bold red][!] VULNERABLE - Introspection ENABLED[/bold red]")
            schema = data["data"]["__schema"]
            types = [t["name"] for t in schema.get("types", [])
                     if t["kind"] == "OBJECT" and not t["name"].startswith("__")]
            console.log(f"[cyan]Types found: {types}[/cyan]")
            return True, schema, types
        else:
            console.log("[green][+] Introspection disabled - good security practice[/green]")
            return False, None, []
    except Exception as e:
        console.log(f"[yellow][-] Endpoint not responding to GraphQL — skipping[/yellow]")
        return False, None, []

def check_common_endpoints(base_url, headers=None):
    console.rule("[bold yellow]Phase 2 - Common Endpoint Discovery")
    endpoints = [
        "/graphql", "/api/graphql", "/graphql/v1",
        "/v1/graphql", "/v2/graphql", "/api/v1/graphql",
        "/query", "/gql", "/graphiql", "/playground"
    ]
    found = []
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    for ep in endpoints:
        url = base_url.rstrip("/") + ep
        try:
            resp = requests.post(url,
                json={"query": "{ __typename }"},
                headers=h, timeout=8)
            if resp.status_code in [200, 400] and "data" in resp.text or "errors" in resp.text:
                console.log(f"[bold red][!] GraphQL endpoint found: {url}[/bold red]")
                found.append(url)
            else:
                console.log(f"[dim]{url} - {resp.status_code}[/dim]")
        except:
            console.log(f"[dim]{url} - timeout/error[/dim]")
    return found
