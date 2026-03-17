#!/usr/bin/env python3
"""
GraphQL Scanner - GraphQL Security Testing Tool
Author: Abin A | github.com/abinsolo
"""
import argparse
import datetime
import sys
from rich.console import Console
from modules import introspection, injection, auth, reporting

console = Console()

BANNER = """

  █████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗ ██████╗ ██╗      ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔═══██╗██║      ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ███╗██████╔╝███████║██████╔╝███████║██║   ██║██║      ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║██║▄▄ ██║██║      ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝███████╗ ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝ ╚══════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                         GraphQL Security Scanner | by Abin A
"""
def create_output_dir(url):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = url.replace("https://","").replace("http://","").split("/")[0]
    path = f"output/{domain}_{ts}"
    import os
    os.makedirs(path, exist_ok=True)
    console.log(f"[green][+][/green] Output: {path}")
    return path

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="GraphQL Scanner by Abin A")
    parser.add_argument("-u", "--url",        required=True, help="Target GraphQL URL e.g. http://localhost:3000/graphql")
    parser.add_argument("--discover",         action="store_true", help="Discover common GraphQL endpoints")
    parser.add_argument("--skip-injection",   action="store_true", help="Skip injection tests")
    parser.add_argument("--skip-auth",        action="store_true", help="Skip auth bypass tests")
    parser.add_argument("--header",           help="Custom header e.g. 'Authorization: Bearer token'")
    args = parser.parse_args()

    url = args.url
    headers = {}
    if args.header:
        key, val = args.header.split(":", 1)
        headers[key.strip()] = val.strip()

    out = create_output_dir(url)
    console.print(f"\n[bold cyan]Target:[/bold cyan] {url}\n")

    # Phase 1 - Introspection
    vuln_intro, schema, types = introspection.run(url, headers)

    # Phase 2 - Endpoint discovery
    endpoints = []
    if args.discover:
        base = url.split("/graphql")[0].split("/api")[0]
        endpoints = introspection.check_common_endpoints(base, headers)

    # Phase 3 - Injection
    injection_results = []
    if not args.skip_injection:
        injection_results = injection.run(url, headers)

    # Phase 4 - Auth bypass
    auth_results = []
    if not args.skip_auth:
        auth_results = auth.run(url, headers)

    # Phase 5 - Report
    reporting.generate(url, out, vuln_intro, endpoints,
                       injection_results, auth_results)

if __name__ == "__main__":
    main()



