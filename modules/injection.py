#!/usr/bin/env python3
"""
Injection Testing Module - ReconKit

Enhancements:
- Dynamic payload loading from file
- Error-based detection
- Time-based detection
- Timeout handling
"""

import time
import requests
from rich.console import Console

console = Console()


# ----------------------------------------
# Load payloads from file
# ----------------------------------------
def load_payloads(file_path="payloads/injections.txt"):
    payloads = []

    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                payloads.append(line)

        console.log(f"[green][+][/green] Loaded {len(payloads)} payloads")

    except Exception as e:
        console.log(f"[red]Error loading payloads: {e}[/red]")

    return payloads


# ----------------------------------------
# Test payloads with response analysis
# ----------------------------------------
def test_payloads(url, headers, payloads):
    findings = []

    for payload in payloads:
        try:
            # Start timing request
            start = time.time()

            response = requests.post(
                url,
                json={"query": payload},
                headers=headers,
                timeout=10
            )

            # End timing
            end = time.time()
            response_time = end - start

            # ----------------------------------------
            # 1. Error-based detection
            # ----------------------------------------
            if any(keyword in response.text.lower() for keyword in [
                "error", "exception", "syntax", "unexpected", "invalid"
            ]):
                console.log(f"[yellow][!] Error-based behavior detected: {payload}[/yellow]")
                findings.append(("Error-based Injection", payload))

            # ----------------------------------------
            # 2. Time-based detection
            # ----------------------------------------
            if response_time > 4:  # Threshold (seconds)
                console.log(
                    f"[bold red][!] Time delay detected ({response_time:.2f}s): {payload}[/bold red]"
                )
                findings.append(("Time-based Injection", payload))

        # ----------------------------------------
        # 3. Timeout detection
        # ----------------------------------------
        except requests.exceptions.Timeout:
            console.log(f"[bold red][!] Request timeout triggered: {payload}[/bold red]")
            findings.append(("Timeout Injection", payload))

        except Exception:
            continue

    return findings


# ----------------------------------------
# Main Injection Testing Entry
# ----------------------------------------
def run(url, headers=None):
    console.rule("[bold yellow]Phase 3 - Injection Testing")

    # Default headers
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)

    results = []

    # ----------------------------------------
    # Test 1 - Field suggestion (info leak)
    # ----------------------------------------
    try:
        resp = requests.post(
            url,
            json={"query": "{ user { INVALIDFIELD } }"},
            headers=h,
            timeout=10
        )

        if "did you mean" in resp.text.lower() or "suggestion" in resp.text.lower():
            console.log("[bold red][!] Field suggestion enabled - information leak[/bold red]")
            results.append(("Field Suggestion", True))
        else:
            console.log("[green][+] Field suggestion disabled[/green]")
            results.append(("Field Suggestion", False))

    except Exception as e:
        console.log(f"[red]Field suggestion test error: {e}[/red]")


    # ----------------------------------------
    # Test 2 - Batch query abuse (DoS risk)
    # ----------------------------------------
    try:
        batch = [{"query": "{ __typename }"}] * 10

        resp = requests.post(url, json=batch, headers=h, timeout=10)

        if resp.status_code == 200 and isinstance(resp.json(), list):
            console.log("[bold red][!] Batch queries accepted - DoS risk[/bold red]")
            results.append(("Batch Query Abuse", True))
        else:
            console.log("[green][+] Batch queries not supported[/green]")
            results.append(("Batch Query Abuse", False))

    except Exception:
        results.append(("Batch Query Abuse", False))


    # ----------------------------------------
    # Test 3 - Deep recursion (no depth limit)
    # ----------------------------------------
    try:
        deep_query = "{ a" + "{ b" * 15 + " }" * 15 + " }"

        resp = requests.post(
            url,
            json={"query": deep_query},
            headers=h,
            timeout=10
        )

        if resp.status_code == 200:
            console.log("[bold red][!] Deep query accepted - no depth limit[/bold red]")
            results.append(("No Query Depth Limit", True))
        else:
            console.log("[green][+] Query depth limited[/green]")
            results.append(("No Query Depth Limit", False))

    except Exception:
        results.append(("No Query Depth Limit", False))


    # ----------------------------------------
    # Test 4 - Payload-based injection testing
    # ----------------------------------------
    payloads = load_payloads()

    findings = test_payloads(url, h, payloads)

    if findings:
        console.log(f"[bold red][!] Potential injection issues found: {len(findings)}[/bold red]")
        results.extend(findings)
    else:
        console.log("[green][+] No obvious injection behavior detected[/green]")


    return results