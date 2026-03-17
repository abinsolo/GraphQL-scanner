#!/bin/bash
echo "[*] Installing GraphQL Scanner dependencies..."
pip3 install -r requirements.txt --break-system-packages
echo "[+] Done! Run: python3 graphql_scanner.py -u <target_url>"
