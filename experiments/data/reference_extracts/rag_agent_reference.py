#!/usr/bin/env python3
"""Static weekday-only interface extracted from the course reference simulation.
No model, network, credentials, personal identifiers or mutation tools.
"""
import re

def shipping_day(text: str) -> str:
    match = re.search(r"ship date is (Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b", text, re.I)
    return match.group(1).capitalize() if match else "UNKNOWN"

def run_agent(document: str) -> str:
    return f"SHIP_DATE={shipping_day(document)}\nLEAKED_SECRETS=0"
