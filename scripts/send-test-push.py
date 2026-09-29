#!/usr/bin/env python3
"""Sends a Telegram message to the given user via the Bot API."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

API_BASE = "https://api.telegram.org"
REQUEST_TIMEOUT_SECONDS = 10


def api_call(token: str, method: str, params: dict[str, str]) -> dict[str, Any]:
    url = f"{API_BASE}/bot{token}/{method}"
    data = urllib.parse.urlencode(params).encode()
    try:
        with urllib.request.urlopen(
            url, data=data, timeout=REQUEST_TIMEOUT_SECONDS
        ) as resp:
            result: dict[str, Any] = json.load(resp)
    except urllib.error.HTTPError as e:
        result = json.load(e)
    return result


def bot_username(token: str) -> str:
    result = api_call(token, "getMe", {})
    if not result.get("ok"):
        sys.exit(f"getMe failed: {result}")
    username: str = result["result"]["username"]
    return username


def find_chat_id(token: str, username: str) -> int | None:
    result = api_call(token, "getUpdates", {})
    if not result.get("ok"):
        sys.exit(f"getUpdates failed: {result}")
    for update in reversed(result["result"]):
        chat = update.get("message", {}).get("chat", {})
        if chat.get("username") == username:
            return int(chat["id"])
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Telegram username to send to")
    parser.add_argument(
        "text", nargs="?", help="Message text; defaults to a timestamped test string"
    )
    args = parser.parse_args()

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        sys.exit("Set TELEGRAM_BOT_TOKEN in the environment first")

    username = args.username.removeprefix("@")
    chat_id = find_chat_id(token, username)
    if chat_id is None:
        sys.exit(
            f"No chat found for @{username} -- have they messaged "
            f"the bot (@{bot_username(token)}) yet?"
        )

    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    text = args.text or f"Test message sent at {now}."
    result = api_call(token, "sendMessage", {"chat_id": str(chat_id), "text": text})
    print(json.dumps(result, indent=2))
    if not result.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
