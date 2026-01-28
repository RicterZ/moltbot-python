# Moltbot Python SDK

Repository: `git@github.com:RicterZ/moltbot-python.git` (branch: `main`)

A lightweight Python SDK + CLI for the Moltbot Gateway WebSocket. It performs the full `connect` handshake (device identity + nonce signing) and exposes RPC helpers such as `chat.send`, `chat.abort`, `chat.history`, `sessions.list`, and `status`. The CLI can stream chat events or run an interactive REPL.

## Prerequisites

- Python 3.11+
- `pip install -e .` from this `sdk/` directory (installs `websockets` + `cryptography` and exposes the `moltbot` entrypoint).

## Quick start

```bash
cd sdk
python -m pip install -e .

# Show gateway status
moltbot status --url ws://127.0.0.1:18789 --token "$GATEWAY_TOKEN"

# Send a chat message and stream events until completion
moltbot chat-send --session my-session --message "Hello" --token "$GATEWAY_TOKEN"

# Interactive chat loop (prints final text for each turn)
moltbot interactive --session my-session --token "$GATEWAY_TOKEN"

# Tail all gateway events
moltbot listen --token "$GATEWAY_TOKEN"
```

Flags:
- `--url` defaults to `ws://127.0.0.1:18789`
- `--token` / `--password` provide gateway auth
- `--scope` can be repeated to request specific operator scopes (default: `operator.admin`)
- Add `--debug` to any command to print Gateway debug logs (handshake, events, responses) to stderr

### High-level helpers (sync/async)

- Async: `from moltbot import chat_once_async, status_async`
- Sync: `from moltbot import chat_once_sync, status_sync`

Example (sync):
```python
from moltbot import chat_once_sync

res = chat_once_sync(
    url="ws://127.0.0.1:18789",
    token="…",
    session_key="mysession",
    message="hello",
    wait_timeout=60,
)
print(res["final_text"])  # final assistant text
print(res["events"])      # streamed chat events
```

Example (async):
```python
import asyncio
from moltbot import chat_once_async

async def main():
    res = await chat_once_async(
        url="ws://127.0.0.1:18789",
        token="…",
        session_key="mysession",
        message="hello",
        wait_timeout=60,
    )
    print(res["final_text"])
    print(res["events"])

asyncio.run(main())
```

Device identity + issued device tokens are stored under `~/.clawdbot/identity/` (or the configured state dir) to match the Node client behavior.
