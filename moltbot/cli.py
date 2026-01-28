import argparse
import asyncio
import json
import logging
import sys
import uuid
from typing import Any

from .client import GatewayError, GatewayWebSocketClient


def _pretty(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def _build_client(args: argparse.Namespace, on_event=None) -> GatewayWebSocketClient:
    return GatewayWebSocketClient(
        url=args.url,
        token=args.token,
        password=args.password,
        scopes=args.scopes,
        role=args.role,
        client_id=args.client_id,
        client_mode=args.client_mode,
        client_version=args.client_version,
        client_display_name=args.client_name,
        on_event=on_event,
    )


async def _cmd_status(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        await client.connect()
        res = await client.status()
        print(_pretty(res or {}))
    finally:
        await client.close()


async def _cmd_chat_send(args: argparse.Namespace) -> None:
    done = asyncio.Event()
    run_id = args.idempotency_key or str(uuid.uuid4())

    def handle_event(evt: dict[str, Any]) -> None:
        payload = evt.get("payload") or {}
        if evt.get("event") != "chat":
            return
        if payload.get("runId") != run_id:
            return
        print(f"[chat event] {_pretty(payload)}")
        state = payload.get("state")
        if state in {"final", "error", "aborted"}:
            done.set()

    client = _build_client(args, on_event=handle_event)
    try:
        await client.connect()
        res = await client.send_chat(
            session_key=args.session,
            message=args.message,
            thinking=args.thinking,
            deliver=args.deliver,
            timeout_ms=args.timeout_ms,
            idempotency_key=run_id,
        )
        print(f"chat.send ack for runId={run_id}: {_pretty(res['response'])}")
        if args.wait:
            await asyncio.wait_for(done.wait(), timeout=args.wait)
    except asyncio.TimeoutError:
        print("timed out waiting for chat events", file=sys.stderr)
        sys.exit(2)
    finally:
        await client.close()


async def _cmd_chat_history(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        await client.connect()
        res = await client.chat_history(session_key=args.session, limit=args.limit)
        print(_pretty(res or {}))
    finally:
        await client.close()


async def _cmd_sessions(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        await client.connect()
        res = await client.sessions_list(limit=args.limit)
        print(_pretty(res or {}))
    finally:
        await client.close()


async def _cmd_listen(args: argparse.Namespace) -> None:
    stop = asyncio.Event()

    def handle_event(evt: dict[str, Any]) -> None:
        print(_pretty(evt))

    client = _build_client(args, on_event=handle_event)
    try:
        await client.connect()
        print("listening for gateway events (Ctrl+C to stop)...")
        await stop.wait()
    finally:
        await client.close()


def _extract_text(message: Any) -> str | None:
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, list):
        return None
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts) if parts else None


async def _cmd_interactive(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()
    pending: dict[str, asyncio.Future] = {}

    def handle_event(evt: dict[str, Any]) -> None:
        if evt.get("event") != "chat":
            return
        payload = evt.get("payload") or {}
        run_id = payload.get("runId")
        fut = pending.get(run_id)
        if not fut:
            return
        state = payload.get("state")
        if state in {"final", "error", "aborted"}:
            if not fut.done():
                fut.set_result(payload)

    client = _build_client(args, on_event=handle_event)
    await client.connect()
    print("Interactive chat. Type '/exit' or Ctrl+C to quit.")
    try:
        while True:
            text = await loop.run_in_executor(None, lambda: input("> ").strip())
            if not text:
                continue
            if text.lower() in {"/exit", "/quit"}:
                break
            run_id = str(uuid.uuid4())
            fut: asyncio.Future = loop.create_future()
            pending[run_id] = fut
            await client.send_chat(
                session_key=args.session,
                message=text,
                thinking=args.thinking,
                deliver=args.deliver,
                timeout_ms=args.timeout_ms,
                idempotency_key=run_id,
            )
            try:
                payload = await asyncio.wait_for(fut, timeout=args.wait)
                final_text = _extract_text(payload.get("message"))
                if final_text:
                    print(final_text)
                else:
                    print(_pretty(payload))
            except asyncio.TimeoutError:
                print("(timeout waiting for response)")
            finally:
                pending.pop(run_id, None)
    finally:
        await client.close()


async def _run(args: argparse.Namespace) -> None:
    if args.command == "status":
        await _cmd_status(args)
    elif args.command == "chat-send":
        await _cmd_chat_send(args)
    elif args.command == "chat-history":
        await _cmd_chat_history(args)
    elif args.command == "sessions":
        await _cmd_sessions(args)
    elif args.command == "listen":
        await _cmd_listen(args)
    elif args.command == "interactive":
        await _cmd_interactive(args)
    else:
        raise GatewayError(f"unknown command {args.command}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Moltbot Gateway Python SDK CLI")
    parser.add_argument("--url", default="ws://127.0.0.1:18789", help="Gateway websocket URL")
    parser.add_argument("--token", help="Gateway auth token")
    parser.add_argument("--password", help="Gateway auth password")
    parser.add_argument(
        "--scope",
        dest="scopes",
        action="append",
        help="Operator scope to request (repeatable)",
    )
    parser.add_argument("--role", default="operator", help="Gateway role (default: operator)")
    parser.add_argument("--client-id", default="gateway-client", help="Gateway client id")
    parser.add_argument(
        "--client-mode",
        default="backend",
        help="Gateway client mode (backend/ui/cli/webchat)",
    )
    parser.add_argument("--client-version", default="python-sdk", help="Client version string")
    parser.add_argument("--client-name", default="moltbot-python-sdk", help="Client display name")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    subs = parser.add_subparsers(dest="command", required=True)

    subs.add_parser("status", help="Fetch gateway status")

    chat_send = subs.add_parser("chat-send", help="Send a chat message to a session")
    chat_send.add_argument("--session", default="default", help="Session key")
    chat_send.add_argument("--message", required=True, help="Message text")
    chat_send.add_argument("--thinking", help="Optional thinking hint")
    chat_send.add_argument("--deliver", action="store_true", help="Force channel delivery")
    chat_send.add_argument("--timeout-ms", type=int, help="Override agent timeout (ms)")
    chat_send.add_argument("--idempotency-key", help="Run id/idempotency key")
    chat_send.add_argument(
        "--wait",
        type=int,
        default=60,
        help="Seconds to wait for chat events (0 to skip waiting)",
    )

    chat_interactive = subs.add_parser("interactive", help="Start an interactive chat loop")
    chat_interactive.add_argument("--session", default="default", help="Session key")
    chat_interactive.add_argument("--thinking", help="Optional thinking hint")
    chat_interactive.add_argument("--deliver", action="store_true", help="Force channel delivery")
    chat_interactive.add_argument("--timeout-ms", type=int, help="Override agent timeout (ms)")
    chat_interactive.add_argument(
        "--wait",
        type=int,
        default=120,
        help="Seconds to wait for a reply before timing out",
    )

    chat_history = subs.add_parser("chat-history", help="Fetch chat history for a session")
    chat_history.add_argument("--session", required=True, help="Session key")
    chat_history.add_argument("--limit", type=int, help="Max messages to return")

    sessions = subs.add_parser("sessions", help="List gateway sessions")
    sessions.add_argument("--limit", type=int, help="Limit number of sessions")

    subs.add_parser("listen", help="Stream all gateway events")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    try:
        asyncio.run(_run(args))
    except GatewayError as err:
        print(f"gateway error: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
