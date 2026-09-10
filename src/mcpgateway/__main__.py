"""Command line entrypoint.

Three modes:
  http   - run the gateway as an HTTP MCP server plus admin API (default)
  stdio  - run as a single stdio MCP server, so any MCP client can point at
           the gateway instead of a dozen individual servers
  scan   - connect to every upstream, print the security report, and exit
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .config import GatewayConfig
from .gateway import Gateway
from .policy import Principal


def _configure_logging(level: str, *, to_stderr: bool = False) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr if to_stderr else sys.stdout,
    )


async def run_stdio(config: GatewayConfig) -> None:
    """Serve MCP over this process's stdin/stdout."""
    gateway = Gateway(config)
    await gateway.start()
    principal = next(
        (p for p in config.principals if p.id == "stdio"),
        Principal(id="stdio", allow=["*"], admin=True),
    )
    session = gateway.create_session(principal, session_id="stdio")

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    def emit(message: dict) -> None:
        sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = await gateway.handle(payload, session)
            for pending in session.drain_notifications():
                emit(pending)
            if response is not None:
                emit(response)
    finally:
        await gateway.aclose()


async def run_scan(config: GatewayConfig) -> int:
    gateway = Gateway(config)
    await gateway.start()
    try:
        entries = sorted(gateway.registry.all(), key=lambda e: -e.scan.score)
        report = {
            "summary": gateway.registry.stats(),
            "tools": [e.to_dict() for e in entries],
        }
        print(json.dumps(report, indent=2))
        return 1 if gateway.registry.quarantined_tools() else 0
    finally:
        await gateway.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcpgateway", description="Secure MCP gateway")
    parser.add_argument("-c", "--config", default="config/gateway.yaml")
    parser.add_argument("--mode", choices=("http", "stdio", "scan"), default="http")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    config = GatewayConfig.load(args.config)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port

    if args.mode == "stdio":
        # stdout is the protocol channel, so logs must go to stderr.
        _configure_logging(args.log_level, to_stderr=True)
        asyncio.run(run_stdio(config))
        return 0

    if args.mode == "scan":
        _configure_logging(args.log_level, to_stderr=True)
        return asyncio.run(run_scan(config))

    _configure_logging(args.log_level)
    import uvicorn

    from .server import build_app

    uvicorn.run(
        build_app(config), host=config.host, port=config.port, log_level=args.log_level.lower()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
