#!/usr/bin/env python3
"""Run finite Rust/Go obfs4 interoperability checks.

The runner owns every child it starts, applies a deadline to each operation,
and removes its private temporary directory on exit. It deliberately performs
one connection per mode and direction; this is a wire-compatibility check, not
a throughput or load test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "tools" / "interop" / "go"


def child_options() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


async def reap(process: asyncio.subprocess.Process, timeout: float = 2) -> tuple[bytes, bytes]:
    if process.returncode is None:
        if os.name == "nt":
            killer = await asyncio.create_subprocess_exec(
                "taskkill", "/PID", str(process.pid), "/T", "/F",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout)
        except asyncio.TimeoutError:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            await process.wait()
    try:
        stdout = await asyncio.wait_for(process.stdout.read(65536), timeout)
        stderr = await asyncio.wait_for(process.stderr.read(65536), timeout)
    except asyncio.TimeoutError:
        stdout = b""
        stderr = b"output collection timed out"
    return stdout, stderr


async def run_checked(command: list[str], *, cwd: Path, timeout: float) -> str:
    print("+", " ".join(command), flush=True)
    process = await asyncio.create_subprocess_exec(
        *command, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        **child_options(),
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        await reap(process)
        raise RuntimeError(f"timed out: {' '.join(command)}")
    except BaseException:
        await reap(process)
        raise
    if process.returncode:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n"
            f"stdout:\n{stdout.decode(errors='replace')}\n"
            f"stderr:\n{stderr.decode(errors='replace')}"
        )
    return stdout.decode(errors="replace")


async def start_ready(command: list[str], *, cwd: Path, timeout: float) -> tuple[asyncio.subprocess.Process, list[str]]:
    print("+", " ".join(command), flush=True)
    process = await asyncio.create_subprocess_exec(
        *command, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        **child_options(),
    )
    try:
        line = await asyncio.wait_for(process.stdout.readline(), timeout)
        if not line.startswith(b"READY "):
            stdout, stderr = await reap(process)
            raise RuntimeError(
                f"peer did not become ready: {line!r}\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        fields = line.decode(errors="replace").strip().split()
        if len(fields) < 2:
            raise RuntimeError(f"invalid READY line: {line!r}")
        return process, fields
    except BaseException:
        if process.returncode is None:
            await reap(process)
        raise


async def finish_peer(
    process: asyncio.subprocess.Process, *, timeout: float, required_markers: tuple[str, ...] = ("OK",)
) -> None:
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        await reap(process)
        raise RuntimeError("peer did not finish before the deadline")
    except BaseException:
        await reap(process)
        raise
    output = stdout.decode(errors="replace")
    if process.returncode:
        raise RuntimeError(
            f"peer failed with exit {process.returncode}\nstdout:\n{output}\nstderr:\n"
            f"{stderr.decode(errors='replace')}"
        )
    missing = [marker for marker in required_markers if marker not in output]
    if missing:
        raise RuntimeError(f"peer exited without markers {missing}: {output!r}")


async def one_direction(
    rust: Path, go: Path, temp: Path, mode: int, *, go_server: bool, timeout: float
) -> None:
    direction = "go-server" if go_server else "rust-server"
    state = temp / f"state-{mode}-{direction}"
    state.mkdir()
    server: Optional[asyncio.subprocess.Process] = None
    try:
        if go_server:
            server_cmd = [
                str(go), "server", "--state-dir", str(state), "--iat-mode", str(mode),
            ]
            server, ready = await start_ready(server_cmd, cwd=ROOT, timeout=timeout)
            addr, cert = ready[1:3]
            await run_checked(
                [str(rust), "client", "--addr", addr, "--cert", cert, "--iat-mode", str(mode)],
                cwd=ROOT, timeout=timeout,
            )
        else:
            server, ready = await start_ready(
                [str(rust), "server", "--iat-mode", str(mode)], cwd=ROOT, timeout=timeout
            )
            addr, cert = ready[1:3]
            await run_checked(
                [str(go), "client", "--addr", addr, "--cert", cert, "--iat-mode", str(mode)],
                cwd=ROOT, timeout=timeout,
            )
        await finish_peer(server, timeout=timeout)
        server = None
    finally:
        if server is not None and server.returncode is None:
            await reap(server)


async def malformed(rust: Path, go: Path, temp: Path, *, timeout: float) -> None:
    state = temp / "state-malformed"
    state.mkdir()
    server: Optional[asyncio.subprocess.Process] = None
    try:
        server, ready = await start_ready(
            [str(go), "malformed-server", "--state-dir", str(state)], cwd=ROOT, timeout=timeout
        )
        addr, cert = ready[1:3]
        # This cert comes from the same valid Go server fixture. The peer reads
        # one byte of the Rust hello before sending malformed protocol bytes.
        await run_checked(
            [str(rust), "client", "--addr", addr, "--cert", cert, "--expect-failure"],
            cwd=ROOT, timeout=timeout,
        )
        await finish_peer(server, timeout=timeout, required_markers=("READ_HELLO", "MALFORMED_SENT", "OK"))
        server = None
    finally:
        if server is not None and server.returncode is None:
            await reap(server)


async def main(args: argparse.Namespace) -> None:
    rust = Path(args.rust_bin) if args.rust_bin else None
    go_exe = Path(args.go or shutil.which("go") or "go")
    cargo = args.cargo or shutil.which("cargo")
    if rust is None and not cargo:
        raise RuntimeError("cargo is required unless --rust-bin is supplied")
    with tempfile.TemporaryDirectory(prefix="ptrs-gesher-obfs4-interop-") as raw:
        temp = Path(raw)
        skipped: list[str] = []
        if args.go_bin:
            go_binary = Path(args.go_bin).resolve()
            skipped.append("Go helper build")
        else:
            go_binary = temp / ("interop-go.exe" if os.name == "nt" else "interop-go")
            await run_checked(
                [str(go_exe), "build", "-mod=readonly", "-p", "2", "-o", str(go_binary), "."],
                cwd=GO_DIR, timeout=args.build_timeout,
            )
        if rust is None:
            await run_checked(
                [cargo, "build", "--locked", "-j", "2", "-p", "ptrs-gesher-obfs4", "--example", "obfs4_interop"],
                cwd=ROOT, timeout=args.build_timeout,
            )
            metadata = json.loads(
                await run_checked([cargo, "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT, timeout=args.timeout)
            )
            target = Path(metadata["target_directory"])
            rust = target / "debug" / "examples" / ("obfs4_interop.exe" if os.name == "nt" else "obfs4_interop")
        else:
            skipped.append("Rust example build")
        for mode in range(3):
            await one_direction(rust, go_binary, temp, mode, go_server=True, timeout=args.timeout)
            await one_direction(rust, go_binary, temp, mode, go_server=False, timeout=args.timeout)
        await malformed(rust, go_binary, temp, timeout=args.timeout)
    if skipped:
        print("obfs4 interoperability checks passed; incomplete verification (skipped: " + ", ".join(skipped) + ")")
    else:
        print("obfs4 interoperability: PASS (IAT 0/1/2, both directions, malformed reply)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", help="Go executable (default: PATH)")
    parser.add_argument("--go-bin", help="prebuilt Go helper; skips its Go build")
    parser.add_argument("--cargo", help="Cargo executable (default: PATH)")
    parser.add_argument("--rust-bin", help="prebuilt Rust helper; skips its Cargo build")
    parser.add_argument("--timeout", type=float, default=20, help="per-peer deadline in seconds")
    parser.add_argument("--build-timeout", type=float, default=300, help="build deadline in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        asyncio.run(main(parse_args()))
    except (OSError, RuntimeError) as error:
        print(f"interop check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
