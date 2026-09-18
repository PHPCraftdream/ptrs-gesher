#!/usr/bin/env python3
"""Run local release gates without publishing, tagging, or changing versions."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="source checkout to verify")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--go", default="go", help="Go executable for local interoperability")
    parser.add_argument("--deny", default="cargo-deny")
    parser.add_argument("--semver", default="cargo-semver-checks")
    parser.add_argument("--msrv", default="1.89", help="rustup toolchain for the MSRV check")
    parser.add_argument("-j", "--jobs", type=int, default=2)
    parser.add_argument("--skip-semver", action="store_true")
    parser.add_argument("--skip-deny", action="store_true")
    parser.add_argument("--skip-package", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.jobs < 1:
        parser.error("--jobs must be positive")

    cargo = shutil.which(args.cargo)
    if not cargo:
        print(f"missing cargo executable: {args.cargo}", file=sys.stderr)
        return 2

    def cargo_command(subcommand: str, *extra: str, toolchain: Optional[str] = None, jobs: bool = True) -> list[str]:
        command = [cargo]
        if toolchain:
            command.append(f"+{toolchain}")
        command.append(subcommand)
        if jobs:
            command.extend(["-j", str(args.jobs)])
        command.extend(extra)
        return command

    checks: list[tuple[str, list[str], Optional[dict[str, str]]]] = [
        ("format", [cargo, "fmt", "--all", "--", "--check"], None),
        ("clippy", cargo_command("clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"), None),
        ("tests", cargo_command("test", "--locked", "--workspace", "--all-features"), None),
        ("release tests", cargo_command("test", "--locked", "--workspace", "--all-features", "--release"), None),
        ("lyrebird experimental server", cargo_command("test", "--locked", "-p", "ptrs-gesher-lyrebird", "--features", "experimental-server"), None),
        (f"MSRV {args.msrv}", cargo_command("check", "--workspace", "--all-features", "--locked", toolchain=args.msrv), None),
        ("Go interoperability", [sys.executable, str(root / "tools/interop/run.py"), "--go", args.go, "--cargo", cargo], None),
        ("no default features", cargo_command("check", "--locked", "--workspace", "--no-default-features"), None),
    ]

    metadata_command = cargo_command("metadata", "--locked", "--no-deps", "--format-version", "1", jobs=False)
    metadata_result = subprocess.run(metadata_command, cwd=root, capture_output=True, text=True)
    if metadata_result.returncode:
        print(metadata_result.stderr, file=sys.stderr)
        return metadata_result.returncode
    metadata = json.loads(metadata_result.stdout)
    baseline = metadata.get("metadata", {}).get("release", {}).get("baseline-version")
    if not baseline:
        print("missing workspace.metadata.release.baseline-version", file=sys.stderr)
        return 2
    for package in metadata["packages"]:
        checks.append((
            f"no default features {package['name']}",
            cargo_command("check", "--locked", "-p", package["name"], "--all-targets", "--no-default-features"),
            None,
        ))
        for feature in sorted(name for name in package["features"] if name != "default"):
            checks.append((
                f"feature {package['name']}:{feature}",
                cargo_command("check", "--locked", "-p", package["name"], "--all-targets", "--no-default-features", "--features", feature),
                None,
            ))

    checks.append((
        "rustdoc",
        cargo_command("doc", "--locked", "--workspace", "--no-deps", "--all-features"),
        {"RUSTDOCFLAGS": "-D warnings"},
    ))

    skipped: list[str] = []
    if args.skip_deny:
        skipped.append("cargo-deny")
    elif shutil.which(args.deny) is None:
        print(f"missing {args.deny}; use --skip-deny only when recording an incomplete result", file=sys.stderr)
        return 2
    else:
        checks.append(("cargo deny", [args.deny, "--locked", "check"], None))
    if args.skip_semver:
        skipped.append("cargo-semver-checks")
    elif shutil.which(args.semver) is None:
        print(f"missing {args.semver}; use --skip-semver only when recording an incomplete result", file=sys.stderr)
        return 2
    else:
        checks.append(("semver release", [args.semver, "check-release", "--workspace", "--all-features", "--baseline-version", baseline], None))

    if args.skip_package:
        skipped.append("package archives")
    else:
        package_args = ["--locked", "--workspace", "--allow-dirty"]
        for package in metadata["packages"]:
            if package.get("publish") == []:
                package_args.extend(["--exclude", package["name"]])
        checks.append(("package archives", cargo_command("package", *package_args), None))

    for name, command, extra_env in checks:
        print(f"==> {name}: {' '.join(command)}", flush=True)
        env = {**os.environ, "CARGO_BUILD_JOBS": str(args.jobs)}
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(command, cwd=root, env=env)
        if result.returncode:
            print(f"FAILED: {name} (exit {result.returncode})", file=sys.stderr)
            return result.returncode
    if skipped:
        print("release checks completed with incomplete gates: " + ", ".join(skipped))
    else:
        print("release checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
