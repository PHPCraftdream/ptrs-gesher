"""Validate the immutable source and package versions of a release."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

PACKAGES = {
    "ptrs-gesher", "ptrs-gesher-core", "ptrs-gesher-bridge-line",
    "ptrs-gesher-obfs4", "ptrs-gesher-webtunnel", "ptrs-gesher-lyrebird",
}


def stable_version(value):
    value = value.strip()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("expected a stable version X.Y.Z")
    return value


def full_sha(value):
    value = value.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
        raise ValueError("source SHA must contain all 40 hexadecimal characters")
    return value.lower()


def git(root, *arguments):
    return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()


def resolve_source(root, version, expected_sha):
    stable_version(version)
    expected_sha = full_sha(expected_sha)
    resolved = git(root, "rev-parse", "--verify", f"refs/tags/v{version}^{{commit}}")
    if resolved != expected_sha:
        raise ValueError("release tag does not match the expected source SHA")
    return resolved


def validate_metadata(metadata, version):
    stable_version(version)
    packages = {package["name"]: package for package in metadata["packages"]
                if package.get("publish") != []}
    if set(packages) != PACKAGES:
        raise ValueError("unexpected set of publishable workspace packages")
    for name, package in packages.items():
        if package["version"] != version:
            raise ValueError(f"{name}: version does not match release {version}")
        for dependency in package["dependencies"]:
            if dependency["name"] in PACKAGES and dependency["req"] not in (
                f"^{version}", f"={version}"
            ):
                raise ValueError(f"{name}: stale internal requirement for {dependency['name']}")
    return packages


def verify_source(root, version, expected_sha):
    expected_sha = full_sha(expected_sha)
    if git(root, "rev-parse", "HEAD") != expected_sha:
        raise ValueError("checkout does not match the approved release SHA")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("release checkout must be clean, including untracked files")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=root, text=True,
    ))
    return validate_metadata(metadata, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("resolve", "verify"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "resolve":
            sha = resolve_source(args.root, args.version, args.source_sha)
            output = f"version={args.version}\nsha={sha}\n"
            print(output, end="")
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as destination:
                    destination.write(output)
        else:
            verify_source(args.root, args.version, args.source_sha)
            print(f"Verified release {args.version} from {args.source_sha}")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release source rejected: {error}\n")


if __name__ == "__main__":
    main()
