"""Publish one crate, checking registry identity instead of parsing success prose."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from release_source import PACKAGES, full_sha, stable_version, verify_source

REGISTRY = "https://crates.io/api/v1/crates"
MAX_RESPONSE = 20 * 1024 * 1024


def request_bytes(url):
    request = Request(url, headers={"User-Agent": "ptrs-gesher-release"})
    with urlopen(request, timeout=30) as response:
        contents = response.read(MAX_RESPONSE + 1)
    if len(contents) > MAX_RESPONSE:
        raise ValueError("registry response exceeds release verification limit")
    return contents


def verify_archive(contents, checksum, crate, version, source_sha):
    if hashlib.sha256(contents).hexdigest() != checksum:
        raise ValueError("published archive checksum differs from registry metadata")
    with gzip.GzipFile(fileobj=io.BytesIO(contents)) as compressed:
        expanded = compressed.read(MAX_RESPONSE + 1)
    if len(expanded) > MAX_RESPONSE:
        raise ValueError("expanded archive exceeds release verification limit")
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        member = archive.getmember(f"{crate}-{version}/.cargo_vcs_info.json")
        if not member.isfile() or member.size > 65536:
            raise ValueError("published package has invalid VCS metadata")
        with archive.extractfile(member) as source:
            vcs = json.load(source)
    if vcs.get("git", {}).get("sha1") != source_sha or vcs.get("git", {}).get("dirty", False):
        raise ValueError("published package comes from different or dirty source; refusing retry")


def published_from(crate, version, source_sha):
    url = f"{REGISTRY}/{crate}/{version}"
    try:
        metadata = json.loads(request_bytes(url))["version"]
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    if metadata["crate"] != crate or metadata["num"] != version or metadata["yanked"]:
        raise ValueError("registry returned mismatched or yanked package version")
    verify_archive(request_bytes(url + "/download"), metadata["checksum"],
                   crate, version, source_sha)
    return True


def verify_existing_release(version, source_sha, root):
    source_sha = full_sha(source_sha)
    verify_source(root, version, source_sha)
    for crate in sorted(PACKAGES):
        published_from(crate, version, source_sha)
    print(f"Verified existing packages for {version} from {source_sha}")


def publish(crate, version, source_sha, root):
    if crate not in PACKAGES:
        raise ValueError("unknown workspace crate")
    stable_version(version)
    source_sha = full_sha(source_sha)
    verify_source(root, version, source_sha)
    if published_from(crate, version, source_sha):
        print(f"VERIFIED ALREADY PUBLISHED: {crate} {version} from {source_sha}")
        return 0
    for attempt in range(1, 4):
        result = subprocess.run(
            ["cargo", "publish", "-p", crate, "--locked", "--registry", "crates-io"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        print(result.stdout, end="", flush=True)
        # Also handles a lost acknowledgement after a successful upload.
        if published_from(crate, version, source_sha):
            print(f"VERIFIED PUBLISHED: {crate} {version} from {source_sha}")
            return 0
        if result.returncode == 0:
            raise ValueError("upload acknowledged but registry version is not visible; retry the same SHA")
        if not re.search(r"\b(?:status|HTTP(?:/\d(?:\.\d)?)?)\s*:?\s*429\b|Too Many Requests",
                         result.stdout, re.IGNORECASE) or attempt == 3:
            return result.returncode
        # Keep retries short enough for the per-crate OIDC access token.
        time.sleep(60 * attempt)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("crate", choices=["check-existing", *sorted(PACKAGES)])
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        if args.crate == "check-existing":
            verify_existing_release(args.version, args.source_sha, args.root)
            code = 0
        else:
            code = publish(args.crate, args.version, args.source_sha, args.root)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Publication not verified: {error}\n")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
