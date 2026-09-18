import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish
import release_source

SHA = "a" * 40
OTHER_SHA = "b" * 40
VERSION = "0.6.0"
CRATE = "ptrs-gesher"


def metadata():
    return {"packages": [
        {"name": name, "version": VERSION, "publish": None, "dependencies": []}
        for name in sorted(release_source.PACKAGES)
    ] + [{"name": "ptrs-gesher-examples", "version": "0.0.0", "publish": [], "dependencies": []}]}


def archive(sha=SHA, dirty=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as package:
        contents = json.dumps({"git": {"sha1": sha, "dirty": dirty}}).encode()
        member = tarfile.TarInfo(f"{CRATE}-{VERSION}/.cargo_vcs_info.json")
        member.size = len(contents)
        package.addfile(member, io.BytesIO(contents))
    return output.getvalue()


class SourceTests(unittest.TestCase):
    def test_tag_must_match_original_sha(self):
        with patch.object(release_source, "git", return_value=OTHER_SHA):
            with self.assertRaisesRegex(ValueError, "tag does not match"):
                release_source.resolve_source(Path.cwd(), VERSION, SHA)

    def test_valid_tag_is_resolved_as_commit(self):
        with patch.object(release_source, "git", return_value=SHA) as git:
            self.assertEqual(release_source.resolve_source(Path.cwd(), VERSION, SHA), SHA)
            self.assertEqual(git.call_args.args[-1], "refs/tags/v0.6.0^{commit}")

    def test_ref_or_short_sha_is_rejected(self):
        for sha in ("main", "a" * 7, SHA + "\nother=value"):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                release_source.resolve_source(Path.cwd(), VERSION, sha)

    def test_version_is_not_a_git_ref_or_output_injection(self):
        for version in ("v0.6.0", "0.6.0\nsha=other", "../main", "00.6.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release_source.resolve_source(Path.cwd(), version, SHA)

    def test_checkout_must_match_sha_before_metadata(self):
        with patch.object(release_source, "git", return_value=OTHER_SHA):
            with self.assertRaisesRegex(ValueError, "checkout does not match"):
                release_source.verify_source(Path.cwd(), VERSION, SHA)

    def test_dirty_checkout_is_rejected(self):
        with patch.object(release_source, "git", side_effect=[SHA, " M Cargo.toml"]):
            with self.assertRaisesRegex(ValueError, "must be clean"):
                release_source.verify_source(Path.cwd(), VERSION, SHA)

    def test_versions_and_private_examples(self):
        self.assertEqual(set(release_source.validate_metadata(metadata(), VERSION)), release_source.PACKAGES)

    def test_mixed_package_versions_rejected(self):
        data = metadata()
        data["packages"][0]["version"] = "0.5.3"
        with self.assertRaisesRegex(ValueError, "version does not match"):
            release_source.validate_metadata(data, VERSION)

    def test_stale_internal_requirement_rejected(self):
        data = metadata()
        data["packages"][0]["dependencies"] = [{"name": "ptrs-gesher-core", "req": "^0.5.3"}]
        with self.assertRaisesRegex(ValueError, "stale internal"):
            release_source.validate_metadata(data, VERSION)

    def test_missing_package_rejected(self):
        data = metadata()
        data["packages"].pop(0)
        with self.assertRaisesRegex(ValueError, "unexpected set"):
            release_source.validate_metadata(data, VERSION)


class RegistryTests(unittest.TestCase):
    def test_existing_archive_must_match_sha_and_checksum(self):
        contents = archive()
        publish.verify_archive(contents, hashlib.sha256(contents).hexdigest(), CRATE, VERSION, SHA)
        with self.assertRaisesRegex(ValueError, "checksum"):
            publish.verify_archive(contents, "0" * 64, CRATE, VERSION, SHA)
        with self.assertRaisesRegex(ValueError, "different or dirty"):
            publish.verify_archive(contents, hashlib.sha256(contents).hexdigest(), CRATE, VERSION, OTHER_SHA)

    def test_dirty_archive_is_rejected(self):
        contents = archive(dirty=True)
        with self.assertRaisesRegex(ValueError, "different or dirty"):
            publish.verify_archive(contents, hashlib.sha256(contents).hexdigest(), CRATE, VERSION, SHA)

    def test_exact_registry_version_is_verified(self):
        contents = archive()
        response = {"version": {"crate": CRATE, "num": VERSION, "yanked": False,
                                "checksum": hashlib.sha256(contents).hexdigest()}}
        with patch.object(publish, "request_bytes", side_effect=[json.dumps(response).encode(), contents]) as request:
            self.assertTrue(publish.published_from(CRATE, VERSION, SHA))
            self.assertEqual(request.call_args_list[0].args[0], f"{publish.REGISTRY}/{CRATE}/{VERSION}")

    def test_only_404_means_absent(self):
        for status in (404, 403, 429, 503):
            with self.subTest(status=status), patch.object(
                publish, "request_bytes", side_effect=HTTPError("url", status, "error", {}, None)
            ):
                if status == 404:
                    self.assertFalse(publish.published_from(CRATE, VERSION, SHA))
                else:
                    with self.assertRaises(HTTPError):
                        publish.published_from(CRATE, VERSION, SHA)

    def test_wrong_or_yanked_registry_version_is_rejected(self):
        for changes in ({"crate": "other"}, {"num": "0.5.3"}, {"yanked": True}):
            version = {"crate": CRATE, "num": VERSION, "yanked": False, **changes}
            with self.subTest(changes=changes), patch.object(
                publish, "request_bytes", return_value=json.dumps({"version": version}).encode()
            ), self.assertRaisesRegex(ValueError, "mismatched or yanked"):
                publish.published_from(CRATE, VERSION, SHA)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        output = patch("sys.stdout", new_callable=io.StringIO)
        output.start()
        self.addCleanup(output.stop)
        for name in ("verify_source", "published_from"):
            mock = patch.object(publish, name)
            setattr(self, name, mock.start())
            self.addCleanup(mock.stop)
        child = patch.object(publish.subprocess, "run")
        self.child = child.start()
        self.addCleanup(child.stop)
        sleeper = patch.object(publish.time, "sleep")
        self.sleep = sleeper.start()
        self.addCleanup(sleeper.stop)
        self.published_from.return_value = False

    def test_file_exists_error_is_not_registry_success(self):
        self.child.return_value = subprocess.CompletedProcess([], 101,
            "error: Cannot create a file when that file already exists. (os error 183)")
        self.assertEqual(publish.publish(CRATE, VERSION, SHA, Path.cwd()), 101)
        self.child.assert_called_once()
        self.sleep.assert_not_called()

    def test_conflict_without_registry_version_fails(self):
        self.child.return_value = subprocess.CompletedProcess([], 101, "status 409")
        self.assertEqual(publish.publish(CRATE, VERSION, SHA, Path.cwd()), 101)

    def test_verified_existing_version_never_uploads(self):
        self.published_from.return_value = True
        self.assertEqual(publish.publish(CRATE, VERSION, SHA, Path.cwd()), 0)
        self.child.assert_not_called()

    def test_partial_release_mismatch_is_found_before_uploading_missing_crates(self):
        self.published_from.side_effect = [False, True, ValueError("different source")]
        with self.assertRaisesRegex(ValueError, "different source"):
            publish.verify_existing_release(VERSION, SHA, Path.cwd())
        self.child.assert_not_called()

    def test_preflight_checks_all_six_packages_without_uploading(self):
        publish.verify_existing_release(VERSION, SHA, Path.cwd())
        self.assertEqual({call.args[0] for call in self.published_from.call_args_list}, release_source.PACKAGES)
        self.child.assert_not_called()

    def test_different_published_source_never_uploads(self):
        self.published_from.side_effect = ValueError("different source")
        with self.assertRaisesRegex(ValueError, "different source"):
            publish.publish(CRATE, VERSION, SHA, Path.cwd())
        self.child.assert_not_called()

    def test_source_guard_precedes_registry_and_upload(self):
        self.verify_source.side_effect = ValueError("dirty source")
        with self.assertRaises(ValueError):
            publish.publish(CRATE, VERSION, SHA, Path.cwd())
        self.child.assert_not_called()
        self.published_from.assert_not_called()

    def test_acknowledgement_loss_can_be_verified(self):
        self.child.return_value = subprocess.CompletedProcess([], 101, "connection interrupted")
        self.published_from.side_effect = [False, True]
        self.assertEqual(publish.publish(CRATE, VERSION, SHA, Path.cwd()), 0)

    def test_success_without_visible_version_is_not_claimed(self):
        self.child.return_value = subprocess.CompletedProcess([], 0, "uploaded")
        with self.assertRaisesRegex(ValueError, "not visible"):
            publish.publish(CRATE, VERSION, SHA, Path.cwd())

    def test_rate_limit_has_finite_retries(self):
        self.child.return_value = subprocess.CompletedProcess([], 101, "HTTP status 429")
        self.assertEqual(publish.publish(CRATE, VERSION, SHA, Path.cwd()), 101)
        self.assertEqual(self.child.call_count, 3)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], [60, 120])


if __name__ == "__main__":
    unittest.main()
