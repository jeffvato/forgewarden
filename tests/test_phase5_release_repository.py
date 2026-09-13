import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from jsonschema import Draft202012Validator, ValidationError

import swarm.phase5_release_repository as repository_module
from swarm.phase5_release_candidate import build_release_candidate
from swarm.phase5_release_provenance import build_release_provenance
from swarm.phase5_release_repository import (
    _ALLOWED_GIT,
    _GitRunner,
    _load_policy,
    build_release_repository,
    encode_release_provenance,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase5ReleaseRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        cls.export_policy = yaml.safe_load(
            (ROOT / "config/phase5-public-export.yaml").read_text(encoding="utf-8"))

    def candidate(
        self, parent: Path, track: str, name: str | None = None,
    ) -> tuple[Path, str, str]:
        candidate = parent / (name or (track.lower() + "-candidate"))
        build_release_candidate(
            ROOT, candidate, track=track, expected_source_commit=self.head)
        manifest_path = candidate / self.export_policy["manifest_name"]
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        provenance = build_release_provenance(
            candidate,
            expected_track=track,
            expected_source_commit=self.head,
            expected_manifest_sha256=manifest_sha256,
        )
        provenance_sha256 = hashlib.sha256(
            encode_release_provenance(provenance)).hexdigest()
        return candidate, manifest_sha256, provenance_sha256

    def build(self, parent: Path, track: str, name: str = "repository"):
        candidate, manifest_sha256, provenance_sha256 = self.candidate(
            parent, track, name + "-candidate")
        destination = parent / name
        result = build_release_repository(
            candidate,
            destination,
            expected_track=track,
            expected_source_commit=self.head,
            expected_manifest_sha256=manifest_sha256,
            expected_provenance_sha256=provenance_sha256,
        )
        return candidate, destination, result

    def git(self, repository: Path, *args: str, check: bool = True):
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            capture_output=True, text=True, check=check,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
        )

    def test_policy_is_exact_local_and_fail_closed(self):
        policy = _load_policy()
        schema = json.loads(
            (ROOT / "schemas/phase5-release-repository.schema.json").read_text(
                encoding="utf-8"))
        Draft202012Validator(schema).validate(policy)
        self.assertEqual(policy["publication"], "DISABLED")
        self.assertEqual(policy["branch"], "main")
        self.assertEqual(policy["object_format"], "sha1")
        self.assertEqual(policy["license_concluded"], "NOASSERTION")
        self.assertEqual(policy["legal_status"], "PENDING")
        self.assertFalse(policy["production_ready"])

    def test_both_real_tracks_are_single_root_commit_and_reproducible(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-") as temp:
            parent = Path(temp)
            for track in ("PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO"):
                with self.subTest(track=track):
                    candidate, first_repo, first = self.build(
                        parent, track, track.lower() + "-first")
                    _, second_repo, second = self.build(
                        parent, track, track.lower() + "-second")
                    self.assertEqual(first["root_commit_sha1"], second["root_commit_sha1"])
                    self.assertEqual(first["tree_sha1"], second["tree_sha1"])
                    self.assertEqual(first["source_binding_sha256"],
                                     second["source_binding_sha256"])
                    self.assertEqual(first["publication"], "DISABLED")
                    self.assertFalse(first["production_ready"])
                    self.assertTrue(all(value is False for value in first["safety"].values()))
                    self.assertEqual(
                        self.git(first_repo, "rev-list", "--all", "--count").stdout.strip(),
                        "1",
                    )
                    root_line = self.git(
                        first_repo, "rev-list", "--parents", "--max-count=1", "HEAD",
                    ).stdout.split()
                    self.assertEqual(root_line, [first["root_commit_sha1"]])
                    self.assertEqual(
                        self.git(first_repo, "symbolic-ref", "--short", "HEAD").stdout.strip(),
                        "main",
                    )
                    refs = self.git(
                        first_repo, "for-each-ref", "--format=%(refname)",
                    ).stdout.splitlines()
                    self.assertEqual(refs, ["refs/heads/main"])
                    self.assertEqual(self.git(first_repo, "remote").stdout, "")
                    self.assertFalse((first_repo / ".git" / "hooks").exists())
                    self.assertFalse(
                        (first_repo / ".git" / "objects" / "info" / "alternates").exists())
                    self.assertEqual(
                        (first_repo / self.export_policy["manifest_name"]).read_bytes(),
                        (candidate / self.export_policy["manifest_name"]).read_bytes(),
                    )
                    self.assertTrue((first_repo / "FORGEWARDEN-PROVENANCE.json").is_file())
                    grep = self.git(
                        first_repo, "grep", "-F", self.head, "HEAD", check=False)
                    self.assertEqual(grep.returncode, 1)
                    commit_text = self.git(first_repo, "cat-file", "-p", "HEAD").stdout
                    self.assertIn("ForgeWarden Release Controller", commit_text)
                    self.assertIn("release-controller@forgewarden.invalid", commit_text)
                    self.assertNotIn(self.head, commit_text)

    def test_exact_track_manifest_and_provenance_bindings_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-binding-") as temp:
            parent = Path(temp)
            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "PUBLIC_SDK")
            cases = (
                {"expected_track": "SOURCE_AVAILABLE_DEMO"},
                {"expected_manifest_sha256": "0" * 64},
                {"expected_provenance_sha256": "0" * 64},
                {"expected_source_commit": "0" * 40},
            )
            for index, changes in enumerate(cases):
                destination = parent / f"denied-{index}"
                values = {
                    "expected_track": "PUBLIC_SDK",
                    "expected_source_commit": self.head,
                    "expected_manifest_sha256": manifest_sha256,
                    "expected_provenance_sha256": provenance_sha256,
                    **changes,
                }
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    build_release_repository(candidate, destination, **values)
                self.assertFalse(destination.exists())

    def test_existing_destination_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-existing-") as temp:
            parent = Path(temp)
            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "PUBLIC_SDK")
            destination = parent / "existing"
            destination.mkdir()
            marker = destination / "keep"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                build_release_repository(
                    candidate,
                    destination,
                    expected_track="PUBLIC_SDK",
                    expected_source_commit=self.head,
                    expected_manifest_sha256=manifest_sha256,
                    expected_provenance_sha256=provenance_sha256,
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_tamper_extra_and_link_inputs_fail_before_repository_creation(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-input-") as temp:
            parent = Path(temp)
            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "PUBLIC_SDK")
            (candidate / "docs/add-on-sdk.md").write_text("tampered\n", encoding="utf-8")
            destination = parent / "tampered-output"
            with self.assertRaises(ValueError):
                build_release_repository(
                    candidate, destination,
                    expected_track="PUBLIC_SDK",
                    expected_source_commit=self.head,
                    expected_manifest_sha256=manifest_sha256,
                    expected_provenance_sha256=provenance_sha256)
            self.assertFalse(destination.exists())

            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "SOURCE_AVAILABLE_DEMO")
            (candidate / "extra.txt").write_text("extra\n", encoding="utf-8")
            destination = parent / "extra-output"
            with self.assertRaises(ValueError):
                build_release_repository(
                    candidate, destination,
                    expected_track="SOURCE_AVAILABLE_DEMO",
                    expected_source_commit=self.head,
                    expected_manifest_sha256=manifest_sha256,
                    expected_provenance_sha256=provenance_sha256)
            self.assertFalse(destination.exists())

        with tempfile.TemporaryDirectory(prefix="phase5-repository-link-") as temp:
            parent = Path(temp)
            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "PUBLIC_SDK")
            target = candidate / "docs/add-on-sdk.md"
            target.unlink()
            target.symlink_to(candidate / "schemas/addon-manifest.schema.json")
            destination = parent / "link-output"
            with self.assertRaises(ValueError):
                build_release_repository(
                    candidate, destination,
                    expected_track="PUBLIC_SDK",
                    expected_source_commit=self.head,
                    expected_manifest_sha256=manifest_sha256,
                    expected_provenance_sha256=provenance_sha256)
            self.assertFalse(destination.exists())

    def test_partial_git_failure_removes_the_destination(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-cleanup-") as temp:
            parent = Path(temp)
            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "PUBLIC_SDK")
            destination = parent / "failed"
            original = _GitRunner.run

            def fail_after_init(runner, args, **kwargs):
                if args[0] == "add":
                    raise ValueError("simulated bounded Git failure")
                return original(runner, args, **kwargs)

            with mock.patch.object(_GitRunner, "run", fail_after_init):
                with self.assertRaisesRegex(ValueError, "simulated"):
                    build_release_repository(
                        candidate, destination,
                        expected_track="PUBLIC_SDK",
                        expected_source_commit=self.head,
                        expected_manifest_sha256=manifest_sha256,
                        expected_provenance_sha256=provenance_sha256)
            self.assertFalse(destination.exists())

    def test_environment_identity_and_global_config_are_ignored(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-env-") as temp:
            parent = Path(temp)
            global_config = parent / "global.gitconfig"
            global_config.write_text(
                "[user]\n\tname = Personal Identity\n"
                "\temail = personal@example.invalid\n"
                "[credential]\n\thelper = store\n",
                encoding="utf-8",
            )
            environment = {
                "GIT_AUTHOR_NAME": "Personal Identity",
                "GIT_AUTHOR_EMAIL": "personal@example.invalid",
                "GIT_CONFIG_GLOBAL": str(global_config),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "user.name",
                "GIT_CONFIG_VALUE_0": "Injected Identity",
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                _, repository, _ = self.build(parent, "PUBLIC_SDK")
            commit_text = self.git(repository, "cat-file", "-p", "HEAD").stdout
            self.assertNotIn("Personal Identity", commit_text)
            self.assertNotIn("personal@example.invalid", commit_text)
            self.assertNotIn("Injected Identity", commit_text)
            self.assertIn("ForgeWarden Release Controller", commit_text)
            config = self.git(repository, "config", "--local", "--list").stdout
            self.assertNotIn("user.", config)
            self.assertNotIn("credential.", config)

    def test_file_and_git_budgets_fail_closed_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="phase5-repository-budget-") as temp:
            parent = Path(temp)
            candidate, manifest_sha256, provenance_sha256 = self.candidate(
                parent, "PUBLIC_SDK")
            policy = _load_policy()
            policy["limits"]["max_files"] = 1
            destination = parent / "file-budget"
            with mock.patch.object(repository_module, "_load_policy", return_value=policy):
                with self.assertRaisesRegex(ValueError, "file-count|output budget"):
                    build_release_repository(
                        candidate, destination,
                        expected_track="PUBLIC_SDK",
                        expected_source_commit=self.head,
                        expected_manifest_sha256=manifest_sha256,
                        expected_provenance_sha256=provenance_sha256)
            self.assertFalse(destination.exists())

            policy = _load_policy()
            policy["limits"]["max_git_commands"] = 1
            destination = parent / "git-budget"
            with mock.patch.object(repository_module, "_load_policy", return_value=policy):
                with self.assertRaisesRegex(ValueError, "Git-command budget"):
                    build_release_repository(
                        candidate, destination,
                        expected_track="PUBLIC_SDK",
                        expected_source_commit=self.head,
                        expected_manifest_sha256=manifest_sha256,
                        expected_provenance_sha256=provenance_sha256)
            self.assertFalse(destination.exists())

    def test_policy_drift_and_non_allowlisted_git_operations_fail_closed(self):
        policy = yaml.safe_load(
            (ROOT / "config/phase5-release-repository.yaml").read_text(
                encoding="utf-8"))
        policy["publication"] = "ENABLED"
        with tempfile.TemporaryDirectory(prefix="phase5-repository-policy-") as temp:
            changed = Path(temp) / "policy.yaml"
            changed.write_text(yaml.safe_dump(policy), encoding="utf-8")
            with mock.patch.object(repository_module, "_POLICY", changed):
                with self.assertRaises(ValidationError):
                    _load_policy()
        self.assertTrue({"clone", "fetch", "pull", "push", "credential"}.isdisjoint(
            _ALLOWED_GIT))
        with tempfile.TemporaryDirectory(prefix="phase5-repository-git-") as temp:
            runner = _GitRunner(Path(temp), _load_policy())
            with self.assertRaisesRegex(ValueError, "not allowlisted"):
                runner.run(["push"])

    def test_implementation_has_no_network_provider_or_publication_executor(self):
        source = (ROOT / "swarm/phase5_release_repository.py").read_text(
            encoding="utf-8")
        for forbidden in (
            "requests.", "urllib.", "socket.", "create_remote", "api_key",
            "access_token", "az login", "gh repo", "package upload",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
