import copy
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

import swarm.phase5_release_ci as ci_module
from swarm.phase5_release_candidate import build_release_candidate
from swarm.phase5_release_ci import (
    _COMMANDS,
    _command_plan,
    _load_policy,
    _run_check,
    run_release_ci,
)
from swarm.phase5_release_provenance import build_release_provenance
from swarm.phase5_release_repository import (
    build_release_repository,
    encode_release_provenance,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase5ReleaseCITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        cls.export_policy = yaml.safe_load(
            (ROOT / "config/phase5-public-export.yaml").read_text(encoding="utf-8"))

    def repository(
        self, parent: Path, track: str, name: str,
    ) -> tuple[Path, dict]:
        candidate = parent / (name + "-candidate")
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
        repository = parent / name
        result = build_release_repository(
            candidate,
            repository,
            expected_track=track,
            expected_source_commit=self.head,
            expected_manifest_sha256=manifest_sha256,
            expected_provenance_sha256=provenance_sha256,
        )
        return repository, result

    def git(self, repository: Path, *args: str, input_text: str | None = None):
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            input=input_text,
            capture_output=True,
            text=True,
            check=True,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
        )

    def worktree_digests(self, repository: Path) -> dict[str, str]:
        return {
            path.relative_to(repository).as_posix(): hashlib.sha256(
                path.read_bytes()).hexdigest()
            for path in repository.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(repository).parts
        }

    def test_policy_is_exact_offline_and_fail_closed(self):
        policy = _load_policy()
        schema = json.loads(
            (ROOT / "schemas/phase5-release-ci.schema.json").read_text(
                encoding="utf-8"))
        Draft202012Validator(schema).validate(policy)
        self.assertEqual(policy["publication"], "DISABLED")
        self.assertEqual(policy["repository_format"],
                         "FORGEWARDEN_RELEASE_REPOSITORY_V1")
        self.assertEqual(policy["license_concluded"], "NOASSERTION")
        self.assertEqual(policy["legal_status"], "PENDING")
        self.assertFalse(policy["production_ready"])
        self.assertEqual(set(policy["tracks"]),
                         {"PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO"})

    def test_both_tracks_pass_deterministically_without_changing_content(self):
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-") as temp:
            parent = Path(temp)
            for track in ("PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO"):
                with self.subTest(track=track):
                    repository, release = self.repository(
                        parent, track, track.lower())
                    before = self.worktree_digests(repository)
                    first = run_release_ci(
                        repository,
                        expected_track=track,
                        expected_repository_result=release,
                    )
                    second = run_release_ci(
                        repository,
                        expected_track=track,
                        expected_repository_result=release,
                    )
                    self.assertEqual(first, second)
                    self.assertEqual(before, self.worktree_digests(repository))
                    self.assertEqual(first["publication"], "DISABLED")
                    self.assertFalse(first["production_ready"])
                    self.assertTrue(all(value is False
                                        for value in first["safety"].values()))
                    self.assertTrue(all(check["passed"] for check in first["checks"]))
                    expected_checks = {
                        item["id"] for item in _load_policy()["tracks"][track]["checks"]
                    }
                    self.assertEqual(
                        {item["check_id"] for item in first["checks"]},
                        expected_checks,
                    )
                    encoded = json.dumps(first, sort_keys=True)
                    self.assertNotIn(self.head, encoded)
                    self.assertNotIn(str(repository), encoded)

    def test_ambient_credentials_identity_path_and_proxy_are_ignored(self):
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-env-") as temp:
            parent = Path(temp)
            repository, release = self.repository(
                parent, "SOURCE_AVAILABLE_DEMO", "demo")
            baseline = run_release_ci(
                repository,
                expected_track="SOURCE_AVAILABLE_DEMO",
                expected_repository_result=release,
            )
            hostile = {
                "HOME": str(ROOT),
                "PYTHONPATH": str(ROOT),
                "PATH": str(ROOT),
                "OPENAI_API_KEY": "not-a-real-secret",
                "AZURE_CLIENT_SECRET": "not-a-real-secret",
                "HTTP_PROXY": "http://outside.invalid",
                "HTTPS_PROXY": "http://outside.invalid",
                "GIT_AUTHOR_NAME": "Personal Identity",
            }
            with mock.patch.dict(os.environ, hostile, clear=False):
                result = run_release_ci(
                    repository,
                    expected_track="SOURCE_AVAILABLE_DEMO",
                    expected_repository_result=release,
                )
            self.assertEqual(result, baseline)

    def test_repository_result_shape_binding_and_cross_track_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-result-") as temp:
            repository, release = self.repository(
                Path(temp), "PUBLIC_SDK", "sdk")
            cases = []
            missing = copy.deepcopy(release)
            missing.pop("tree_sha1")
            cases.append(missing)
            extra = copy.deepcopy(release)
            extra["source_commit"] = self.head
            cases.append(extra)
            for key, value in (
                ("track", "SOURCE_AVAILABLE_DEMO"),
                ("root_commit_sha1", "0" * 40),
                ("tree_sha1", "0" * 40),
                ("source_manifest_sha256", "0" * 64),
                ("provenance_sha256", "0" * 64),
                ("publication", "ENABLED"),
                ("production_ready", True),
                ("license_concluded", "MIT"),
            ):
                changed = copy.deepcopy(release)
                changed[key] = value
                cases.append(changed)
            changed = copy.deepcopy(release)
            changed["safety"]["network_accessed"] = True
            cases.append(changed)
            for index, changed in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    run_release_ci(
                        repository,
                        expected_track="PUBLIC_SDK",
                        expected_repository_result=changed,
                    )

    def test_symlinked_repository_root_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-link-") as temp:
            parent = Path(temp)
            repository, release = self.repository(
                parent, "PUBLIC_SDK", "sdk")
            link = parent / "repository-link"
            link.symlink_to(repository, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "real directory"):
                run_release_ci(
                    link,
                    expected_track="PUBLIC_SDK",
                    expected_repository_result=release,
                )

    def test_dirty_tree_extra_ref_and_unreachable_object_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-dirty-") as temp:
            parent = Path(temp)
            repository, release = self.repository(
                parent, "PUBLIC_SDK", "dirty")
            target = repository / "docs/add-on-sdk.md"
            target.write_text("tampered\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                run_release_ci(
                    repository,
                    expected_track="PUBLIC_SDK",
                    expected_repository_result=release,
                )

            repository, release = self.repository(
                parent, "PUBLIC_SDK", "extra-ref")
            self.git(repository, "update-ref", "refs/tags/unapproved", "HEAD")
            with self.assertRaises(ValueError):
                run_release_ci(
                    repository,
                    expected_track="PUBLIC_SDK",
                    expected_repository_result=release,
                )

            repository, release = self.repository(
                parent, "PUBLIC_SDK", "extra-object")
            self.git(repository, "hash-object", "-w", "--stdin", input_text="unreachable")
            with self.assertRaises(ValueError):
                run_release_ci(
                    repository,
                    expected_track="PUBLIC_SDK",
                    expected_repository_result=release,
                )

    def test_missing_runtime_and_command_plan_drift_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-runtime-") as temp:
            repository, release = self.repository(
                Path(temp), "PUBLIC_SDK", "sdk")
            with mock.patch.object(
                ci_module, "_runtime", side_effect=ValueError("runtime unavailable")
            ):
                with self.assertRaisesRegex(ValueError, "runtime unavailable"):
                    run_release_ci(
                        repository,
                        expected_track="PUBLIC_SDK",
                        expected_repository_result=release,
                    )
        policy = _load_policy()
        policy["tracks"]["PUBLIC_SDK"]["checks"] = []
        with self.assertRaisesRegex(ValueError, "plan is empty"):
            _command_plan("PUBLIC_SDK", policy)
        policy = _load_policy()
        policy["tracks"]["PUBLIC_SDK"]["checks"][0]["id"] = "UNKNOWN"
        with self.assertRaisesRegex(ValueError, "unknown"):
            _command_plan("PUBLIC_SDK", policy)
        policy = _load_policy()
        policy["tracks"]["PUBLIC_SDK"]["checks"][0]["runtime"] = "NODE"
        with self.assertRaisesRegex(ValueError, "runtime binding"):
            _command_plan("PUBLIC_SDK", policy)

    def test_command_failure_timeout_and_output_overflow_fail_closed(self):
        policy = _load_policy()
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-command-") as temp:
            root = Path(temp)
            completed = subprocess.CompletedProcess(
                args=[], returncode=1, stdout=b"", stderr=b"failed")
            with mock.patch.object(ci_module, "_runtime", return_value="/usr/bin/python3"):
                with mock.patch.object(ci_module.subprocess, "run", return_value=completed):
                    with self.assertRaisesRegex(ValueError, "check failed"):
                        _run_check(
                            root,
                            check_id="SDK_CONTRACT",
                            runtime="PYTHON",
                            args=_COMMANDS["SDK_CONTRACT"][1],
                            marker="SDK_CONTRACT_OK",
                            policy=policy,
                        )
                completed = subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout=b"x" * (policy["limits"]["max_output_bytes"] + 1),
                    stderr=b"",
                )
                with mock.patch.object(ci_module.subprocess, "run", return_value=completed):
                    with self.assertRaisesRegex(ValueError, "output exceeded"):
                        _run_check(
                            root,
                            check_id="SDK_CONTRACT",
                            runtime="PYTHON",
                            args=_COMMANDS["SDK_CONTRACT"][1],
                            marker="SDK_CONTRACT_OK",
                            policy=policy,
                        )
                with mock.patch.object(
                    ci_module.subprocess,
                    "run",
                    side_effect=subprocess.TimeoutExpired(["python3"], 1),
                ):
                    with self.assertRaisesRegex(ValueError, "timed out"):
                        _run_check(
                            root,
                            check_id="SDK_CONTRACT",
                            runtime="PYTHON",
                            args=_COMMANDS["SDK_CONTRACT"][1],
                            marker="SDK_CONTRACT_OK",
                            policy=policy,
                        )

    def test_policy_drift_is_rejected_by_exact_schema(self):
        policy = yaml.safe_load(
            (ROOT / "config/phase5-release-ci.yaml").read_text(encoding="utf-8"))
        policy["publication"] = "ENABLED"
        with tempfile.TemporaryDirectory(prefix="phase5-release-ci-policy-") as temp:
            changed = Path(temp) / "policy.yaml"
            changed.write_text(yaml.safe_dump(policy), encoding="utf-8")
            with mock.patch.object(ci_module, "_POLICY", changed):
                with self.assertRaises(ValidationError):
                    _load_policy()

    def test_command_surface_has_no_network_package_remote_or_private_core(self):
        rendered = json.dumps(_COMMANDS, sort_keys=True)
        for forbidden in (
            "socket.socket",
            "subprocess.run",
            "pip install",
            "npm install",
            "git ",
            "swarm.",
            "requests",
            "urllib",
            "curl ",
            "wget ",
            "fetch(",
        ):
            self.assertNotIn(forbidden, rendered)
        source = (ROOT / "swarm/phase5_release_ci.py").read_text(encoding="utf-8")
        for forbidden in (
            "requests.",
            "urllib.",
            "create_remote",
            "api_key",
            "access_token",
            "az login",
            "gh repo",
            "package upload",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
