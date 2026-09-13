import copy
import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from swarm.phase5_release_gate import build_release_assurance_gate


def facts(track: str, seed: str) -> dict:
    digest = hashlib.sha256(seed.encode()).hexdigest()
    return {"track": track, "publication": "DISABLED", "production_ready": False, "legal_status": "PENDING", "license_concluded": "NOASSERTION", "license_declared": "NOASSERTION", "source_binding_sha256": digest, "source_manifest_sha256": hashlib.sha256((seed+"m").encode()).hexdigest(), "provenance_sha256": hashlib.sha256((seed+"p").encode()).hexdigest(), "safety": {"publication_performed": False, "deployment_performed": False, "authority_granted": False, "network_accessed": False, "credential_accessed": False, "license_selected": False, "human_gate_satisfied": False}}


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.tracks = ("PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO")
        self.provenance = {}
        self.repositories = {}
        self.ci = {}
        for track in self.tracks:
            p = facts(track, track)
            r = dict(p, root_commit_sha1="1" * 40, tree_sha1="2" * 40, file_count=4)
            c = dict(p, repository_result_sha256="3" * 64, command_plan_sha256="4" * 64, checks=[{"check_id": "OK", "passed": True}])
            self.provenance[track], self.repositories[track], self.ci[track] = p, r, c
        self.history = {"schema_version": "1", "audit_kind": "EXACT_GIT_HISTORY", "publication": "DISABLED", "mutation_performed": False, "strategy": "SANITIZED_SINGLE_COMMIT", "candidate_proof_required": True, "disposition": "CANDIDATE_PROOF_REQUIRED", "blocking_finding_count": 0, "matched_values_included": False}

    def test_verified_but_human_gates_remain_blocked(self):
        result = build_release_assurance_gate(history_audit=self.history, provenance=self.provenance, repositories=self.repositories, ci=self.ci)
        self.assertEqual(result["final_disposition"], "BLOCKED_PENDING_HUMAN_GATES")
        self.assertEqual(len(result["tracks"]), 2)
        self.assertEqual(result["safety"], {key: False for key in result["safety"]})
        self.assertEqual(result, build_release_assurance_gate(history_audit=self.history, provenance=self.provenance, repositories=self.repositories, ci=self.ci))

    def test_cross_stage_and_history_denials(self):
        for field, value in (("source_manifest_sha256", "f" * 64), ("production_ready", True)):
            provenance = copy.deepcopy(self.provenance); provenance["PUBLIC_SDK"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                build_release_assurance_gate(history_audit=self.history, provenance=provenance, repositories=self.repositories, ci=self.ci)
        history = dict(self.history, blocking_finding_count=1)
        with self.assertRaises(ValueError):
            build_release_assurance_gate(history_audit=history, provenance=self.provenance, repositories=self.repositories, ci=self.ci)

    def test_rejects_secret_duplicate_track_and_stronger_output_facts(self):
        secret = copy.deepcopy(self.provenance); secret["PUBLIC_SDK"]["secret"] = "x"
        with self.assertRaises(ValueError):
            build_release_assurance_gate(history_audit=self.history, provenance=secret, repositories=self.repositories, ci=self.ci)
        duplicate = copy.deepcopy(self.provenance); duplicate["EXTRA"] = duplicate["PUBLIC_SDK"]
        with self.assertRaises(ValueError):
            build_release_assurance_gate(history_audit=self.history, provenance=duplicate, repositories=self.repositories, ci=self.ci)

    def test_schema_has_only_blocked_constants(self):
        schema = json.loads(Path(__file__).parents[1].joinpath("schemas/phase5-release-gate.schema.json").read_text())
        Draft202012Validator(schema).validate(build_release_assurance_gate(history_audit=self.history, provenance=self.provenance, repositories=self.repositories, ci=self.ci))
        with self.assertRaises(ValidationError):
            bad = build_release_assurance_gate(history_audit=self.history, provenance=self.provenance, repositories=self.repositories, ci=self.ci); bad["final_disposition"] = "PUBLISH"; Draft202012Validator(schema).validate(bad)


if __name__ == "__main__":
    unittest.main()
