import copy
import json
from pathlib import Path
from unittest import TestCase

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/phase5-release-readiness.yaml"
SCHEMA = ROOT / "schemas/phase5-release-readiness.schema.json"
NOTE = ROOT / "docs/phase5-release-readiness.md"


class Phase5ReleaseReadinessTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))

    def assert_invalid_value(self, path, value):
        candidate = copy.deepcopy(self.profile)
        target = candidate
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        self.assertTrue(list(self.validator.iter_errors(candidate)))

    def test_exact_plan_and_tracks_validate(self):
        self.validator.validate(self.profile)
        self.assertEqual((self.profile["publication"], self.profile["history_strategy"]),
                         ("DISABLED", "SANITIZED_SINGLE_COMMIT"))
        self.assertEqual(self.profile["current_repository"]["classification"], "PRIVATE_CORE")
        self.assertEqual(self.profile["public_export_repository"], {
            "creation": "NEW_REPOSITORY", "initial_history": "SINGLE_COMMIT",
            "source_references": "PROHIBITED",
        })
        self.assertEqual([item["track"] for item in self.profile["tracks"]],
                         ["PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO", "PRIVATE_CORE"])
        self.assertTrue(all(item["publication"] == "DISABLED" for item in self.profile["tracks"]))
        self.assertEqual(set(self.profile["legal_decisions"].values()), {"UNSELECTED", False})

    def test_provenance_sanitization_and_review_gates_are_explicit(self):
        expected = {
            "personal_names_removed", "cloud_resource_and_deployment_ids_removed",
            "historical_commit_ids_removed", "credential_shaped_fixtures_removed",
            "customer_tenant_and_endpoint_examples_removed",
            "unproven_asset_metadata_and_assets_removed",
        }
        self.assertLessEqual(expected, set(self.profile["required_identifier_sanitization"]))
        self.assertEqual(self.profile["public_identifier_exceptions"], [
            "CANONICAL_FORGEWARDEN_REQUIREMENT_IDS", "CANONICAL_FORGEWARDEN_SCHEMA_IDS",
            "CANONICAL_FORGEWARDEN_API_IDS", "DETERMINISTIC_FICTIONAL_DEMO_IDS",
        ])
        for key, value in (
            ("required_owner_gates", "chain_of_title_verified"),
            ("required_provenance_gates", "sbom_verified"),
            ("required_reviews", "secret_history_review"),
            ("required_approval_gates", "customer_root_release_approval_recorded"),
        ):
            self.assertIn(value, self.profile[key])

    def test_unsafe_values_and_authority_fields_fail_closed(self):
        cases = (
            (("publication",), "ENABLED"), (("history_strategy",), "PRESERVE_HISTORY"),
            (("public_export_repository", "source_references"), "ALLOWED"),
            (("current_repository", "visibility"), "PUBLIC"),
            (("tracks", 0, "includes_private_core"), True),
            (("tracks", 2, "repository_visibility"), "PUBLIC_CANDIDATE"),
            (("legal_decisions", "rights_holding_entity"), "EXAMPLE_LLC"),
            (("legal_decisions", "public_sdk_license"), "Apache-2.0"),
            (("tracks", 0, "osi_open_source_claim"), True),
            (("deployment_enabled",), True), (("credentials",), "AVAILABLE"),
            (("tracks", 0, "authority_granted"), True),
        )
        for path, value in cases:
            with self.subTest(path=path):
                self.assert_invalid_value(path, value)

    def test_missing_gate_or_expanded_exception_fails_closed(self):
        for key in ("required_owner_gates", "required_provenance_gates", "required_reviews",
                    "required_identifier_sanitization"):
            candidate = copy.deepcopy(self.profile)
            candidate[key].pop()
            self.assertTrue(list(self.validator.iter_errors(candidate)))
        candidate = copy.deepcopy(self.profile)
        candidate["public_identifier_exceptions"].append("INTERNAL_COMMIT_IDS")
        self.assertTrue(list(self.validator.iter_errors(candidate)))

    def test_documentation_does_not_authorize_release(self):
        text = NOTE.read_text(encoding="utf-8")
        for required in (
            "PUBLIC_SDK", "SOURCE_AVAILABLE_DEMO", "PRIVATE_CORE", "SANITIZED_SINGLE_COMMIT",
            "PRESERVE_HISTORY", "chain of title", "SBOM", "full-history secret audit",
            "clean-export CI", "Customer Root", "publication: DISABLED", "legal opinion",
            "new repository", "no source-history", "personal names",
            "deterministic\nfictional demo IDs",
        ):
            self.assertIn(required, text)
        self.assertIn("visibility alone grants no license", text.lower())


if __name__ == "__main__":
    import unittest
    unittest.main()
