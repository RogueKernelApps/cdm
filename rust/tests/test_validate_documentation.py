#!/usr/bin/env python3
"""Focused tests for release-version documentation validation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch


VALIDATOR_PATH = Path(__file__).with_name("validate_documentation.py")
SPEC = importlib.util.spec_from_file_location("validate_documentation", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def result(returncode: int, stdout: str) -> CompletedProcess[str]:
    return CompletedProcess(args=["git"], returncode=returncode, stdout=stdout, stderr="")


class DevelopmentVersionTests(unittest.TestCase):
    def check_version(self, version: str, exact_tag: str = "") -> list[str]:
        exact = result(0, f"{exact_tag}\n") if exact_tag else result(1, "")
        with patch.object(
            validator.subprocess,
            "run",
            side_effect=[result(0, "v0.1.3\nv0.1.4\n"), exact],
        ):
            errors: list[str] = []
            validator.check_development_version(version, errors)
            return errors

    def test_untagged_development_must_advance_past_highest_release(self) -> None:
        self.assertTrue(self.check_version("0.1.3"))
        self.assertTrue(self.check_version("0.1.4"))
        self.assertFalse(self.check_version("0.1.5"))

    def test_only_exact_highest_release_tag_may_equal_released_version(self) -> None:
        self.assertFalse(self.check_version("0.1.4", "v0.1.4"))
        self.assertTrue(self.check_version("0.1.3", "v0.1.4"))
        self.assertTrue(self.check_version("0.1.5", "v0.1.4"))
        self.assertTrue(self.check_version("0.1.3", "v0.1.3"))


class ProfileContractTests(unittest.TestCase):
    def test_complete_profile_contract_passes(self) -> None:
        config = '\n'.join(
            [
                '#[serde(rename = "import")]',
                'const BUNDLED_PROFILE_WARNING: &str = "warning";',
                *(f'id: "{profile}",' for profile in validator.PROFILE_IDS),
            ]
        )
        documents = {
            name: ' '.join(
                [
                    "`import`",
                    "_warning",
                    "~/.cdm/base.json",
                    "~/.cdm/profiles",
                    *validator.PROFILE_IDS,
                ]
            )
            for name in validator.PROFILE_CONTRACT_DOCUMENTS
        }
        errors: list[str] = []

        validator.check_profile_contract(
            config,
            "materialize_setup_selection_in detect_profiles dialoguer IsTerminal",
            documents,
            errors,
        )

        self.assertEqual(errors, [])

    def test_missing_profile_contract_marker_fails(self) -> None:
        errors: list[str] = []

        validator.check_profile_contract("", "", {"README.md": ""}, errors)

        self.assertTrue(errors)

    def test_legacy_profile_registry_contract_is_rejected(self) -> None:
        config = '\n'.join(
            [
                '#[serde(rename = "import")]',
                'const BUNDLED_PROFILE_WARNING: &str = "warning";',
                *(f'id: "{profile}",' for profile in validator.PROFILE_IDS),
                'setup-profiles.json',
            ]
        )
        documents = {
            name: ' '.join(
                [
                    "`import`",
                    "_warning",
                    "~/.cdm/base.json",
                    "~/.cdm/profiles",
                    *validator.PROFILE_IDS,
                ]
            )
            for name in validator.PROFILE_CONTRACT_DOCUMENTS
        }
        errors: list[str] = []

        validator.check_profile_contract(
            config,
            "materialize_setup_selection_in detect_profiles dialoguer IsTerminal",
            documents,
            errors,
        )

        self.assertTrue(any("legacy profile contract" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
