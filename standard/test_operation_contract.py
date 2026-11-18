"""Tests for the POA operation contract v1 (HEY-04)."""

from __future__ import annotations

import unittest
from copy import deepcopy

from standard import conformance as poa
from standard import operation_contract as oc

try:
    import jsonschema
except ImportError:  # the standard itself stays dependency-free
    jsonschema = None


class OperationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = oc.validate_schema_integrity()
        self.declared, self.generated = oc.example_operations()

    def test_examples_validate_and_digest_is_stable(self) -> None:
        for example in (self.declared, self.generated):
            self.assertIs(oc.validate_operation(example), example)
            self.assertEqual(oc.operation_sha256(example), oc.operation_sha256(deepcopy(example)))
        self.assertNotEqual(oc.operation_sha256(self.declared), oc.operation_sha256(self.generated))

    def test_every_adversarial_mutation_is_rejected(self) -> None:
        report = oc.run_operation_conformance()
        self.assertEqual(report["adversarial_rejections"], len(oc.ADVERSARIAL))

    def test_semantic_rules(self) -> None:
        destructive = deepcopy(self.declared)
        destructive["effects"] = ["destructive"]
        with self.assertRaisesRegex(oc.ContractError, "high risk"):
            oc.validate_operation(destructive)
        destructive["risk"] = "high"
        oc.validate_operation(destructive)
        generated = deepcopy(self.generated)
        del generated["provenance"]["code_sha256"]
        with self.assertRaisesRegex(oc.ContractError, "generator and code digest"):
            oc.validate_operation(generated)

    def test_secret_material_is_rejected_anywhere(self) -> None:
        leaked = deepcopy(self.generated)
        leaked["input_schema"]["properties"]["text"]["description"] = "api" + "_key" + "=" + "abcd1234efgh"  # split: not a real secret
        with self.assertRaisesRegex(oc.ContractError, "secret"):
            oc.validate_operation(leaked)

    def test_schema_integrity_is_pinned(self) -> None:
        self.assertEqual(poa.digest_text(poa.canonical(self.schema)), oc.SCHEMA_DIGEST)

    def test_conformance_report_includes_operation_contract(self) -> None:
        report = poa.run_all()
        self.assertEqual(report["checks"]["operation_contract"]["adversarial_rejections"], len(oc.ADVERSARIAL))

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_json_schema_and_validator_agree(self) -> None:
        validator = jsonschema.Draft202012Validator(self.schema, format_checker=jsonschema.FormatChecker())
        for example in oc.example_operations():
            validator.validate(example)
        semantic_only = {("effects",), ("provenance", "code_sha256"), ("provenance", "generated_by"),
                         ("summary",), ("provenance", "recorded_at"), ("version",)}
        for index, path, value in oc.ADVERSARIAL:
            mutated = oc._mutated(oc.example_operations()[index], path, value)
            if path in semantic_only and validator.is_valid(mutated):
                continue  # secret scanning, semantics, bool-vs-int and dates are validator-only rules
            self.assertFalse(validator.is_valid(mutated), path)


if __name__ == "__main__":
    unittest.main()
