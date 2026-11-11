"""Pytest/unittest conformance suite for POA v1 and v2 validators."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from standard import conformance as poa  # noqa: E402
from standard import poa_primitives as pr  # noqa: E402
from standard import ticket_queue as tq  # noqa: E402
from standard import ticket_queue_conformance as tqc  # noqa: E402


class PoaConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = poa.Contracts()
        self.contracts.validate_integrity()
        self.plan = poa.compile_example_plan(
            self.contracts, poa.example_process(), poa.example_request()
        )
        self.seed = tq.load_seed()

    def test_run_all_and_ticket_queue_conformance(self) -> None:
        report = poa.run_all()
        self.assertTrue(report["ok"])
        self.assertEqual(report["schema"], "poa.conformance-report/v1")
        self.assertGreaterEqual(report["checks"]["adversarial_rejections"], 25)
        queue_report = report["checks"]["ticket_queue"]
        self.assertTrue(queue_report["ok"])
        self.assertGreaterEqual(queue_report["adversarial_rejections"], 12)
        self.assertEqual(queue_report["queue_admission"]["state"], "running")

    def test_strict_loads_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(pr.ContractError):
            pr.strict_loads('{"schema":"poa.request/v1","schema":"poa.request/v1"}')

    def test_bool_rejected_for_numeric_fields_in_v1_and_v2(self) -> None:
        env = copy.deepcopy(poa.example_execution_envelope(self.plan))
        env["timeout_seconds"] = True
        with self.assertRaises(poa.ContractError):
            poa.validate_execution_envelope(self.contracts, env)

        queue = tq.TicketQueue(copy.deepcopy(self.seed))
        bad_qplan = tqc._queue_plan(
            "poa.tkt.control-origin-unify",
            1,
            "qplan.bool",
            authority_ref="authority:subactor-validator",
        )
        bad_qplan["queue_revision"] = True
        with self.assertRaises(tq.QueueContractError):
            queue.propose_process_queue(bad_qplan)

    def test_unhashable_list_items_and_non_string_queue_inputs_raise_contract_errors(self) -> None:
        proc = copy.deepcopy(poa.example_process())
        proc["steps"][0]["depends_on"] = [{"bad": "type"}]
        with self.assertRaises(poa.ContractError):
            poa.validate_process(self.contracts, proc)

        queue = tq.TicketQueue(copy.deepcopy(self.seed))
        bad_qplan = tqc._queue_plan(
            "poa.tkt.control-origin-unify",
            1,
            "qplan.int",
            authority_ref="authority:subactor-validator",
        )
        bad_qplan["ticket_id"] = 12345  # type: ignore[assignment]
        with self.assertRaises(tq.QueueContractError):
            queue.propose_process_queue(bad_qplan)

    def test_secret_material_and_naive_timestamps_rejected(self) -> None:
        token = "gh" + "p_" + ("A" * 26)
        req = copy.deepcopy(poa.example_request())
        req["input_ref"] = token
        with self.assertRaises(poa.ContractError) as ctx:
            poa.validate_request(self.contracts, req)
        self.assertIn("credential material", str(ctx.exception))

        obs = copy.deepcopy(poa.example_observation())
        obs["observed_at"] = "2026-08-15 10:00:00Z"
        with self.assertRaises(poa.ContractError):
            poa.validate_observation(self.contracts, obs)

    def test_cli_request_and_duplicate_key_exit_codes(self) -> None:
        valid_raw = json.dumps(poa.example_request(), sort_keys=True)
        self.assertEqual(poa.main(["--request", valid_raw]), 0)
        dup_raw = (
            '{"schema":"poa.request/v1","schema":"poa.request/v1",'
            '"operation":"inspect","process_ref":"proc.alpha"}'
        )
        self.assertEqual(poa.main(["--request", dup_raw]), 1)
        self.assertEqual(tq.main(), 0)


if __name__ == "__main__":
    unittest.main()
