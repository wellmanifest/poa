"""Hardening tests for POA v1/v2 file bounds, finite JSON, URI segments, and ticket DAGs."""

from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from standard import conformance as poa
from standard import poa_primitives as pr
from standard import ticket_queue as tq
from standard import ticket_queue_conformance as tqc


class PoaHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = poa.Contracts()
        self.contracts.validate_integrity()
        self.plan = poa.compile_example_plan(
            self.contracts, poa.example_process(), poa.example_request()
        )
        self.seed = tq.load_seed()

    def test_read_regular_utf8_rejects_symlinks_directories_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "payload.json"
            target.write_text('{"ok": true}', encoding="utf-8")
            self.assertEqual(pr.load_strict_json(target), {"ok": True})

            with self.assertRaises(pr.ContractError):
                pr.read_regular_utf8(root)
            with self.assertRaises(pr.ContractError):
                pr.read_regular_utf8(target, max_bytes=4)

            if hasattr(os, "O_NOFOLLOW"):
                link = root / "link.json"
                link.symlink_to(target)
                with self.assertRaises(pr.ContractError):
                    pr.read_regular_utf8(link)

    def test_strict_loads_and_canonical_reject_non_finite_and_excess_depth(self) -> None:
        for bad_raw in (
            '{"x": NaN}',
            '{"x": Infinity}',
            '{"x": -Infinity}',
            '{"x": 1e999}',
            '{"x": -1e999}',
            ("[" * 66) + "0" + ("]" * 66),
        ):
            with self.subTest(bad_raw=bad_raw[:24]):
                with self.assertRaises(pr.ContractError):
                    pr.strict_loads(bad_raw)

        for bad_val in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(pr.ContractError):
                pr.canonical({"x": bad_val})

        nested: object = 0
        for _ in range(66):
            nested = [nested]
        with self.assertRaises(pr.ContractError):
            pr.canonical(nested)

    def test_uri_traversal_and_schema_max_length_rejected(self) -> None:
        for bad_ref in (
            "artifact://example.test/inputs/../escape/r1",
            "artifact://example.test/inputs/./escape/r1",
            "artifact://example.test/inputs//escape/r1",
            "artifact://example.test/" + ("a" * 320) + "/r1",
        ):
            req = copy.deepcopy(poa.example_request())
            req["input_ref"] = bad_ref
            with self.assertRaises(poa.ContractError):
                poa.validate_request(self.contracts, req)

        env = copy.deepcopy(poa.example_execution_envelope(self.plan))
        env["grant_ref"] = "grant:" + ("g" * 160)
        with self.assertRaises(poa.ContractError):
            poa.validate_execution_envelope(self.contracts, env)

    def test_unhashable_enums_and_keys_raise_contract_errors(self) -> None:
        with self.assertRaises(pr.ContractError):
            pr.exact_fields({1: "x"}, {"a"})  # type: ignore[arg-type]
        with self.assertRaises(pr.QueueContractError):
            pr.exact_queue({1: "x"}, {"a"})  # type: ignore[arg-type]

        proc = copy.deepcopy(poa.example_process())
        proc["steps"][0]["kind"] = ["query"]
        with self.assertRaises(poa.ContractError):
            poa.validate_process(self.contracts, proc)

        receipt = poa.example_receipt(self.plan)
        receipt["state"] = ["succeeded"]
        with self.assertRaises(poa.ContractError):
            poa.validate_receipt(self.contracts, receipt)

        event = poa.example_event(self.plan)
        event["event_type"] = {"bad": 1}
        with self.assertRaises(poa.ContractError):
            poa.validate_event(self.contracts, event)

        queue = tq.TicketQueue(copy.deepcopy(self.seed))
        bad_task = tqc._task(
            "poa.tkt.control-origin-unify", "observe-worktree-5552b4a", "ops.auth"
        )
        bad_task["process_step_id"] = ["unhashable"]
        with self.assertRaises(tq.QueueContractError) as step_err:
            queue.enqueue_task(bad_task)
        self.assertEqual(step_err.exception.code, "POA-QUEUE-005")

        bad_status = tqc._task(
            "poa.tkt.control-origin-unify", "observe-worktree-5552b4a", "ops.auth"
        )
        bad_status["status"] = "unknown"
        with self.assertRaises(tq.QueueContractError) as status_err:
            queue.enqueue_task(bad_status)
        self.assertEqual(status_err.exception.code, "POA-QUEUE-001")

    def test_schedule_ticket_rejects_self_dependency_and_cycles_atomically(self) -> None:
        queue = tq.TicketQueue(copy.deepcopy(self.seed))
        sched = {
            "schema": "poa.scheduled-ticket/v1",
            "ticket_id": "poa.tkt.mailpit",
            "not_before": "2026-08-16T16:00:00+02:00",
            "timezone": "Europe/Warsaw",
            "local_hour": 16,
            "rrule": "",
            "trigger": "clock",
        }
        before_deps = len(queue.dependencies)

        with self.assertRaises(tq.QueueContractError) as self_err:
            queue.schedule_ticket(
                sched,
                [
                    {
                        "schema": "poa.ticket-dependency/v1",
                        "from_ticket_id": "poa.tkt.mailpit",
                        "to_ticket_id": "poa.tkt.mailpit",
                        "type": "happens-after",
                    }
                ],
            )
        self.assertEqual(self_err.exception.code, "POA-SCHED-002")
        self.assertNotIn("poa.tkt.mailpit", queue.schedules)
        self.assertEqual(len(queue.dependencies), before_deps)

        # Seed already contains control-origin-unify -> saas-access-request; reverse edge cycles.
        with self.assertRaises(tq.QueueContractError) as cycle_err:
            queue.schedule_ticket(
                sched,
                [
                    {
                        "schema": "poa.ticket-dependency/v1",
                        "from_ticket_id": "poa.tkt.saas-access-request",
                        "to_ticket_id": "poa.tkt.control-origin-unify",
                        "type": "happens-after",
                    }
                ],
            )
        self.assertEqual(cycle_err.exception.code, "POA-SCHED-002")
        self.assertNotIn("poa.tkt.mailpit", queue.schedules)
        self.assertEqual(len(queue.dependencies), before_deps)


if __name__ == "__main__":
    unittest.main()
