"""Hardening tests for POA v1/v2 file bounds, finite JSON, URI segments, and ticket DAGs."""

from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

                real_dir = root / "real_dir"
                real_dir.mkdir()
                nested = real_dir / "nested.json"
                nested.write_text('{"ok": true}', encoding="utf-8")
                parent_link = root / "parent_link"
                parent_link.symlink_to(real_dir)
                prev_cwd = Path.cwd()
                try:
                    os.chdir(root)
                    with self.assertRaises(pr.ContractError):
                        pr.read_regular_utf8(Path("parent_link/nested.json"))
                finally:
                    os.chdir(prev_cwd)

            real_lstat = os.lstat
            real_fstat = os.fstat

            def _swapped_fstat(fd: int) -> os.stat_result:
                orig = real_fstat(fd)
                vals = list(orig)
                vals[1] = orig.st_ino + 1
                return os.stat_result(vals)

            with (
                patch("standard.poa_primitives.os.lstat", side_effect=real_lstat),
                patch("standard.poa_primitives.os.fstat", side_effect=_swapped_fstat),
                self.assertRaises(pr.ContractError),
            ):
                pr.read_regular_utf8(target)

            for bad_max in (0, -1, True, False):
                with self.assertRaises(pr.ContractError):
                    pr.read_regular_utf8(target, max_bytes=bad_max)  # type: ignore[arg-type]

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

        for bad_colon_ref in (
            "grant:../../escape",
            "grant:foo/../bar",
            "grant:example:001\n",
        ):
            bad_env = copy.deepcopy(poa.example_execution_envelope(self.plan))
            bad_env["grant_ref"] = bad_colon_ref
            with self.assertRaises(poa.ContractError):
                poa.validate_execution_envelope(self.contracts, bad_env)

        for bad_uri in (
            "urn:example:../escape",
            "intent:foo/../bar",
            r"artifact://example.test/inputs\escape/r1",
        ):
            with self.assertRaises(pr.ContractError):
                pr.validate_safe_uri_segments(bad_uri)

        with self.assertRaises(pr.ContractError):
            pr.require_datetime("2030-01-01T00:00:00Z\n", "ts")

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

    def test_twin_plan_and_internal_process_validation(self) -> None:
        queue = tq.TicketQueue(copy.deepcopy(self.seed))
        base_twin = copy.deepcopy(self.seed["twin_plans"][0])

        with self.assertRaises(tq.QueueContractError):
            queue.plan_twin_work("not-a-dict")  # type: ignore[arg-type]

        cyclic_twin = copy.deepcopy(base_twin)
        cyclic_twin["steps"][0]["depends_on"] = ["request-otp"]
        with self.assertRaises(tq.QueueContractError) as dag_err:
            queue.plan_twin_work(cyclic_twin)
        self.assertEqual(dag_err.exception.code, "POA-DAG-001")

        bad_tz_twin = copy.deepcopy(base_twin)
        bad_tz_twin["timezone"] = "Europe/../Warsaw"
        with self.assertRaises(tq.QueueContractError) as tz_err:
            queue.plan_twin_work(bad_tz_twin)
        self.assertEqual(tz_err.exception.code, "POA-TWIN-001")

        uninspectable = copy.deepcopy(self.seed)
        for item in uninspectable["tickets"]:
            if item["ticket_id"] == base_twin["ticket_id"]:
                item["inspectable"] = False
        locked_queue = tq.TicketQueue(uninspectable)
        with self.assertRaises(tq.QueueContractError) as lock_err:
            locked_queue.plan_twin_work(base_twin)
        self.assertEqual(lock_err.exception.code, "POA-QUEUE-003")

        with self.assertRaises(tq.QueueContractError):
            queue.register_internal_process(
                {"ticket_id": "poa.tkt.custom", "queue": "ops.internal"},
                {
                    "process_ref": "poa://subactor.test/process/custom/v1",
                    "steps": [],
                },
            )

    def test_huge_int_lone_surrogates_abs_symlink_ancestors_key_scan_and_uri_segments(self) -> None:
        for bad_json in (
            '{"n": ' + ("9" * 400) + "}",
            '{"n": -' + ("9" * 400) + "}",
            '{"n": ' + ("9" * 5000) + "}",
            '{"s": "\\ud800"}',
            '{"\\udfff": 1}',
            '{"s": "\ud800"}',
        ):
            with self.subTest(sample=bad_json[:32]), self.assertRaises(pr.ContractError):
                pr.strict_loads(bad_json, parse_error=pr.ContractError("bad json"))

        with self.assertRaises(pr.ContractError):
            pr.canonical({"huge": 10**400})
        with self.assertRaises(pr.ContractError):
            pr.canonical({"bad": "sur\ud800"})
        with self.assertRaises(pr.ContractError):
            pr.digest_text("sur\ud800")

        crafted_key = "gh" + "p_" + ("A" * 24)
        with self.assertRaises(pr.ContractError):
            pr.reject_secret_material({crafted_key: "clean"})

        for bad_uri in (
            "poa://subactor.test/foo:..:bar",
            "poa://subactor.test/foo:.:bar",
            "grant:",
            "grant:.:bad",
            "grant:foo::bar",
        ):
            with self.subTest(uri=bad_uri), self.assertRaises(pr.ContractError):
                pr.validate_safe_uri_segments(bad_uri)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real_poa"
            real_dir.mkdir()
            doc = real_dir / "doc.json"
            doc.write_text('{"ok": true}\n', encoding="utf-8")
            sym_dir = root / "sym_poa"
            sym_dir.symlink_to(real_dir)
            with self.assertRaises(pr.ContractError):
                pr.read_regular_utf8(sym_dir / "doc.json")


if __name__ == "__main__":
    unittest.main()
