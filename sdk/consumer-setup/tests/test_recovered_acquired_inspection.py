"""Recovered archive research retains read-only owner and process boundaries."""
import copy
import unittest
from unittest.mock import patch

import test_acquisition_recovery as recovery
from test_acquired_inspection import InspectionFixture
from test_selected_setup import adapter, backend


class RecoveryFixture(InspectionFixture):
    def recovery(self, case, original, **changes):
        profile = case.root / "selected.json"
        return recovery.AcquisitionRecoveryTests.recovered(self, original,
            **{"allow_acquired_inspection": True,
               "selected_install_profile": profile,
               "selected_install_profile_sha256": backend.digest(profile.read_bytes()),
               **changes})


class RecoveredInspectionTests(RecoveryFixture, unittest.TestCase):
    def test_explicit_recovered_python_and_node_read_exact_members(self):
        for kind in ("python", "node"):
            with self.subTest(kind=kind):
                case, original, request = self.acquired(kind)
                original.close_admission()
                original.join()
                before = recovery.inventory(original.workspace), recovery.inventory(case.staging)
                current = self.recovery(case, original)
                historical = copy.deepcopy(current.job)
                observation = current.reconcile({"job_id": request["job_id"]})["observation"]
                self.assertEqual(observation["status"], "matched")
                result = current.inspect_acquired(request)
                self.assertEqual(result["archive_sha256"], observation["result"]["primary"]["sha256"])
                member = next(row for row in result["members"]
                              if row["path"].endswith("METADATA" if kind == "python" else "package.json"))
                read = current.inspect_acquired({"job_id": request["job_id"],
                    "receipt_sha256": request["receipt_sha256"], "member": member["path"], "offset": 0})
                self.assertEqual(read["member_sha256"], member["sha256"])
                self.assertTrue(read["text"])
                self.assertEqual(current.job, historical)
                self.assertEqual(current.job["status"], "unconfirmed")
                self.assertIsNone(getattr(current, kind + "_acquisition"))
                self.assertIsNone(current.node)
                self.assertIsNone(current.npm_cli)
                self.assertEqual(before, (recovery.inventory(original.workspace), recovery.inventory(case.staging)))

    def test_missing_optin_profile_and_observation_never_enter_worker(self):
        case, original, request = self.acquired()
        disabled = recovery.AcquisitionRecoveryTests.recovered(self, original, suffix="disabled")
        self.assertFalse(disabled.allow_acquired_inspection)
        with self.assertRaisesRegex(backend.SetupError, "invalid_acquired_inspection_scope"):
            recovery.AcquisitionRecoveryTests.recovered(self, original, suffix="no-profile",
                                                       allow_acquired_inspection=True)
        current = self.recovery(case, original)
        for controller in (disabled, current):
            with patch.object(controller.runner, "run_compose", side_effect=AssertionError("worker entered")) as run:
                with self.assertRaisesRegex(backend.SetupError, "acquired_inspection_unavailable"):
                    controller.inspect_acquired(request)
                # A success label is not retained file evidence.
                controller.job["status"] = "succeeded"
                with self.assertRaisesRegex(backend.SetupError, "acquired_inspection_unavailable"):
                    controller.inspect_acquired(request)
                run.assert_not_called()

    def test_stale_matched_observation_rechecks_all_retained_inputs(self):
        for selected in ("archive", "receipt", "dependency", "request", "retained-installer"):
            with self.subTest(selected=selected):
                case, original, request = self.acquired()
                current = self.recovery(case, original)
                self.assertEqual(current.reconcile({"job_id": request["job_id"]})["observation"]["status"], "matched")
                stage = case.staging / request["job_id"]
                inputs = {"archive": stage / "artifact.whl", "receipt": stage / "acquisition.json",
                          "request": original.workspace / "requests" / (request["job_id"] + ".json"),
                          "dependency": next((stage / "closure").rglob("*.whl")),
                          "retained-installer": original.python_acquisition.assets / "installer.py"}
                path = inputs[selected]
                # The fixture host owns these retained files, even when read-only.
                path.chmod(0o600)
                path.write_bytes(path.read_bytes() + b"changed")
                with patch.object(current.runner, "run_compose", side_effect=AssertionError("worker entered")) as run:
                    with self.assertRaisesRegex(backend.SetupError, "acquired_inspection_unavailable"):
                        current.inspect_acquired(request)
                    run.assert_not_called()

    def test_current_worker_installer_and_python_are_rechecked(self):
        for selected in ("worker", "installer", "python"):
            with self.subTest(selected=selected):
                case, original, request = self.acquired()
                current = self.recovery(case, original)
                current.reconcile({"job_id": request["job_id"]})
                if selected == "python":
                    path = case.root / "current-python"
                    path.write_bytes(current.acquired_inspection_python_raw)
                    current.python = str(path)
                else:
                    path = current.workspace / ("acquired-inspection.py" if selected == "worker"
                                                 else "selected-tools/installer.py")
                path.write_bytes(path.read_bytes() + b"changed")
                with patch.object(current.runner, "run_compose", side_effect=AssertionError("worker entered")) as run:
                    with self.assertRaisesRegex(backend.SetupError, "acquired_inspection_unavailable"):
                        current.inspect_acquired(request)
                    run.assert_not_called()

    def test_mutation_during_read_withholds_output_and_releases_operation(self):
        case, original, request = self.acquired()
        current = self.recovery(case, original)
        current.reconcile({"job_id": request["job_id"]})
        run = current.runner.run_compose
        def changed(*args, **kwargs):
            result = run(*args, **kwargs)
            path = case.staging / request["job_id"] / "artifact.whl"
            path.write_bytes(path.read_bytes() + b"changed")
            return result
        with patch.object(current.runner, "run_compose", side_effect=changed):
            with self.assertRaisesRegex(backend.SetupError, "acquired_inspection_unavailable"):
                current.inspect_acquired(request)
        self.assertFalse(current.operation_lock.locked())
        self.assertEqual(current.job["status"], "unconfirmed")

    def test_manifest_observations_do_not_authorize_other_jobs(self):
        case, original, first = self.acquired()
        original._acquire("python", original.python_acquisition, {**case.request, "request_id": "c" * 32})
        original.join()
        self.assertEqual(original.job["status"], "succeeded")
        second = {"job_id": original.job["id"], "receipt_sha256": original.job["result"]["receipt_sha256"], "after": None}
        manifest = case.root / "recovery.json"
        manifest.write_bytes(backend.encoded({"schema_version": 1, "workspace": str(original.workspace),
            "requests": [original.jobs[r["job_id"]]["recovery_request"] for r in (first, second)]}))
        current = self.recovery(case, original, recover_workspace=None, recover_request=None,
            recover_request_sha256=None, recover_manifest=manifest,
            recover_manifest_sha256=backend.digest(manifest.read_bytes()))
        current.reconcile({"job_id": first["job_id"]})
        self.assertEqual(current.inspect_acquired(first)["job_id"], first["job_id"])
        for request in (second, {**first, "receipt_sha256": second["receipt_sha256"]},
                        {**first, "job_id": "0" * 32}):
            with self.assertRaisesRegex(backend.SetupError, "acquired_inspection_unavailable"):
                current.inspect_acquired(request)
        current.reconcile({"job_id": second["job_id"]})
        self.assertEqual(current.inspect_acquired(second)["job_id"], second["job_id"])
        self.assertTrue(all(job["status"] == "unconfirmed" for job in current.jobs.values()))


class RecoveredMcpTests(RecoveryFixture, unittest.IsolatedAsyncioTestCase):
    async def test_only_opted_in_read_added_to_recovery_mcp(self):
        from mcp import Client
        case, original, request = self.acquired("node")
        current = self.recovery(case, original)
        owner = adapter.SetupAdapter(current)
        try:
            async with Client(adapter.create_server(owner)) as client:
                self.assertEqual({tool.name for tool in (await client.list_tools()).tools},
                                 {"setup_recovery_manifest", "setup_state", "setup_reconcile", "setup_inspect_acquired"})
                self.assertTrue((await client.call_tool("setup_inspect_acquired", request)).is_error)
                checked = await client.call_tool("setup_reconcile", {"job_id": request["job_id"]})
                self.assertFalse(checked.is_error)
                result = await client.call_tool("setup_inspect_acquired", request)
                self.assertFalse(result.is_error, result)
                self.assertEqual(result.structured_content["job_id"], request["job_id"])
                self.assertTrue((await client.call_tool("setup_selected_install", {})).is_error)
                with self.assertRaisesRegex(backend.SetupError, "recovery_read_only"):
                    current.admit_setup()
                self.assertEqual(current.job["status"], "unconfirmed")
        finally:
            await owner.aclose()


if __name__ == "__main__":
    unittest.main()
