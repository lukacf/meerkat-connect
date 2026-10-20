"""Actual Controller ownership over inert package effects; no native proof."""
import asyncio
import copy
import threading
import unittest
from unittest.mock import patch

from test_selected_setup import SelectedFixture, adapter, backend
from test_backend import FixtureMixin as CatalogFixture, backend as catalog_backend
from test_catalog_routes import entries, request as route_request, route_fixture


async def transport_call(peer, route, arguments):
    # Test-only custody injection through the actual private owner API. This
    # proves transport matching, not native permission or canonical membership.
    owner = peer._controller_owner
    index = owner._connections.index(peer)
    preparation = owner._preparation_by_validation.get(arguments.get("validation_id"))
    command = {"operation": "prepare_entry", "peer": index, "connection": "1",
               "tool": "setup_" + route.removeprefix("/api/"),
               "arguments": arguments, "preparation": preparation}
    token = owner.owner_control(command)["entry"]
    try:
        return await peer.dispatch(route, arguments, _entry=token)
    finally:
        owner.owner_control({"operation": "close_entry", "peer": index, "entry": token})
        owner.owner_control({"operation": "finish_entry", "peer": index, "entry": token})


async def transport_check(owner, peer, request):
    # Mechanical transport control only. Production releases this private
    # observation only after its actual Rust source owner commits P membership.
    pending = await transport_call(peer, "/api/selected_check", request)
    command = {"operation": "inspect_selection", "peer": owner._connections.index(peer),
               "ticket": pending["ticket"]}
    inspected = owner.owner_control(command)
    return owner.owner_control({**command, "operation": "release_selection",
                                "selection_sha256": inspected["selection_sha256"], "preparation": "f" * 64})


class SharedPreparation(SelectedFixture, unittest.IsolatedAsyncioTestCase):
    async def test_bounded_job_wait_consumes_one_exact_entry_and_peer_close_preserves_b(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        a, b, foreign = owner.open(), owner.open(), owner.open()
        request = self.stage("node")
        selected_a = await transport_check(owner, a, request)
        selected_b = await transport_check(owner, b, request)
        controller.runner.block = threading.Event()
        tasks = []
        try:
            install_a = asyncio.create_task(transport_call(a, "/api/selected_install", self.selection(selected_a)))
            tasks.append(install_a)
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            install_b = asyncio.create_task(transport_call(b, "/api/selected_install", self.selection(selected_b)))
            tasks.append(install_b)
            job = controller.validations[selected_a["validation_id"]]["job_id"]
            async with asyncio.timeout(3):
                while job not in owner._views[b]["jobs"]:
                    await asyncio.sleep(0)
            immediate = await transport_call(b, "/api/job", {"job_id": job, "wait_ms": 0})
            self.assertEqual(immediate["job"]["status"], "running")
            with self.assertRaisesRegex(backend.SetupError, "unknown_job"):
                await transport_call(foreign, "/api/job", {"job_id": job, "wait_ms": 10000})
            wait_a = asyncio.create_task(transport_call(a, "/api/job", {"job_id": job, "wait_ms": 10000}))
            wait_b = asyncio.create_task(transport_call(b, "/api/job", {"job_id": job, "wait_ms": 10000}))
            tasks.extend((wait_a, wait_b))
            async with asyncio.timeout(3):
                while not a._job_reads or not b._job_reads:
                    await asyncio.sleep(0)
            self.assertFalse(wait_a.done())
            self.assertFalse(wait_b.done())
            await asyncio.wait_for(a.aclose(), 3)
            with self.assertRaises(asyncio.CancelledError):
                await wait_a
            with self.assertRaisesRegex(backend.SetupError, "host_closing"):
                await install_a
            self.assertFalse(controller.closing)
            self.assertFalse(controller._job_controls[job]["requested"].is_set())
            self.assertTrue(controller._job_threads[job].is_alive())
            self.assertFalse(wait_b.done())
            self.assertFalse(install_b.done())
            self.assertFalse(a._job_reads)
            controller.runner.block.set()
            self.assertEqual((await asyncio.wait_for(install_b, 3))["job"]["status"], "succeeded")
            self.assertEqual((await asyncio.wait_for(wait_b, 3))["job"]["status"], "succeeded")
            self.assertEqual(len(controller.jobs), 1)
            self.assertFalse(b._job_reads)
        finally:
            controller.runner.block.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await owner.aclose()
        self.assertFalse(owner._job_waits)
        self.assertTrue(all(not thread.is_alive() for thread in controller.threads))

    async def test_completion_requires_joined_worker_and_exact_peer_then_allows_late_observation(self):
        # Physical evidence only. The private release stands for the Rust P
        # membership owner; it does not grant native admission in this control.
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, late, foreign = owner.open(), owner.open(), owner.open()
        request = self.stage("node")
        checked = await transport_check(owner, first, request)
        command = {"operation": "observe_completion", "peer": 0,
            "validation_id": checked["validation_id"], "preparation": "f" * 64}
        controller.runner.block = threading.Event()
        waiting = asyncio.create_task(transport_call(first, "/api/selected_install", self.selection(checked)))
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            self.assertEqual(owner.owner_control(command), {"completion": None})
            for changed in ({"peer": 1}, {"peer": 2}, {"preparation": "e" * 64}):
                with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                    owner.owner_control({**command, **changed})
            controller.runner.block.set()
            installed = await asyncio.wait_for(waiting, 3)
            job_id = installed["job"]["id"]
            self.assertFalse(controller._job_threads[job_id].is_alive())
            observed = owner.owner_control(command)
            completion = observed["completion"]
            self.assertEqual(completion, {"controller": owner._identity,
                "validation_id": checked["validation_id"], "job": {
                    key: controller.jobs[job_id].get(key)
                    for key in ("id", "kind", "family", "status", "result", "error")}})
            self.assertEqual(completion["job"]["status"], "succeeded")
            before = copy.deepcopy(controller.runner.calls)
            # A fresh exact check joins the existing physical selection. It
            # neither starts a second installer nor reads through a guessed ID.
            later = await transport_check(owner, late, request)
            self.assertEqual(later, checked)
            self.assertEqual(owner.owner_control({**command, "peer": 1}), observed)
            self.assertEqual(controller.runner.calls, before)
            self.assertEqual(len(controller.jobs), 1)
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                owner.owner_control({**command, "peer": 2})
            owner.owner_control({**command, "operation": "leave_preparation", "last": False})
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                owner.owner_control(command)
            self.assertEqual(owner.owner_control({**command, "peer": 1}), observed)
        finally:
            controller.runner.block.set()
            await asyncio.gather(waiting, return_exceptions=True)
            await owner.aclose()

    async def test_shared_stop_requires_owner_leave_and_a_does_not_stop_b_worker(self):
        # The private command substitutes only for the canonical Rust P owner
        # in this transport control. Native/P membership is tested separately.
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        request = self.stage("node")
        a = await transport_check(owner, first, request)
        b = await transport_check(owner, second, request)
        controller.runner.block = threading.Event()
        waiting_a = asyncio.create_task(transport_call(first, "/api/selected_install", self.selection(a)))
        waiting_b = None
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            job = controller.validations[a["validation_id"]]["job_id"]
            # B's released exact check can replay and observe this one worker.
            waiting_b = asyncio.create_task(transport_call(second, "/api/selected_install", self.selection(b)))
            async with asyncio.timeout(3):
                while job not in owner._views[second]["jobs"]:
                    await asyncio.sleep(0.01)
            stop = await transport_call(first, "/api/stop", {"job_id": job})
            self.assertEqual(stop, {"scope": "host_shared_stop_pending", "job_id": job})
            self.assertNotIn("stop", controller.jobs[job])
            self.assertFalse(controller._job_controls[job]["requested"].is_set())
            leave = owner.owner_control({"operation": "leave_preparation", "peer": 0,
                "validation_id": a["validation_id"], "preparation": "f" * 64, "last": False})
            self.assertFalse(leave["physical_stop_requested"])
            self.assertFalse(leave["worker_joined"])
            first.close_admission()
            await asyncio.wait_for(first.aclose(), 3)
            with self.assertRaisesRegex(backend.SetupError, "host_closing"):
                await asyncio.wait_for(waiting_a, 3)
            self.assertFalse(controller.closing)
            self.assertFalse(controller._job_controls[job]["requested"].is_set())
            self.assertTrue(controller._job_threads[job].is_alive())
            self.assertEqual((await transport_call(second, "/api/job", {"job_id": job}))["job"]["id"], job)
            self.assertFalse(waiting_b.done())
            controller.runner.block.set()
            self.assertEqual((await asyncio.wait_for(waiting_b, 3))["job"]["status"], "succeeded")
        finally:
            controller.runner.block.set()
            await asyncio.gather(*[task for task in (waiting_a, waiting_b) if task is not None], return_exceptions=True)
            await owner.aclose()
        self.assertFalse(owner._job_waits)
        self.assertTrue(all(not thread.is_alive() for thread in controller.threads))

    async def test_last_member_stop_retains_pending_until_actual_worker_join(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, foreign = owner.open(), owner.open()
        checked = await transport_check(owner, first, self.stage("node"))
        controller.runner.block = threading.Event()
        waiting = asyncio.create_task(transport_call(first, "/api/selected_install", self.selection(checked)))
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            job = controller.validations[checked["validation_id"]]["job_id"]
            command = {"operation": "leave_preparation", "peer": 0,
                "validation_id": checked["validation_id"], "preparation": "f" * 64, "last": True}
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                owner.owner_control({**command, "peer": 1})
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                owner.owner_control({**command, "preparation": "e" * 64})
            with patch.object(controller, "stop", wraps=controller.stop) as stopping:
                pending = owner.owner_control(command)
                self.assertTrue(pending["physical_stop_requested"])
                self.assertFalse(pending["worker_joined"])
                self.assertTrue(controller._job_threads[job].is_alive())
                self.assertEqual(owner.owner_control(command), pending)
                self.assertEqual(stopping.call_count, 1, "pending observation does not replay stop")
                with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                    await transport_call(first, "/api/selected_install", self.selection(checked))
                controller.runner.block.set()
                await asyncio.wait_for(waiting, 3)
                settled = owner.owner_control(command)
                self.assertTrue(settled["worker_joined"])
                self.assertTrue(settled["physical_stop_requested"])
                self.assertFalse(controller._job_threads[job].is_alive())
                self.assertEqual(stopping.call_count, 1)
        finally:
            controller.runner.block.set()
            await asyncio.gather(waiting, return_exceptions=True)
            await owner.aclose()

    async def test_entry_metadata_cannot_arm_replay_change_or_cross_a_peer(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        request = self.stage("node")
        try:
            for token in (None, "f" * 64):
                with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                    await first.dispatch("/api/selected_check", request, _entry=token)
            self.assertFalse(controller.validations)
            command = {"operation": "prepare_entry", "peer": 0, "connection": "17",
                       "tool": "setup_selected_check", "arguments": request, "preparation": None}
            token = owner.owner_control(command)["entry"]
            with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                owner.owner_control({**command, "connection": "18"})
            changed = {**request, "staged_id": "foreign"}
            for peer, arguments in ((second, request), (first, changed)):
                with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                    await peer.dispatch("/api/selected_check", arguments, _entry=token)
            self.assertFalse(controller.validations)
            result = await first.dispatch("/api/selected_check", request, _entry=token)
            self.assertEqual(set(result), {"scope", "ticket"})
            self.assertNotIn(token, repr(result))
            with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                await first.dispatch("/api/selected_check", request, _entry=token)
            self.assertEqual(len(controller.validations), 1)
            self.assertEqual(owner.owner_control({"operation": "finish_entry", "peer": 0,
                                                 "entry": token}), {"decision": "entered"})
            token = owner.owner_control(command)["entry"]
            self.assertEqual(owner.owner_control({"operation": "close_entry", "peer": 0,
                                                 "entry": token}), {"decision": "not_entered"})
            with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                await first.dispatch("/api/selected_check", request, _entry=token)
            self.assertEqual(owner.owner_control({"operation": "finish_entry", "peer": 0,
                                                 "entry": token}), {"decision": "not_entered"})
            self.assertFalse(owner._entries[first])
            self.assertFalse(controller.jobs)
        finally:
            await owner.aclose()

    async def test_delayed_emitted_entry_is_closed_before_peer_ack_while_b_worker_survives(self):
        # This holds actual transport correlation before Controller dispatch.
        # Native metadata emission/source cancellation is a separate native control.
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        request = self.stage("node")
        a = await transport_check(owner, first, request)
        b = await transport_check(owner, second, request)
        self.assertEqual(a, b)
        arguments = self.selection(a)
        token = owner.owner_control({"operation": "prepare_entry", "peer": 0,
            "connection": "1", "tool": "setup_selected_install", "arguments": arguments,
            "preparation": owner._preparation_by_validation[a["validation_id"]]})["entry"]
        release = asyncio.Event()
        async def delayed():
            await release.wait()
            return await first.dispatch("/api/selected_install", arguments, _entry=token)
        held = asyncio.create_task(delayed())
        controller.runner.block = threading.Event()
        surviving = asyncio.create_task(transport_call(second, "/api/selected_install", self.selection(b)))
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            before = copy.deepcopy(controller.runner.calls)
            self.assertEqual(owner.owner_control({"operation": "close_entry", "peer": 0,
                "entry": token}), {"decision": "not_entered"})
            first.close_admission()
            await asyncio.wait_for(first.aclose(), 3)
            # This is the peer-close acknowledgement while B is still held.
            self.assertFalse(surviving.done())
            self.assertTrue(controller.operation_lock.locked())
            self.assertTrue(any(thread.is_alive() for thread in controller.threads))
            self.assertEqual(len(owner._job_waits), 1)
            job = next(iter(controller.jobs.values()))
            self.assertEqual((await transport_call(second, "/api/job", {"job_id": job["id"]}))["job"]["id"], job["id"])
            release.set()
            with self.assertRaisesRegex(backend.SetupError, "host_closing|shared_entry_unavailable"):
                await asyncio.wait_for(held, 3)
            with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                await second.dispatch("/api/selected_install", self.selection(b), _entry=token)
            self.assertEqual(controller.runner.calls, before)
            self.assertEqual(len(controller.jobs), 1)
            self.assertEqual(owner.owner_control({"operation": "finish_entry", "peer": 0,
                "entry": token}), {"decision": "not_entered"})
            controller.runner.block.set()
            self.assertEqual((await asyncio.wait_for(surviving, 3))["job"]["status"], "succeeded")
        finally:
            release.set()
            controller.runner.block.set()
            await asyncio.gather(held, surviving, return_exceptions=True)
            await owner.aclose()
        self.assertTrue(all(not thread.is_alive() for thread in controller.threads))
        self.assertFalse(owner._job_waits)
        self.assertTrue(all(not entries for entries in owner._entries.values()))

    async def test_exact_check_replays_during_worker_but_changed_effect_refuses(self):
        controller = self.controller()
        request = self.stage("node")
        other = self.stage("node", "other")
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        checked = await transport_check(owner, first, request)
        controller.runner.block = threading.Event()
        task = asyncio.create_task(transport_call(first, "/api/selected_install", self.selection(checked)))
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            self.assertTrue(controller.operation_lock.locked())
            before = copy.deepcopy(controller.runner.calls)
            repeated = await asyncio.wait_for(transport_check(owner, first, request), 3)
            self.assertEqual(repeated, checked)
            self.assertEqual(controller.runner.calls, before)
            self.assertFalse(task.done())
            pending = await transport_call(second, "/api/selected_check", request)
            self.assertEqual(set(pending), {"scope", "ticket"})
            self.assertEqual(pending["scope"], "host_shared_selection_pending")
            with self.assertRaisesRegex(backend.SetupError, "operation_in_progress"):
                await transport_check(owner, second, other)
            original = (self.staging / "choice/closure/dependency").read_bytes()
            (self.staging / "choice/closure/dependency").write_bytes(b"changed closure")
            with self.assertRaisesRegex(backend.SetupError, "selected_source_changed"):
                await transport_call(second, "/api/selected_check", request)
            (self.staging / "choice/closure/dependency").write_bytes(original)
            self.assertEqual(len(controller.validations), 1)
            self.assertEqual(len(controller.jobs), 1)
            controller.runner.block.set()
            self.assertEqual((await asyncio.wait_for(task, 3))["job"]["status"], "succeeded")
        finally:
            controller.runner.block.set()
            await asyncio.gather(task, return_exceptions=True)
            await owner.aclose()

    async def test_peer_close_detaches_observation_before_host_owned_worker_settles(self):
        controller = self.controller()
        request = self.stage("node")
        other = self.stage("node", "second")
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        checked = await transport_check(owner, first, request)
        second_checked = await transport_check(owner, second, other)
        controller.runner.block = threading.Event()
        call = asyncio.create_task(transport_call(first, "/api/selected_install", self.selection(checked)))
        closing = None
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            first.close_admission()
            closing = asyncio.create_task(first.aclose())
            with self.assertRaisesRegex(backend.SetupError, "host_closing"):
                await transport_check(owner, first, request)
            self.assertEqual(await transport_check(owner, second, other), second_checked)
            self.assertFalse(controller.closing)
            await asyncio.wait_for(closing, 3)
            with self.assertRaisesRegex(backend.SetupError, "host_closing"):
                await asyncio.wait_for(call, 3)
            self.assertTrue(controller.operation_lock.locked())
            self.assertTrue(any(thread.is_alive() for thread in controller.threads))
            self.assertEqual(len(owner._job_waits), 1)
            self.assertFalse(first._inflight)
            self.assertFalse(first._observations)
            # The other peer remains live while the physical job is still
            # held. P membership, rather than this transport control, will
            # authorize a second member's observation of that same job.
            self.assertEqual(await transport_check(owner, second, other), second_checked)
            controller.runner.block.set()
            await asyncio.wait_for(asyncio.gather(*tuple(owner._job_waits.values())), 3)
            self.assertEqual(next(iter(controller.jobs.values()))["status"], "succeeded")
            self.assertFalse(controller.closing)
            self.assertEqual(await transport_check(owner, second, other), second_checked)
        finally:
            controller.runner.block.set()
            await asyncio.gather(*[task for task in (call, closing) if task is not None], return_exceptions=True)
            await owner.aclose()
        self.assertTrue(controller.closing)
        self.assertTrue(all(not thread.is_alive() for thread in controller.threads))
        self.assertFalse(owner._job_waits)
        with self.assertRaisesRegex(backend.SetupError, "host_closing"):
            owner.open()
        with self.assertRaisesRegex(backend.SetupError, "host_closing"):
            await transport_call(second, "/api/selected_check", request)

    async def test_cancelled_call_detaches_but_host_close_joins_the_physical_worker(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        peer = owner.open()
        checked = await transport_check(owner, peer, self.stage("node"))
        controller.runner.block = threading.Event()
        call = asyncio.create_task(transport_call(peer, "/api/selected_install", self.selection(checked)))
        closing = None
        try:
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            # An actual current job observation establishes that dispatch and
            # handle publication finished before cancellation of this wait.
            await transport_call(peer, "/api/jobs", {"before": None})
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(call, 3)
            await asyncio.wait_for(peer.aclose(), 3)
            self.assertTrue(controller.operation_lock.locked())
            self.assertEqual(len(owner._job_waits), 1)
            closing = asyncio.create_task(owner.aclose())
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            controller.runner.block.set()
            await asyncio.wait_for(closing, 3)
            self.assertFalse(owner._job_waits)
            self.assertTrue(all(not thread.is_alive() for thread in controller.threads))
        finally:
            controller.runner.block.set()
            await asyncio.gather(call, return_exceptions=True)
            await owner.aclose()

    async def test_unjoined_peer_cannot_read_or_reuse_foreign_job_or_proposal(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        request = self.stage("node")
        try:
            checked = await transport_check(owner, first, request)
            result = await transport_call(first, "/api/selected_install", self.selection(checked))
            identifier = result["job"]["id"]
            self.assertEqual((await transport_call(first, "/api/job", {"job_id": identifier}))["job"]["id"], identifier)
            self.assertEqual(len((await transport_call(first, "/api/jobs", {"before": None}))["jobs"]), 1)
            for route, arguments in (
                ("/api/job", {"job_id": identifier}),
                ("/api/job", {"job_id": "f" * 32}),
                ("/api/reconcile", {"job_id": identifier}),
                ("/api/stop", {"job_id": identifier}),
                ("/api/jobs", {"before": identifier}),
                ("/api/recovery_manifest", {"job_ids": [identifier]}),
            ):
                with self.assertRaisesRegex(backend.SetupError, "unknown_job"):
                    await transport_call(second, route, arguments)
            with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                await transport_call(second, "/api/selected_install", self.selection(checked))
            pending = await transport_call(second, "/api/selected_check", request)
            self.assertEqual(set(pending), {"scope", "ticket"})
            self.assertEqual(pending["scope"], "host_shared_selection_pending")
            self.assertEqual(await transport_call(second, "/api/jobs", {"before": None}), {"jobs": [], "next_before": None})
            state = await transport_call(second, "/api/state", {})
            self.assertEqual(state["observation_scope"], "this_helper_connection")
            self.assertIsNone(state["job"])
            self.assertEqual(state["reconciliation"], {"available": False, "observation": None})
            self.assertEqual(state["job_history"]["count"], 0)
            self.assertEqual(len(controller.jobs), 1)
        finally:
            await owner.aclose()

    async def test_state_is_explicit_and_history_does_not_scan_global_jobs(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        try:
            checked = await transport_check(owner, first, self.stage("node"))
            installed = await transport_call(first, "/api/selected_install", self.selection(checked))
            identifier = installed["job"]["id"]
            actual_state = controller.state
            def with_future_private_fields():
                value = actual_state()
                value.update(future_private_field="foreign", acquisition_recovery_summary={"foreign": True},
                             prior_selection={"foreign": True}, compose={"foreign": True})
                value["family_contents_sha256"] = {"foreign-family": "foreign"}
                value["selected_installation"]["future_private_field"] = "foreign"
                return value
            with patch.object(controller, "state", with_future_private_fields):
                observed = await transport_call(second, "/api/state", {})
            for name in ("future_private_field", "acquisition_recovery_summary", "prior_selection", "compose"):
                self.assertNotIn(name, observed)
            self.assertEqual(observed["family_contents_sha256"], {})
            self.assertNotIn("future_private_field", observed["selected_installation"])
            self.assertEqual(observed["plugin_inspection"], {"available": False})
            self.assertEqual(observed["export_retry"], {"available": False})
            self.assertEqual(observed["local_recipes"], {"available": False})
            self.assertNotIn(identifier, repr(observed))

            class NoGlobalIteration(dict):
                def __iter__(self):
                    raise AssertionError("peer history iterated global jobs")
                def __reversed__(self):
                    raise AssertionError("peer history reversed global jobs")
            original = controller.jobs
            controller.jobs = NoGlobalIteration(original)
            try:
                page = await transport_call(first, "/api/jobs", {"before": None})
                self.assertEqual([row["id"] for row in page["jobs"]], [identifier])
                self.assertEqual(await transport_call(first, "/api/jobs", {"before": identifier}),
                                 {"jobs": [], "next_before": None})
                self.assertEqual(await transport_call(second, "/api/jobs", {"before": None}),
                                 {"jobs": [], "next_before": None})
            finally:
                controller.jobs = original
        finally:
            await owner.aclose()

    async def test_private_handoff_binds_peer_request_and_exact_current_selection(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        request = self.stage("node")
        try:
            pending = await transport_call(first, "/api/selected_check", request)
            self.assertEqual(set(pending), {"scope", "ticket"})
            self.assertFalse(owner._views[first]["validations"])
            command = {"operation": "inspect_selection", "peer": 0, "ticket": pending["ticket"]}
            inspected = owner.owner_control(command)
            selected = inspected["selection"]
            self.assertEqual(selected["arguments_sha256"], backend.digest(backend.encoded(request)))
            self.assertEqual(selected["effect"], next(iter(controller.validations.values()))["effect"])
            self.assertEqual(selected["plan"], next(iter(controller.validations.values()))["plan"])
            for changed in ({**command, "peer": 1}, {**command, "ticket": "f" * 32},
                            {**command, "peer": True}, {**command, "unexpected": 1}):
                with self.assertRaises(backend.SetupError):
                    owner.owner_control(changed)
            with self.assertRaisesRegex(backend.SetupError, "shared_entry_unavailable"):
                await transport_call(first, "/api/selected_install", self.selection(selected["result"]))
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_changed"):
                owner.owner_control({**command, "operation": "release_selection", "selection_sha256": "0" * 64, "preparation": "f" * 64})
            effect_file = controller.workspace / "selections" / selected["result"]["validation_id"] / "effect.json"
            original = effect_file.read_bytes()
            effect_file.write_bytes(original + b" ")
            with self.assertRaisesRegex(backend.SetupError, "selected_proposal_changed"):
                owner.owner_control({**command, "operation": "release_selection",
                                     "selection_sha256": inspected["selection_sha256"], "preparation": "f" * 64})
            effect_file.write_bytes(original)
            result = owner.owner_control({**command, "operation": "release_selection",
                                          "selection_sha256": inspected["selection_sha256"], "preparation": "f" * 64})
            self.assertEqual(result, selected["result"])
            self.assertFalse(owner._views[second]["validations"])
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                owner.owner_control(command)
            another = await transport_call(second, "/api/selected_check", request)
            second.close_admission()
            with self.assertRaisesRegex(backend.SetupError, "shared_selection_unavailable"):
                owner.owner_control({"operation": "inspect_selection", "peer": 1, "ticket": another["ticket"]})
            self.assertFalse(controller.jobs)
        finally:
            await owner.aclose()

    async def test_exact_shared_job_disclosure_requires_both_private_releases(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        request = self.stage("node")
        controller.runner.block = threading.Event()
        calls = []
        try:
            selected = await transport_check(owner, first, request)
            calls.append(asyncio.create_task(transport_call(first, "/api/selected_install", self.selection(selected))))
            self.assertTrue(await asyncio.to_thread(controller.runner.entered.wait, 3))
            identifier = next(iter(controller.jobs))
            pending = await transport_call(second, "/api/selected_check", request)
            with self.assertRaisesRegex(backend.SetupError, "unknown_job"):
                await transport_call(second, "/api/job", {"job_id": identifier})
            command = {"operation": "inspect_selection", "peer": 1, "ticket": pending["ticket"]}
            inspected = owner.owner_control(command)
            second_selected = owner.owner_control({**command, "operation": "release_selection",
                                                    "selection_sha256": inspected["selection_sha256"], "preparation": "f" * 64})
            self.assertEqual(second_selected, selected)
            self.assertEqual((await transport_call(second, "/api/job", {"job_id": identifier}))["job"]["id"], identifier)
            calls.append(asyncio.create_task(transport_call(second, "/api/selected_install", self.selection(second_selected))))
            await transport_call(second, "/api/jobs", {"before": None})
            await asyncio.wait_for(first.aclose(), 3)
            with self.assertRaisesRegex(backend.SetupError, "host_closing"):
                await asyncio.wait_for(calls[0], 3)
            self.assertFalse(calls[1].done())
            self.assertTrue(controller.operation_lock.locked())
            self.assertEqual(len(controller.jobs), 1)
            controller.runner.block.set()
            self.assertEqual((await asyncio.wait_for(calls[1], 3))["job"]["status"], "succeeded")
        finally:
            controller.runner.block.set()
            await asyncio.gather(*calls, return_exceptions=True)
            await owner.aclose()

    async def test_legacy_adapter_close_still_closes_its_controller(self):
        controller = self.controller()
        peer = adapter.SetupAdapter(controller)
        await peer.aclose()
        self.assertTrue(controller.closing)
        await peer.aclose()
        with self.assertRaisesRegex(backend.SetupError, "host_closing"):
            await peer.dispatch("/api/state", {})

    async def test_shared_tool_schema_exposes_only_scoped_source_and_wait_contract(self):
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        peer = owner.open()
        try:
            shared = {item["name"]: item for item in adapter.tool_descriptions(peer)}
            legacy = {item["name"]: item for item in adapter.tool_descriptions(adapter.SetupAdapter(controller))}
            self.assertIn("plugin_source", legacy["setup_selected_check"]["inputSchema"]["properties"])
            self.assertNotIn("plugin_source", shared["setup_selected_check"]["inputSchema"]["properties"])
            self.assertNotIn("Optional plugin_source", shared["setup_selected_check"]["description"])
            self.assertIn("detaches its observation", shared["setup_selected_install"]["description"])
            self.assertIn("Cancelling the call joins the worker", legacy["setup_selected_install"]["description"])
            self.assertFalse(set(shared) & {"setup_recipes", "setup_export_recipe", "setup_inspect_plugin", "setup_plugin_source", "setup_compose_start"})
            for arguments in (
                {"source": {"job_id": "f" * 32}},
                {"source": None},
            ):
                with self.assertRaisesRegex(backend.SetupError, "selected_source_unavailable"):
                    await transport_call(peer, "/api/acquire_node_prebuilt", arguments)
            self.assertFalse(controller.runner.calls)
        finally:
            await owner.aclose()


class SharedCatalog(CatalogFixture, unittest.IsolatedAsyncioTestCase):
    async def test_foreign_prepared_family_has_no_help_or_readback_projection(self):
        route_fixture(self)
        controller = self.controller()
        owner = adapter.ControllerConnections(controller)
        first, second = owner.open(), owner.open()
        try:
            await transport_call(first, "/api/prepare", {"family": "agno"})
            await asyncio.to_thread(controller.join)
            self.assertEqual((await transport_call(first, "/api/catalog_route", route_request(controller)))["status"], "prepared")
            foreign = await transport_call(second, "/api/catalog_entry", entries()[0]["identity"])
            option = foreign["setup_options"][0]
            self.assertEqual(option["status"], "unobserved")
            self.assertEqual(option["reason"], "not_observed_by_this_helper")
            with self.assertRaisesRegex(catalog_backend.SetupError, "shared_preparation_unavailable"):
                await transport_call(second, "/api/catalog_route", route_request(controller))
            with self.assertRaisesRegex(backend.SetupError, "family_not_prepared"):
                await transport_call(second, "/api/help", {"family": "agno", "profile": "searxng"})
            state = await transport_call(second, "/api/state", {})
            self.assertNotIn("agno", state["family_contents_sha256"])
            self.assertFalse(any(row["id"] == "agno" for row in state["families"]))
            # The other independently prepared family remains a normal own
            # catalog/help path; no controller-wide observation is borrowed.
            await transport_call(second, "/api/prepare", {"family": "services"})
            await asyncio.to_thread(controller.join)
            own = await transport_call(second, "/api/catalog_route", route_request(controller, "alternative"))
            self.assertEqual(own["status"], "prepared")
            self.assertEqual(own["help"], controller.help({"family": "services", "profile": "slack"}))
        finally:
            await owner.aclose()


if __name__ == "__main__":
    unittest.main()
