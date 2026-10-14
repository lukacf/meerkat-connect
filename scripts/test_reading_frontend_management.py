"""Component checks of Reading's SQLite/actor disable recovery, without a runtime.

Native observation endpoints are controlled fakes. The application methods and
Toolkit close value types are real source; these checks make no native journey,
provider delivery, CLI or Console acceptance claim.
"""
import argparse
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from uuid import UUID


ROOT = Path(__file__).resolve().parents[1]
APPLICATION = ROOT / "crates/meerkat-connect/tests/fixtures/forge-reading/application"
TOOLKIT_PYTHON = ROOT / "sdk/python/src"


def module_at(name, path, *, package=False):
    spec = importlib.util.spec_from_file_location(
        name, path, submodule_search_locations=[str(path.parent)] if package else None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def component_imports():
    # Import-only placeholders avoid loading any installed native SDK/runtime.
    # No instance or method on these placeholders is used by the component.
    meta = types.ModuleType("meerkat_meta")
    meta.__path__ = []
    transport = types.ModuleType("meerkat_meta._transport")
    transport.PersistentTransport = type("UnusedPersistentTransport", (), {})
    runtime = types.ModuleType("meerkat_meta.runtime")
    runtime.MetaRuntime = type("UnusedMetaRuntime", (), {})
    errors = types.ModuleType("meerkat_meta.errors")
    errors.TurnUnknownError = type("ComponentTurnUnknownError", (Exception,), {})
    errors.TurnFailedError = type("ComponentTurnFailedError", (Exception,), {})
    return {"meerkat_meta": meta, "meerkat_meta._transport": transport,
            "meerkat_meta.runtime": runtime, "meerkat_meta.errors": errors}


class ControlledClose:
    """Observation endpoint only; all returned receipts are explicitly synthetic."""
    def __init__(self, sdk):
        self.sdk = sdk
        self.handle = sdk.HostCloseHandle(UUID(int=1), UUID(int=2),
                                         sdk.HostCloseScope("component", "reading-telegram"))
        self.begin_calls, self.observe_calls, self.join_calls = [], [], []
        self.unknown_entry = False
        self.lost_join = False
        self.settled = False

    def observation(self, state):
        return self.sdk.HostCloseObservation(self.handle, state, None)

    def begin_close_component(self, component, reason):
        self.begin_calls.append((component, reason))
        if self.unknown_entry:
            raise TimeoutError("controlled missing entry receipt")
        return self.observation(self.sdk.HostCloseState.CLOSING)

    def observe_close(self, handle):
        self.observe_calls.append(handle)
        return self.observation(self.sdk.HostCloseState.SETTLED if self.settled
                                else self.sdk.HostCloseState.CLOSING)

    def join_close(self, handle):
        self.join_calls.append(handle)
        if self.lost_join and not self.settled:
            raise TimeoutError("controlled lost join observation")
        self.settled = True
        return self.observation(self.sdk.HostCloseState.SETTLED)


class ControlledRuntime:
    def __init__(self, host_control):
        self.host_control = host_control
        self.completed = False
        self.observations = []
        self.dispatches = self.replies = self.provider_entries = 0

    async def turn_result(self, identity, ticket):
        self.observations.append((identity, ticket))
        value = {"identity": identity, "ticket": ticket,
                 "state": "completed" if self.completed else "pending"}
        if self.completed:
            value.update(output_status="text", output="controlled component result",
                         output_truncated=False)
        return types.SimpleNamespace(to_dict=lambda: dict(value))

    async def submit(self, *args, **kwargs):
        self.dispatches += 1
        raise AssertionError("disable recovery must not submit input")

    async def dispatch(self, *args, **kwargs):
        self.dispatches += 1
        raise AssertionError("disable recovery must not dispatch input")

    async def send_text(self, *args, **kwargs):
        self.replies += 1
        raise AssertionError("disable recovery must not send a reply")

    def provider(self, *args, **kwargs):
        self.provider_entries += 1
        raise AssertionError("disable recovery must not open a provider")


class ReadingManagementRecoveryTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = patch.dict(sys.modules, component_imports())
        cls.modules.start()
        cls.addClassCleanup(cls.modules.stop)
        cls.sdk = module_at("meerkat_toolkit.host_control",
                            TOOLKIT_PYTHON / "meerkat_toolkit/host_control.py")
        toolkit = types.ModuleType("meerkat_toolkit")
        toolkit.__path__ = []
        toolkit.host_control = cls.sdk
        sys.modules["meerkat_toolkit"] = toolkit
        cls.application = module_at("_reading_management_component", APPLICATION / "__init__.py",
                                    package=True)

    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="reading-management-component-")
        self.addCleanup(self.temporary.cleanup)
        self.environment = patch.dict(os.environ, {"CONSOLE_USER_ID": "component-owner"}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.host = {"protocol": 1, "host_id": "forge:" + "1" * 64,
                     "application_id": "reading-component", "source_digest": "2" * 64}
        self.close = ControlledClose(self.sdk)
        self.runtime = ControlledRuntime(self.close)
        context = types.SimpleNamespace(root=self.temporary.name,
            deployment={"slug": "reading-component"}, frontend_host=lambda: dict(self.host),
            runtime=self.runtime, submit_frontend_input=self.runtime.submit,
            telegram_transport_factory=self.runtime.provider)
        self.app = self.application.Integration(context)
        self.app.frontends.start()
        self.addCleanup(self.app.frontends.stop)
        self.commit({"component_id": "reading-telegram", "profile": "private-text-dm",
            "participant_id": "reading-owner", "route_id": "reading-lead-dm",
            "telegram_user_id": 42, "telegram_dm_chat_id": 42, "native_identity": "lead:main",
            "bot_token": {"private_field": "READING_TELEGRAM_BOT_TOKEN"},
            "exclusive_polling_acknowledged": True})
        self.disable = self.commit({"component_id": "reading-telegram", "action": "disable"})
        self.actor = self.app.telegram
        self.actor.poll_interval = .01
        self.started = False

    def request(self, operation, payload, approved=False):
        return types.SimpleNamespace(operation=operation, payload=payload, approved=approved,
                                     host=dict(self.host), principal="component-owner")

    def commit(self, configuration):
        with self.app.frontends.connection(readonly=True) as db:
            revision = self.app.frontends.state(db)["revision"]
        proposal = self.app.frontends.manage(self.request("prepare",
            {"configuration": configuration, "expected_revision": revision}))["proposal"]
        return self.app.frontends.manage(self.request("submit", {"proposal": proposal,
            "approval": {"principal": "component-owner", "expires_at": proposal["expires_at"]}}, True))

    async def start_actor(self, *, pending=False):
        await self.actor.start()
        self.started = True
        # No event-loop yield occurs between schema creation and retained rows.
        # The actor's first selected state is the already committed disable.
        selection = self.actor.selected()
        with self.app.frontends.connection(readonly=False) as db, db:
            rows = [(2, "queued", None), (3, "outbound-unknown", None)]
            if pending:
                rows.append((1, "native-pending", json.dumps(
                    {"identity": "lead:main", "turn_ticket": "component-ticket"})))
            for update_id, status, admission in rows:
                db.execute("INSERT INTO reading_telegram_inbox(bot_id,update_id,payload,binding,status,admission) VALUES(?,?,?,?,?,?)",
                    ("component-bot", update_id, "{}", json.dumps(selection, sort_keys=True,
                     separators=(",", ":")), status, admission))

    async def asyncTearDown(self):
        if self.started:
            await self.actor.stop()
        self.assertEqual((self.runtime.dispatches, self.runtime.replies, self.runtime.provider_entries), (0, 0, 0))
        if self.started:
            with self.app.frontends.connection(readonly=True) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM reading_telegram_outbound").fetchone()[0], 0)

    def close_state(self):
        return self.app.frontends.management_observation()["native_close"]

    async def wait_for(self, predicate):
        async def wait():
            while not predicate():
                if self.actor.task.done():
                    self.actor.task.result()
                    self.fail("application owner stopped before the component condition")
                await asyncio.sleep(.005)
        await asyncio.wait_for(wait(), 2)

    def change_count(self):
        with self.app.frontends.connection(readonly=True) as db:
            return db.execute("SELECT COUNT(*) FROM reading_frontend_changes").fetchone()[0]

    async def test_submission_disposition_is_explicit_and_retains_original_command(self):
        with self.app.frontends.connection(readonly=True) as db:
            proposal = json.loads(db.execute("SELECT proposal FROM reading_frontend_changes WHERE change_id=?",
                (self.disable["change_id"],)).fetchone()[0])
        command = self.request("submit", {"proposal": proposal,
            "approval": {"principal": "component-owner", "expires_at": proposal["expires_at"]}}, True)
        declarations = []
        def formatter(original, observation, *, known):
            declarations.append((original, observation, known))
            return (original, observation, known)
        self.app.context.frontend_submission_result = formatter
        known = await self.app.frontend_management(command)
        self.assertIs(known[0], command)
        self.assertIs(known[2], True)
        self.assertEqual(known[1]["status"], "committed")
        self.assertIsNone(known[1]["management_observation"]["native_close"])
        # A missing retained command stays unknown, even in a live configured app.
        missing = self.request("submit", {"proposal": {**proposal, "change_id": "unretained"},
            "approval": command.payload["approval"]}, True)
        unknown = await self.app.frontend_management(missing)
        self.assertIs(unknown[0], missing)
        self.assertIs(unknown[2], False)
        self.assertEqual(unknown[1]["status"], "unknown")
        # An exact command conflict is a known refusal, not success or close.
        conflict = self.request("submit", {"proposal": {**proposal, "expected_revision": 99},
            "approval": command.payload["approval"]}, True)
        refused = await self.app.frontend_management(conflict)
        self.assertIs(refused[2], True)
        self.assertEqual(refused[1]["status"], "change-conflict")
        with self.assertRaises(PermissionError):
            await self.app.frontend_management(self.request("submit", command.payload, False))
        self.assertEqual(len(declarations), 3)
        # A status read is still opaque observation and cannot declare settlement.
        observed = await self.app.frontend_management(self.request("status", {"change_id": self.disable["change_id"]}))
        self.assertIs(type(observed), dict)
        self.assertEqual(len(declarations), 3)
        del self.app.context.frontend_submission_result
        legacy = await self.app.frontend_management(command)
        self.assertIs(type(legacy), dict)
        self.assertEqual(legacy, known[1])
        self.assertEqual(self.close.begin_calls, [])

    async def test_pending_ticket_settles_without_second_approval_or_dispatch(self):
        await self.start_actor(pending=True)
        await self.wait_for(lambda: (self.close_state() or {}).get("state") == "not_entered")
        self.assertEqual(self.close.begin_calls, [])
        count = self.change_count()
        # Status is observational and does not advance a pending native ticket.
        status = self.app.frontends.manage(self.request("status", {"change_id": self.disable["change_id"]}))
        self.assertEqual(status["management_observation"]["native_close"]["state"], "not_entered")
        self.runtime.completed = True
        await self.wait_for(lambda: (self.close_state() or {}).get("state") == "settled")
        self.assertEqual(self.change_count(), count)
        self.assertEqual(self.close.begin_calls, [("reading-telegram", self.sdk.HostCloseReason.OPERATOR_DISABLE)])
        self.assertTrue(self.runtime.observations)
        self.assertEqual(set(self.runtime.observations), {("lead:main", "component-ticket")})
        with self.app.frontends.connection(readonly=True) as db:
            row = db.execute("SELECT status,completion FROM reading_telegram_inbox WHERE update_id=1").fetchone()
            self.assertEqual(row["status"], "disabled-reply-stopped")
            self.assertEqual(json.loads(row["completion"])["ticket"], "component-ticket")
        self.assertEqual(self.close_state()["application_drain"],
            {"accepted_native_unsettled": 0, "provider_outcome_unknown": 1,
             "pending_input_stopped": 1, "pending_reply_stopped": 1})
        self.assertEqual(self.commit({"component_id": "reading-telegram", "action": "remove"})["management_state"], "removed")

    async def test_lost_join_recovers_only_the_same_known_handle(self):
        self.close.lost_join = True
        await self.start_actor()
        await self.wait_for(lambda: (self.close_state() or {}).get("state") == "uncertain")
        retained = self.close_state()["observation"]["handle"]
        self.assertEqual(retained, self.close.handle.wire())
        self.assertEqual(len(self.close.begin_calls), 1)
        # Recreate the application actor over its same SQLite owner. No second
        # disable or close entry is needed to observe the retained handle.
        await self.actor.stop()
        self.started = False
        self.close.settled = True
        await self.actor.start()
        self.started = True
        await self.wait_for(lambda: (self.close_state() or {}).get("state") == "settled")
        self.assertEqual(len(self.close.begin_calls), 1)
        self.assertEqual(self.close_state()["observation"]["handle"], retained)
        self.assertTrue(self.close.join_calls)
        self.assertTrue(all(handle == self.close.handle for handle in self.close.observe_calls + self.close.join_calls))

    async def test_unknown_entry_without_handle_never_starts_another_close(self):
        self.close.unknown_entry = True
        await self.start_actor()
        await self.wait_for(lambda: (self.close_state() or {}).get("state") == "uncertain")
        self.assertIsNone(self.close_state()["observation"])
        await self.actor.stop()
        self.started = False
        self.close.unknown_entry = False
        self.close.settled = True
        await self.actor.start()
        self.started = True
        await self.wait_for(lambda: self.actor.state == "disabled-close-outcome-unknown")
        self.assertEqual(len(self.close.begin_calls), 1)
        self.assertEqual((self.close.observe_calls, self.close.join_calls), ([], []))
        self.assertEqual(self.close_state()["state"], "uncertain")
        with self.assertRaises(ValueError):
            self.commit({"component_id": "reading-telegram", "action": "remove"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--application-directory", type=Path, default=APPLICATION)
    parser.add_argument("--toolkit-python", type=Path, default=TOOLKIT_PYTHON)
    options, unittest_args = parser.parse_known_args()
    APPLICATION, TOOLKIT_PYTHON = options.application_directory, options.toolkit_python
    unittest.main(argv=[sys.argv[0], *unittest_args])
