"""Inert controls for the real Browser observer, not browser/native acceptance."""
import contextlib
import dataclasses
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "browser_status_subject", Path(__file__).with_name("verify_installed_console.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
UNAVAILABLE = {"error": "Protected setup is unavailable"}


def observation(status=200, *, method="GET", suffix="/data", value=None):
    return {"method": method, "path": C.PANEL + suffix,
            "request": {} if method == "POST" else None, "status": status,
            "response": value if value is not None else
            ({"review": None} if status == 200 else UNAVAILABLE)}


@dataclasses.dataclass
class Input:
    channel: str = "host-authenticated-console"
    principal: str = C.EMAIL
    identity: str = "original"
    content: str = "fixture input"
    interaction_id: str = "interaction"
    session_id: str = "session"
    input_frame_id: str = "frame"
    cursor: str = "console:1"
    conversation_id: str = "conversation"


@dataclasses.dataclass
class Retirement:
    fenced: bool = True
    reservations_drained: bool = True
    uncertain: bool = False


class ObserverHarness:
    """Supply transport observations; replace unrelated journey qualification."""

    def __init__(self, directory, batches, late):
        self.directory, self.batches, self.late = directory, list(batches), late
        self.clock, self.reads, self.closes = 0, 0, 0
        self.events = mock.Mock()
        self.process = SimpleNamespace(poll=lambda: None)
        self.provider = SimpleNamespace(lock=contextlib.nullcontext(), requests=[],
            errors=[], results={}, business_observation=None, enabled=False,
            finished=SimpleNamespace(is_set=lambda: True))
        self.client = SimpleNamespace(event_hooks={"response": []})
        self.front = SimpleNamespace(application=self.application, client=self.client,
            start=self.start, close=self.close, failures=[], key=None,
            task=SimpleNamespace(done=lambda: False))
        self.scenario = object.__new__(C.BrowserConsoleScenario)
        self.scenario.v = SimpleNamespace(ACQUISITION_LIMIT=3, save_json=self.save,
            unique_json=json.loads, exact_bytes=lambda path: path.read_bytes())
        self.scenario.front = self.front
        self.scenario.origin = "http://127.0.0.1:12345"
        self.scenario.password = "public-fixture"
        self.scenario.source_receipt, self.scenario.forge_sources = {}, []
        self.scenario.auth = SimpleNamespace(ISSUER="fixture")
        self.scenario.login_module = SimpleNamespace(
            NativeConsoleLogin=lambda *args, **kwargs: SimpleNamespace(close=self.retire))
        self.scenario.original_request = lambda: "fixture input"
        # This suite tests status-observer acceptance only. Actual timeline,
        # approval and native qualification are deliberately not simulated.
        self.scenario.completed = lambda *args: {"fixture_only": True}
        self.scenario.finish_report = self.finish
        self.finished_at = []
        self.save(directory / "browser-release.json", {"finish": True})

    @staticmethod
    def save(path, value):
        path.write_text(json.dumps(value))

    def finish(self, report, results, provider, completion):
        self.finished_at.append(self.clock)
        report.update(status="passed", completion=completion)

    async def retire(self):
        return Retirement()

    def application(self, _native_url):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": scope["fixture_status"]})
        return app

    async def emit(self, rows):
        for row in rows:
            async def read(value=row["response"]):
                self.reads += 1
                return json.dumps(value).encode()
            response = SimpleNamespace(status_code=row["status"], aread=read,
                request=SimpleNamespace(url=SimpleNamespace(path=row["path"]),
                    method=row["method"], content=json.dumps(row["request"]).encode()))
            for observer in self.client.event_hooks["response"]:
                await observer(response)

    async def start(self, native_url):
        app = self.front.application(native_url)
        self.front.console_login_factory(object())
        self.front.on_input(Input())
        # Satisfy unrelated front-route guards with inert ASGI responses.
        routes = [("GET", "/login", 200), ("POST", "/login", 303),
                  ("GET", C.PANEL, 200), ("POST", C.PANEL + "/data", 200),
                  ("POST", C.PANEL + "/answer", 202),
                  ("POST", C.PANEL + "/answer", 202),
                  ("POST", C.PANEL + "/start", 202)]
        async def discard(_message):
            pass
        for method, path, status in routes:
            await app({"type": "http", "method": method, "path": path,
                       "fixture_status": status}, None, discard)
        await self.emit(self.batches.pop(0) if self.batches else [])

    async def sleep(self, _duration):
        self.clock += 1
        await self.emit(self.batches.pop(0) if self.batches else [])

    async def close(self):
        self.closes += 1
        await self.emit(self.late)

    def run(self):
        error = None
        with mock.patch.object(C.time, "monotonic", side_effect=lambda: self.clock), \
                mock.patch.object(C.asyncio, "sleep", self.sleep), \
                mock.patch.object(C.socket, "socket", side_effect=AssertionError("no sockets")), \
                mock.patch.object(C, "HTTPConnection", side_effect=AssertionError("no HTTP")):
            work = self.scenario.run(None, self.provider, self.directory, self.events,
                                     self.process, "http://127.0.0.1:54321")
            try:
                work.send(None)
            except StopIteration:
                pass
            except AssertionError as caught:
                error = caught
            finally:
                work.close()
        return json.loads((self.directory / "console-journey.json").read_text()), error


class BrowserStatusTests(unittest.TestCase):
    def exercise(self, batches, *, late=()):
        with tempfile.TemporaryDirectory(prefix="inert-browser-status-") as scratch:
            harness = ObserverHarness(Path(scratch), batches, late)
            report, error = harness.run()
        self.assertEqual(harness.closes, 1)
        self.assertEqual(report["decisions"], [])
        self.assertEqual(report["starts"], [])
        self.assertEqual(harness.provider.requests, [])
        self.assertEqual(harness.client.__dict__.keys(), {"event_hooks"})
        return harness, report, error

    def test_get_and_post_unavailable_wait_for_later_success(self):
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                pending, ready = observation(503, method=method), observation()
                harness, report, error = self.exercise([[pending], [ready]])
                self.assertIsNone(error)
                self.assertEqual(report["status"], "passed")
                self.assertEqual(report["http"], [pending, ready])
                self.assertEqual(harness.finished_at, [1])
                self.assertEqual(harness.reads, 2)
                harness.events.add.assert_called_once()

    def test_earlier_success_does_not_clear_later_unavailable(self):
        ready, pending = observation(), observation(503)
        harness, report, error = self.exercise([[ready, pending]])
        self.assertRegex(str(error), "did not complete and release")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["http"], [ready, pending])
        self.assertEqual(harness.finished_at, [])
        self.assertEqual(harness.reads, 2)
        harness.events.add.assert_not_called()

    def test_other_failures_stay_strict_and_retained(self):
        cases = [
            observation(503, value={"error": "different"}),
            observation(503, value={**UNAVAILABLE, "extra": True}),
            observation(403), observation(500),
            observation(503, method="DELETE"),
            observation(503, method="POST", suffix="/answer"),
            observation(503, method="POST", suffix="/start"),
        ]
        for row in cases:
            with self.subTest(row=row):
                harness, report, error = self.exercise([[row]])
                self.assertIsNotNone(error)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["http"], [row])
                self.assertEqual(harness.finished_at, [])
                harness.events.add.assert_not_called()

    def test_late_unavailable_invalidates_apparent_completion(self):
        ready, pending = observation(), observation(503, method="POST")
        harness, report, error = self.exercise([[ready]], late=[pending])
        self.assertRegex(str(error), "remained unavailable after completion")
        self.assertEqual(harness.finished_at, [0])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["cleanup_failure_phase"], "post_close_observation")
        self.assertEqual(report["http"], [ready, pending])
        harness.events.add.assert_not_called()


if __name__ == "__main__":
    unittest.main()
