"""Inert physical worker for the public SDK two-child native control.

Only the installer/validator output is controlled. The real Controller, peer
MCP transports, native dispatch, review and canonical P owners remain in use.
This does not establish package activation or usable service operations.
"""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_selected_setup import SelectedFixture, SelectedRunner, adapter, backend

spec = importlib.util.spec_from_file_location("sdk_shared_local_session", HERE.parent / "local_session.py")
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


async def main(output):
    output = Path(output).resolve(strict=True)
    fixture = SelectedFixture()
    fixture.setUp()
    physical = []
    lock = threading.Lock()

    def retain(name, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        temporary = output / (name + ".tmp")
        temporary.write_bytes(raw)
        temporary.replace(output / name)

    class HeldRunner(SelectedRunner):
        def run(self, argv, capture=False):
            if "--package" not in argv and "--verify-existing" not in argv:
                with lock:
                    physical.append(list(argv))
                    retain("WORKER-ENTERED.json", {"entries": physical})
                deadline = time.monotonic() + 90
                while not (output / "RELEASE-WORKER").exists():
                    if time.monotonic() >= deadline:
                        retain("WORKER-BOUND-FAILED.json", {"reason": "test owner did not release worker"})
                        return 2, b"test owner release absent"
                    time.sleep(0.01)
            return super().run(argv, capture)

    controller = fixture.controller(runner_factory=HeldRunner)
    try:
        selected = fixture.stage("python")
        retain("SELECTED-INPUT.json", selected)
        await local.shared_stdio_owner(adapter, controller, 2)
    finally:
        # Failure cleanup still joins the real worker before the process exits.
        # This release is not the successful cancellation-before-release proof.
        if not (output / "RELEASE-WORKER").exists():
            (output / "RELEASE-WORKER").write_text("failure cleanup\n")
        await asyncio.to_thread(controller.join)
        retain("OWNER-JOINED.json", {
            "physical_entries": len(physical),
            "workers_alive": sum(thread.is_alive() for thread in controller.threads),
            "closing": controller.closing,
        })
        fixture.tearDown()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
