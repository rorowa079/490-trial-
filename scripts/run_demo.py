#!/usr/bin/env python3
"""Run the whole system on simulated traffic, for development and demos.

    python scripts/run_demo.py        then open http://localhost:8000

Creates ./data-demo with throwaway keys, five accounts (one per role) and a
small hotlist. Password for all of them:  demo-password-123

    alice  investigator    bob    supervisor    carol  reviewer
    dana   auditor         admin  admin

Custodian shares are saved to data-demo/DEMO_SHARES.txt so you can try the
two-person unseal. A real device never stores shares or uses this script.
Use "localhost" in the address bar, not 127.0.0.1: browsers only allow
security keys on localhost or HTTPS.
"""
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vrs.api.serve import serve                   # noqa: E402
from vrs.api.server import create_app             # noqa: E402
from vrs.capture.camera import SimulatedSource    # noqa: E402
from vrs.config import load_config                # noqa: E402
from vrs.provision import is_provisioned, provision_device   # noqa: E402
from vrs.system import System                     # noqa: E402

PASSWORD = "demo-password-123"
ACCOUNTS = (("alice", "investigator"), ("bob", "supervisor"), ("carol", "reviewer"), ("dana", "auditor"),
            ("admin", "admin"))
# Stolen vehicles as the "agency" describes them...
HOTLIST = [
    {"plate": "7ABC123", "case_ref": "24-0117", "color": "silver", "make": "toyota", "model": "camry", "body_type": "car"},
    {"plate": "4XYZ789", "case_ref": "24-0131", "color": "red", "make": "ford", "model": "f-150", "body_type": "truck"},
    {"plate": "9LMN456", "case_ref": "24-0142", "color": "black", "make": "honda", "model": "civic", "body_type": "car"},
]
# ...and as they actually drive past. Two of the three do NOT fully match,
# which is exactly what the reviewer is there to catch.
ON_THE_ROAD = [
    {"plate": "7ABC123", "color": "silver", "make": "toyota", "model": "rav4", "body_type": "car"},
    {"plate": "4XYZ789", "color": "red", "make": "ford", "model": "f-150", "body_type": "truck"},
    {"plate": "9LMN456", "color": "white", "make": "honda", "model": "civic", "body_type": "car"},
]


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(ROOT / "config" / "demo.yaml")
    first_run = not is_provisioned(cfg)
    if first_run:
        shares = provision_device(cfg)
        (Path(cfg["data_dir"]) / "DEMO_SHARES.txt").write_text(
            "DEMO ONLY. A real device never stores custodian shares.\n\n" + "\n".join(
                f"{name}: {share}" for name, share in zip(("admin", "alice", "bob"), shares)) + "\n")
    system = System(cfg)
    if first_run:
        for name, role in ACCOUNTS:
            system.auth.create_user(name, PASSWORD, role)
        system.hotlist.ingest(HOTLIST, "demo-hotlist", "demo", replace=True)
    capture = cfg["capture"]
    system.start(SimulatedSource(capture["width"], capture["height"], capture["fps"], realtime=True,
                                 plate_pool=ON_THE_ROAD, pool_rate=0.35))
    scheme = "https" if cfg["api"]["tls"]["enabled"] else "http"
    print(f"\nDemo running: {scheme}://localhost:{cfg['api']['port']}   password for every account: {PASSWORD}")
    print("  " + "   ".join(f"{name} ({role})" for name, role in ACCOUNTS) + "\n")
    try:
        serve(create_app(system), cfg)
    finally:
        system.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
