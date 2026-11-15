"""Entry point: start the pipeline and the operator API.

    python -m vrs.app            (after scripts/init_device.py)

Shutdown (Ctrl-C or SIGTERM) stops the pipeline, zeroes every key in RAM and
writes the shutdown to the audit log.
"""
from __future__ import annotations

import logging
import sys

from .api.serve import serve
from .api.server import create_app
from .config import load_config
from .system import StartupError, System


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    try:
        system = System(cfg)
    except StartupError as exc:
        logging.error("%s", exc)
        return 1
    system.start()
    try:
        serve(create_app(system), cfg)
    finally:
        system.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
