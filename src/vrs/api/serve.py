"""Run the API server: HTTPS with TLS 1.3 only when ``api.tls.enabled``, plain HTTP otherwise.

Plain HTTP exists for development on localhost. Anything reachable from
another machine must use TLS (NIST SP 800-53 SC-8; CJIS requires encryption in
transit), and security keys only work over HTTPS or on ``localhost``.
"""
from __future__ import annotations

import logging
import ssl

import uvicorn

from ..security.device_identity import tls_files

log = logging.getLogger(__name__)


def build_server(app, cfg: dict) -> uvicorn.Server:
    api = cfg["api"]
    tls = api["tls"]
    options: dict = {"host": api["host"], "port": api["port"], "log_level": "warning", "server_header": False}
    if tls["enabled"]:
        cert, key = tls_files(cfg)
        options.update(ssl_certfile=cert, ssl_keyfile=key)
        if tls.get("client_ca_file"):
            options.update(ssl_ca_certs=tls["client_ca_file"], ssl_cert_reqs=ssl.CERT_REQUIRED)
    else:
        if api["host"] not in ("127.0.0.1", "localhost", "::1"):
            log.warning("serving plain HTTP on %s: enable api.tls before exposing this beyond localhost", api["host"])
    config = uvicorn.Config(app, **options)
    if tls["enabled"]:
        config.load()
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    return uvicorn.Server(config)


def serve(app, cfg: dict) -> None:
    build_server(app, cfg).run()
