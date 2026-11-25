"""The scapegoat daemon: sessions, the scheduler thread, the HTTP API, island publish."""

from __future__ import annotations

import importlib
import json
import logging
import signal
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone

from . import VERSION
from . import localaddr
from . import ext
from .config import Config
from .session import Session

log = logging.getLogger("scapegoat.service")

ISLAND_EVERY_S = 5.0
ISLAND_ERROR_LOG_EVERY_S = 60.0


class NetUnavailable(Exception):
    """scapegoat.net (or one of its functions) is not installed."""


def _net(module: str, func: str):
    try:
        mod = importlib.import_module(f"scapegoat.net.{module}")
    except ImportError as exc:
        raise NetUnavailable(f"network tools are not installed (scapegoat.net.{module}: {exc})")
    fn = getattr(mod, func, None)
    if not callable(fn):
        raise NetUnavailable(f"scapegoat.net.{module} has no {func}()")
    return fn


class Service:
    def __init__(self, config: Config, sessions: dict | None = None,
                 only_session: str | None = None):
        self.config = config
        if only_session is not None and only_session not in config.sessions:
            raise KeyError(f"no session named {only_session!r} in the config. Known: "
                           f"{', '.join(config.sessions) or 'none'}")
        self.started = time.time()
        self.stop_flag = threading.Event()
        self.events: deque = deque(maxlen=500)  # service-level audit (net actions)
        self.sessions: dict = sessions if sessions is not None else {
            sid: Session(sc) for sid, sc in config.sessions.items()
            if only_session is None or sid == only_session}
        self.threads: list = []
        self.httpd = None
        from .outputs import OutputLayer
        self.outputs = OutputLayer(config.outputs, config.island_rest, config.transformers_path)
        for s in self.sessions.values():
            s.on_tracks = self.outputs.publish
        self._warn_double_publish()

    def _warn_double_publish(self):
        """One track path per sensor (ADR 0002): a session whose messages are forwarded to a
        receiver that publishes tracks (e.g. a Billie kid) must not also feed an output that
        publishes the same tracks."""
        for o in self.outputs.outputs:
            if not o.enabled:
                continue
            for sid, s in self.sessions.items():
                if o.wants(sid) and s.cfg.forward:
                    self.event("outputs", f"session {sid} forwards to "
                               f"{', '.join(s.cfg.forward)} and feeds output {o.name}: make sure "
                               "the forward receiver does not also publish these tracks "
                               "(one track path per sensor)", level="warn")

    # -------------------------------------------------------------- audit
    def event(self, kind: str, msg: str, level: str = "info", source: str = "core"):
        ts = time.time()
        iso = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        self.events.append({"time": iso, "ts": ts, "kind": kind, "level": level,
                            "source": source, "message": msg})
        log.info("[service] %s (%s): %s", kind, source, msg)

    # -------------------------------------------------------------- run
    def start(self, http: bool = True):
        for s in self.sessions.values():
            s.start()
        t = threading.Thread(target=self._scheduler, name="scapegoat-scheduler", daemon=True)
        t.start()
        self.threads.append(t)
        if self.config.island_rest:
            t = threading.Thread(target=self._island, name="scapegoat-island", daemon=True)
            t.start()
            self.threads.append(t)
        self.outputs.start()
        if http:
            from scapegoat.api.http import make_server
            self.httpd = make_server(self, self.config.bind_addr)
            t = threading.Thread(target=self.httpd.serve_forever, name="scapegoat-http",
                                 daemon=True)
            t.start()
            self.threads.append(t)
            host, port = self.httpd.server_address[:2]
            log.info("scapegoat %s API and web page on http://%s:%s/", VERSION, host, port)

    def stop(self):
        self.stop_flag.set()
        self.outputs.stop()
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        for s in self.sessions.values():
            s.stop()

    def _scheduler(self):
        intervals = [s.interval for s in self.sessions.values() if s.interval > 0] or [1.0]
        step = min(0.5, max(0.01, min(intervals) / 20))
        while not self.stop_flag.wait(step):
            for s in list(self.sessions.values()):
                try:
                    s.tick()
                except Exception as exc:
                    log.exception("tick failed for %s: %s", s.id, exc)

    # -------------------------------------------------------------- island publish
    def _island(self):
        base = self.config.island_rest.rstrip("/")
        last_err_log = 0.0
        while not self.stop_flag.wait(ISLAND_EVERY_S):
            for sid, s in list(self.sessions.items()):
                body = json.dumps(dict(s.status(), node=self.config.node_name,
                                       time=time.time())).encode()
                for url in self.island_urls(sid):
                    req = urllib.request.Request(url, data=body, method="PUT",
                                                 headers={"Content-Type": "application/json"})
                    try:
                        with urllib.request.urlopen(req, timeout=3) as r:
                            r.read()
                    except Exception as exc:
                        now = time.monotonic()
                        if now - last_err_log > ISLAND_ERROR_LOG_EVERY_S:
                            last_err_log = now
                            self.event("island", f"publish to {url} failed: {exc} "
                                                 "(logged at most once a minute)", level="warn")

    def island_urls(self, sid: str) -> list:
        """scapegoat/<node>/<session>/status (plus any topic a site extension adds)."""
        base = self.config.island_rest.rstrip("/")
        urls = [f"{base}/scapegoat/{self.config.node_name}/{sid}/status"]
        return urls + ext.extra_island_urls(base, self.config, sid)

    # -------------------------------------------------------------- API helpers
    def health(self) -> dict:
        return {"ok": True, "version": VERSION, "node_name": self.config.node_name,
                "uptime_s": round(time.time() - self.started, 1),
                "sessions": len(self.sessions),
                "profile": self.config.profile or None,
                "config_path": self.config.path,
                "allow_net_control": self.config.allow_net_control,
                "expected_local": localaddr.check(self.config.expected_local_address),
                "topology": self.config.topology or "auto",
                "identity": self.identity(),
                "outputs": self.outputs.status()}

    def identity(self) -> dict:
        """Which machine this is, for the first line of every page and of `scapegoat status`."""
        from . import node
        n = node.snapshot(self.config)
        b = n.get("billie") or {}
        role = self.config.node_role
        handle = b.get("node_handle")
        mesh = next((a["cidr"].split("/")[0] for a in n.get("addresses", [])
                     if a["role"] == "NetBird mesh" and a["family"] == "ipv4"), None)
        slot = b.get("billie_fabric_prefix")
        slot_short = slot if not slot or len(str(slot)) <= 24 else f"{str(slot)[:10]}…{str(slot)[-10:]}"
        title = n.get("hostname", "?") + " · " + (role or handle or "role not set")
        return {"hostname": n.get("hostname"), "node_role": role or None,
                "role_note": "" if role else "role not set (node_role in scapegoat.toml)",
                "billie_node": handle, "mesh_address": mesh, "slot": slot,
                "slot_short": slot_short, "title": title,
                "sensor_sees": [{"session": sid, "address": s.local_seen_as()}
                               for sid, s in self.sessions.items()]}

    def net_snapshot(self) -> dict:
        return _net("visibility", "snapshot")(self.config)

    def net_run(self, name: str, args: dict, source: str = "api"):
        fn = _net("control", "run")
        shown = {k: v for k, v in args.items()}
        self.event("net", f"net {name} {json.dumps(shown, sort_keys=True)}", source=source)
        result = fn(name, args, self.config)
        self.event("net", f"net {name} result: {json.dumps(result, default=str)[:400]}",
                   source=source)
        return result


def run_forever(config: Config, only_session: str | None = None):
    """Start everything and block until SIGTERM / Ctrl-C."""
    svc = Service(config, only_session=only_session)
    svc.start(http=True)
    done = threading.Event()

    def _stop(*_):
        done.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        while not done.wait(1.0):
            pass
    finally:
        log.info("stopping")
        svc.stop()
    return 0
