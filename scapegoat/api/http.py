"""JSON API and the web page. Standard library http.server only."""

from __future__ import annotations

import inspect
import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from scapegoat.core import ext
from scapegoat.core.session import ActionFailed, ActionRefused, ActionUnknown

log = logging.getLogger("scapegoat.api")

UI_FILE = Path(__file__).resolve().parent.parent / "ui" / "index.html"
PROBE_ACTIONS = {"ping", "capture", "udp_probe"}  # read-only: scapegoat.net.probe
MAX_BODY = 64 * 1024


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _source(handler) -> str:
    src = (ext.header(handler.headers, "X-Scapegoat-Source") or "api").strip().lower()
    return src if src in ("cli", "ui", "api") else "api"


def _who(handler) -> str:
    """Who/where for the audit trail: the CLI's user name, else the client address."""
    user = (ext.header(handler.headers, "X-Scapegoat-User") or "").strip()[:64]
    addr = handler.client_address[0] if getattr(handler, "client_address", None) else "?"
    return f"{user}@{addr}" if user else addr


def _call_probe(name: str, args: dict):
    import importlib
    try:
        mod = importlib.import_module("scapegoat.net.probe")
    except ImportError as exc:
        raise ApiError(501, f"network tools are not installed (scapegoat.net.probe: {exc})")
    fn = getattr(mod, name, None)
    if not callable(fn):
        raise ApiError(501, f"scapegoat.net.probe has no {name}()")
    params = inspect.signature(fn).parameters
    kwargs = {k: v for k, v in args.items() if k in params}
    try:
        return fn(**kwargs)
    except (TypeError, ValueError) as exc:
        raise ApiError(400, f"{name}: {exc}")


class Handler(BaseHTTPRequestHandler):
    server_version = "scapegoat"
    service = None  # set by make_server

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    # ----------------------------------------------------------------- plumbing
    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj):
        self._send(status, json.dumps(obj, default=str).encode(), "application/json")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError(400, "request body too large")
        if n == 0:
            return {}
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise ApiError(400, "request body must be JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "request body must be a JSON object")
        return data

    def _session(self, sid: str):
        s = self.service.sessions.get(sid)
        if s is None:
            raise ApiError(404, f"no session named {sid!r}. Known: "
                                f"{', '.join(self.service.sessions) or 'none'}")
        return s

    def _dispatch(self, method: str):
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        query = parse_qs(url.query)
        try:
            status, obj = self._route(method, path, query)
        except ApiError as exc:
            status, obj = exc.status, {"error": str(exc)}
        except ActionRefused as exc:
            status, obj = 403, {"error": str(exc)}
        except ActionUnknown as exc:
            status, obj = 404, {"error": str(exc)}
        except ActionFailed as exc:
            status, obj = 400, {"error": str(exc)}
        except Exception as exc:
            log.exception("API error on %s %s", method, self.path)
            status, obj = 500, {"error": f"internal error: {exc}"}
        if isinstance(obj, bytes):
            self._send(status, obj, "text/html; charset=utf-8")
        else:
            self._json(status, obj)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    # ----------------------------------------------------------------- routes
    def _route(self, method, path, query):
        svc = self.service
        if method == "GET" and path in ("/", "/index.html"):
            try:
                return 200, UI_FILE.read_bytes()
            except OSError:
                raise ApiError(404, "web page file is missing (scapegoat/ui/index.html)")
        if method == "GET" and path == "/api/health":
            return 200, svc.health()
        if method == "GET" and path == "/api/sessions":
            return 200, [s.status() for s in svc.sessions.values()]
        m = re.fullmatch(r"/api/sessions/([^/]+)", path)
        if m and method == "GET":
            return 200, self._session(m.group(1)).status(events=50)
        m = re.fullmatch(r"/api/sessions/([^/]+)/events", path)
        if m and method == "GET":
            try:
                n = int(query.get("n", ["200"])[0])
            except ValueError:
                raise ApiError(400, "n must be a number")
            return 200, self._session(m.group(1)).get_events(n)
        m = re.fullmatch(r"/api/sessions/([^/]+)/traffic", path)
        if m and method == "GET":
            s = self._session(m.group(1))
            try:
                since = int(query["since"][0]) if "since" in query else None
                limit = int(query.get("limit", ["200"])[0])
            except ValueError:
                raise ApiError(400, "since and limit must be numbers")
            return 200, s.get_traffic(since, limit)
        m = re.fullmatch(r"/api/sessions/([^/]+)/wire", path)
        if m and method == "GET":
            s = self._session(m.group(1))
            try:
                seconds = float(query.get("seconds", ["10"])[0])
            except ValueError:
                raise ApiError(400, "seconds must be a number")
            iface = query.get("iface", ["any"])[0]
            if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,15}", iface):
                raise ApiError(400, "bad interface name")
            svc.event("wire", f"wire capture {seconds:g}s on {s.id} port {s.local[1]}",
                      source=_source(self))
            return 200, s.wire(seconds, iface)
        m = re.fullmatch(r"/api/sessions/([^/]+)/actions/([^/]+)", path)
        if m and method == "POST":
            body = self._body()
            s = self._session(m.group(1))
            args = body.get("args") or {}
            if not isinstance(args, dict):
                raise ApiError(400, "args must be an object")
            return 200, s.run_action(m.group(2).replace("-", "_"), confirm=body.get("confirm"),
                                     source=_source(self), args=args, token=body.get("token"),
                                     who=_who(self))
        m = re.fullmatch(r"/api/sessions/([^/]+)/(arm|disarm)/([^/]+)", path)
        if m and method == "POST":
            body = self._body()
            s = self._session(m.group(1))
            name = m.group(3).replace("-", "_")
            if m.group(2) == "arm":
                return 200, s.arm(name, source=_source(self), who=_who(self),
                                  args=body.get("args") or {})
            return 200, s.disarm(name, source=_source(self), who=_who(self))
        m = re.fullmatch(r"/api/sessions/([^/]+)/(enable|disable|reset)", path)
        if m and method == "POST":
            self._body()
            s = self._session(m.group(1))
            getattr(s, m.group(2))(source=_source(self))
            return 200, s.status()
        m = re.fullmatch(r"/api/sessions/([^/]+)/lock", path)
        if m and method == "POST":
            body = self._body()
            s = self._session(m.group(1))
            if not body.get("peer"):
                raise ApiError(400, 'give the address to lock onto: {"peer": "IP:PORT"}')
            s.force_lock(str(body["peer"]), source=_source(self))
            return 200, s.status()
        if method == "GET" and path == "/api/outputs":
            return 200, svc.outputs.status()
        if method == "GET" and path == "/api/node":
            from scapegoat.core import node
            lo = query.get("loopback", ["0"])[0] in ("1", "true", "yes")
            return 200, node.snapshot(svc.config, include_loopback=lo)
        if method == "GET" and path == "/api/profiles":
            from scapegoat.core.config import list_profiles
            return 200, list_profiles(svc.config.get("profiles_dir"))
        if method == "GET" and path == "/api/events":
            return 200, list(svc.events)
        if method == "GET" and path == "/api/net":
            from scapegoat.core.service import NetUnavailable
            try:
                return 200, svc.net_snapshot()
            except NetUnavailable as exc:
                raise ApiError(501, str(exc))
        m = re.fullmatch(r"/api/net/([a-z_]+)", path)
        if m and method == "POST":
            return self._net_action(m.group(1), self._body())
        raise ApiError(404, f"no such endpoint: {method} {path}")

    def _net_action(self, name: str, body: dict):
        svc = self.service
        src = _source(self)
        if name in PROBE_ACTIONS:
            svc.event("net", f"net {name} {json.dumps(body, sort_keys=True)}", source=src)
            return 200, _call_probe(name, body)
        from scapegoat.core.service import NetUnavailable
        if not svc.config.allow_net_control:
            svc.event("refused", f"net {name} refused: allow_net_control is false",
                      level="warn", source=src)
            raise ApiError(403, "network control is off. Set allow_net_control = true in the "
                                "config and restart scapegoat, then repeat with confirm.")
        if body.get("confirm") is not True:
            svc.event("refused", f"net {name} refused: not confirmed", level="warn", source=src)
            raise ApiError(403, f"net {name} changes the node's network: repeat it with "
                                "confirm (--confirm on the CLI).")
        try:
            result = svc.net_run(name, body, source=src)
        except NetUnavailable as exc:
            raise ApiError(501, str(exc))
        except PermissionError as exc:
            raise ApiError(403, str(exc))
        except (ValueError, KeyError, TypeError) as exc:
            raise ApiError(400, f"net {name}: {exc}")
        if isinstance(result, dict) and result.get("ok") is False:
            msg = str(result.get("error") or result.get("message") or f"net {name} failed")
            return (403 if msg.startswith("refused") else 400), dict(result, error=msg)
        return 200, result


def make_server(service, addr) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"service": service})
    httpd = ThreadingHTTPServer(tuple(addr), handler)
    httpd.daemon_threads = True
    return httpd
