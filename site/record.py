#!/usr/bin/env python3
"""Record the landing page's first screen: a real scapegoat session against the toy simulator.

    python3 -I site/record.py          # writes site/session.json (about 40 s)

It starts `scapegoat serve` with the laptop config (deploy/scapegoat.toml, profile
sim-local) on loopback, starts `scapegoat sim toy` a few seconds later, stops the
simulator once the link is established, and starts it again after the link is lost.
Every event and every message the service logs is kept, with its time from the start.
Nothing leaves 127.0.0.1. Standard library only.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "site", "session.json")
API = "http://127.0.0.1:18730"
PY = [sys.executable, "-m", "scapegoat"]


def get(path):
    with urllib.request.urlopen(API + path, timeout=5) as r:
        return json.load(r)


def state():
    try:
        return get("/api/sessions/sensor")["state"]
    except Exception:
        return None


def wait_for(want, limit):
    end = time.time() + limit
    while time.time() < end:
        if state() == want:
            return True
        time.sleep(0.2)
    raise SystemExit(f"record: session never reached {want!r} in {limit} s")


def sim():
    return subprocess.Popen(PY + ["sim", "toy", "--bind", "127.0.0.1:47001"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = os.path.join(tmp, "scapegoat.toml")
        with open(os.path.join(ROOT, "deploy", "scapegoat.toml")) as f:
            base = f.read()
        with open(cfg, "w") as f:
            f.write(base + '\nbind = "127.0.0.1:18730"\n')
        serve = subprocess.Popen(PY + ["serve", "--config", cfg], cwd=ROOT,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        peer = None
        try:
            wait_for("handshaking", 15)
            time.sleep(4)
            peer = sim()
            wait_for("established", 30)
            time.sleep(7)
            peer.terminate(); peer.wait()
            wait_for("lost", 30)
            time.sleep(2)
            peer = sim()
            wait_for("established", 30)
            time.sleep(4)
            events = get("/api/sessions/sensor/events")
            traffic = get("/api/sessions/sensor/traffic?limit=500")
        finally:
            for p in (peer, serve):
                if p and p.poll() is None:
                    p.terminate(); p.wait()
    start = events[0]["ts"]
    lines = []
    for e in events:
        lines.append({"t": round(e["ts"] - start, 2), "kind": e["kind"], "level": e["level"],
                      "text": e["message"]})
    for m in traffic["entries"]:
        text = m["summary"]
        if m["name"] == "Data" and "payload" in m["fields"]:
            text = "payload=" + repr(bytes.fromhex(m["fields"]["payload"]).decode("ascii", "replace"))
        lines.append({"t": round(m["ts"] - start, 2), "dir": m["direction"], "name": m["name"],
                      "text": text, "hex": m["hex"]})
    lines.sort(key=lambda x: x["t"])
    with open(OUT, "w") as f:
        json.dump({"source": "site/record.py: scapegoat serve (deploy/scapegoat.toml) "
                             "and scapegoat sim toy on 127.0.0.1",
                   "lines": lines}, f, indent=1)
        f.write("\n")
    states = [l["text"].split(":")[0] for l in lines if l.get("kind") == "state"]
    print(f"record: {len(lines)} lines -> site/session.json")
    for s_ in states:
        print("  ", s_)


if __name__ == "__main__":
    main()
