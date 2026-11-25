import socket
import time

from scapegoat.core.config import from_dict


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_config(sensor_port, local_port, forward=(), allow_radiate=False, interval=0.2,
                allow_net=False, candidates=None, extra=None):
    data = {
        "bind": "127.0.0.1:0",
        "allow_net_control": allow_net,
        "node_name": "test-node",
        "sessions": {"sensor": {
            "protocol": "fake", "enabled": True,
            "local": f"127.0.0.1:{local_port}", "peer": f"127.0.0.1:{sensor_port}",
            "forward": list(forward), "allow_radiate_control": allow_radiate,
            "protocol_settings": {"keepalive_interval_s": interval, "establish_after": 3,
                                  "device_id": 1},
        }},
    }
    if candidates is not None:
        s = data["sessions"]["sensor"]
        s["peer"] = ""
        s["peer_candidates"] = list(candidates)
    data.update(extra or {})
    return from_dict(data)


def wait_for(pred, timeout=5.0, step=0.02):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return False
