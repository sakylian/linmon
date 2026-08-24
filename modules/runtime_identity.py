"""Runtime identity shared by scanners.

The monitor must never classify its own listener as a backdoor.  Keeping this
state in a tiny module avoids circular imports between the process, network and
web layers.
"""

import os
import threading


_lock = threading.RLock()
_identity = {
    'pid': os.getpid(),
    'ports': set(),
    'name': 'linmon',
}


def configure_monitor_identity(pid=None, ports=None, name='linmon'):
    """Register the current monitor process and the ports it intentionally owns."""
    with _lock:
        if pid is not None:
            _identity['pid'] = int(pid)
        if ports is not None:
            _identity['ports'] = {int(p) for p in ports if int(p) > 0}
        if name:
            _identity['name'] = str(name)
        return get_monitor_identity()


def get_monitor_identity():
    with _lock:
        return {
            'pid': _identity['pid'],
            'ports': set(_identity['ports']),
            'name': _identity['name'],
        }


def is_monitor_process(pid):
    try:
        return int(pid) == get_monitor_identity()['pid']
    except (TypeError, ValueError):
        return False


def is_monitor_port(local_port):
    try:
        return int(local_port) in get_monitor_identity()['ports']
    except (TypeError, ValueError):
        return False


def is_monitor_listener(pid, local_port):
    ident = get_monitor_identity()
    try:
        return int(pid) == ident['pid'] and int(local_port) in ident['ports']
    except (TypeError, ValueError):
        return False
