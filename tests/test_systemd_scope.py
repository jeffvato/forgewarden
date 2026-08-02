import json
import os
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from swarm.adapters import ResourceLimits, _minimal_test_environment, limited_run
from swarm.core import SwarmError


def _user_bus_available() -> bool:
    if shutil.which("systemd-run") is None:
        return False
    uid = os.getuid()
    bus = Path("/run/user") / str(uid) / "bus"
    if not bus.is_socket():
        return False
    result = subprocess.run(
        ["systemctl", "--user", "show-environment"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


class SystemdScopeSafetyTests(unittest.TestCase):
    def test_cgroup_mode_fails_closed_without_network_isolating_scope(self):
        with patch("swarm.adapters.shutil.which", return_value=None):
            with self.assertRaisesRegex(SwarmError, "network-isolated execution"):
                limited_run(
                    ["/bin/true"],
                    Path.cwd(),
                    "",
                    ResourceLimits(timeout_seconds=5),
                    use_cgroup=True,
                )


@unittest.skipUnless(_user_bus_available(), "user systemd bus is unavailable in this execution context")
class SystemdScopeIntegrationTests(unittest.TestCase):
    def test_real_scope_receives_bus_environment_and_memory_controls(self):
        limits = ResourceLimits(memory_bytes=2_147_483_648, timeout_seconds=30)
        probe = (
            "import json, os, pathlib; "
            "cg=pathlib.Path('/proc/self/cgroup').read_text(); "
            "paths=[pathlib.Path('/sys/fs/cgroup')/p.split(':',2)[2].strip('/') for p in cg.splitlines() if p.startswith('0::')]; "
            "path=next((p for p in paths if (p/'memory.max').exists()), pathlib.Path('/sys/fs/cgroup')); "
            "print(json.dumps({'pid':os.getpid(),'xdg':os.environ.get('XDG_RUNTIME_DIR'),"
            "'dbus':os.environ.get('DBUS_SESSION_BUS_ADDRESS'),'cgroup_path':str(path.relative_to('/sys/fs/cgroup')),"
            "'memory_max':(path/'memory.max').read_text().strip(),"
            "'swap_max':(path/'memory.swap.max').read_text().strip()}))"
        )
        result = limited_run(
            ["/home/jeff/anaconda3/bin/python3", "-c", probe],
            Path.cwd(),
            "",
            limits,
            use_cgroup=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout.strip())
        uid = os.getuid()
        self.assertEqual(evidence["xdg"], f"/run/user/{uid}")
        self.assertEqual(evidence["dbus"], f"unix:path=/run/user/{uid}/bus")
        self.assertEqual(evidence["memory_max"], "2147483648")
        self.assertEqual(evidence["swap_max"], "0")
        cgroup = Path("/sys/fs/cgroup") / evidence["cgroup_path"]
        for _ in range(20):
            if not cgroup.exists():
                break
            time.sleep(0.05)
        self.assertFalse(cgroup.exists())
