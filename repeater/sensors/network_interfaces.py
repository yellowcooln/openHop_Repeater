"""
Network interfaces sensor plug-in.

Requires: psutil (already a dependency for hardware_stats)

Config example:
  - type: network_interfaces
    name: "eth0"
    enabled: true
    auto_install_packages: false
    settings:
      interface: eth0   # Name of the network interface to monitor
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import SensorBase
from .registry import SensorRegistry


@SensorRegistry.register("network_interfaces")
class NetworkInterfacesSensor(SensorBase):
    sensor_type = "network_interfaces"

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None, log=None):
        super().__init__(name=name, config=config, log=log)

        self.interface_name = str(self.settings.get("interface", "eth0"))

        if not self.ensure_python_modules([("psutil", "psutil")]):
            return

        import psutil  # type: ignore[import-not-found]

        self._psutil = psutil
        self._available = self.interface_name in psutil.net_io_counters(pernic=True)
        if not self._available:
            self.log.warning(
                "Network interface %s not found (available: %s)",
                self.interface_name,
                list(psutil.net_io_counters(pernic=True).keys()),
            )

    def _read(self) -> Dict[str, Any]:
        """Read network interface statistics."""
        if not self._available:
            raise RuntimeError(f"Network interface {self.interface_name} not available")

        net_io = self._psutil.net_io_counters(pernic=True).get(self.interface_name)
        if net_io is None:
            raise RuntimeError(f"Network interface {self.interface_name} vanished")

        stats = self._psutil.net_if_stats().get(self.interface_name)
        addrs = self._psutil.net_if_addrs().get(self.interface_name, [])

        ip_addresses = []
        mac_address = None
        for addr in addrs:  # type: ignore[union-attr]
            if addr.family == self._psutil.AF_LINK:  # type: ignore[attr-defined]
                mac_address = addr.address
            elif addr.family in (self._psutil.AF_INET, self._psutil.AF_INET6):  # type: ignore[attr-defined]
                ip_addresses.append(f"{addr.address}/{addr.netmask}")

        result = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errin": net_io.errin,
            "errout": net_io.errout,
            "dropin": net_io.dropin,
            "dropout": net_io.dropout,
        }

        if stats:
            result["is_up"] = stats.isup
            result["speed_mbps"] = stats.speed or 0
            result["duplex"] = stats.duplex.name if hasattr(stats, "duplex") and stats.duplex else None  # type: ignore[union-attr]
            result["mtu"] = stats.mtu or 0

        if mac_address:
            result["mac_address"] = str(mac_address)  # type: ignore[assignment]
        if ip_addresses:
            result["ip_addresses"] = ip_addresses

        return result
