"""
Hardware statistics collection using psutil.
KISS - Keep It Simple Stupid approach.
"""

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

import logging
import platform
import time

logger = logging.getLogger("HardwareStats")


class HardwareStatsCollector:
    def __init__(self):

        self.start_time = time.time()
        # Stable optional metadata: probe once, including when sources are absent.
        self._hardware_models = self._get_hardware_models()

    @staticmethod
    def _get_hardware_models():
        models = {}
        if platform.system() != "Linux":
            return models
        for path in (
            "/sys/firmware/devicetree/base/model",
            "/proc/device-tree/model",
            "/sys/class/dmi/id/product_name",
        ):
            try:
                with open(path, "rb") as source:
                    raw = source.read(513)
                if len(raw) <= 512:
                    model = raw.decode("utf-8").rstrip("\x00").strip()
                    if HardwareStatsCollector._valid_model(model):
                        models["system"] = model
                        break
            except (OSError, UnicodeError):
                continue

        # Only descriptive CPU fields: numeric model/processor IDs and ARM
        # Hardware identify something else. Never expose Serial/UUID fields.
        try:
            with open("/proc/cpuinfo", "rb") as source:
                raw = source.read(65536)
            # Ignore an incomplete final line rather than publishing a prefix.
            lines = raw.rpartition(b"\n")[0].decode("utf-8").splitlines()
            candidates = {}
            for line in lines:
                key, sep, value = line.partition(":")
                key = key.strip().lower()
                model = value.strip()
                if (
                    sep
                    and key in ("model name", "cpu model", "processor")
                    and HardwareStatsCollector._valid_model(model)
                    and not model.isdecimal()
                ):
                    candidates.setdefault(key, model)
            for key in ("model name", "cpu model", "processor"):
                if key in candidates:
                    models["cpu"] = candidates[key]
                    break
        except (OSError, UnicodeError):
            pass
        return models

    @staticmethod
    def _valid_model(model):
        return (
            bool(model)
            and len(model) <= 512
            and all(char.isprintable() for char in model)
            and model.casefold()
            not in {
                "unknown",
                "none",
                "not specified",
                "not applicable",
                "default string",
                "system product name",
                "to be filled by o.e.m.",
                "to be filled by o.e.m",
            }
        )

    def get_stats(self):

        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available - cannot collect hardware stats")
            return {"error": "psutil library not available - cannot collect hardware statistics"}

        try:
            # Get current timestamp
            now = time.time()

            # CPU stats
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()

            # Memory stats
            memory = psutil.virtual_memory()

            # Disk stats
            disk = psutil.disk_usage("/")

            # Network stats (total across all interfaces)
            net_io = psutil.net_io_counters()

            # Load average (Unix only)
            load_avg = None
            try:
                load_avg = psutil.getloadavg()
            except (AttributeError, OSError):
                # Not available on all systems - use zeros
                load_avg = (0.0, 0.0, 0.0)

            # System boot time
            boot_time = psutil.boot_time()
            system_uptime = now - boot_time
            system_info = self._get_system_info()

            # Temperature (if available)
            temperatures = {}
            try:
                temps = psutil.sensors_temperatures()
                for name, entries in temps.items():
                    for i, entry in enumerate(entries):
                        temp_name = f"{name}_{i}" if len(entries) > 1 else name
                        temperatures[temp_name] = entry.current
            except (AttributeError, OSError):
                # Temperature sensors not available
                pass

            # Format data structure to match Vue component expectations
            stats = {
                "cpu": {
                    "usage_percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": cpu_freq.current if cpu_freq else 0,
                    "load_avg": {"1min": load_avg[0], "5min": load_avg[1], "15min": load_avg[2]},
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "usage_percent": memory.percent,
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "usage_percent": round((disk.used / disk.total) * 100, 1),
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                },
                "system": {
                    "uptime": system_uptime,
                    "boot_time": boot_time,
                    "os": system_info["os"],
                    "kernel": system_info["kernel"],
                    "arch": system_info["arch"],
                },
            }

            for section, model in self._hardware_models.items():
                stats[section]["model"] = model

            # Add temperatures if available
            if temperatures:
                stats["temperatures"] = temperatures

            return stats

        except Exception as e:
            logger.error(f"Error collecting hardware stats: {e}")
            return {"error": str(e)}

    @staticmethod
    def _get_system_info(os_release_path="/etc/os-release"):
        os_name = None
        try:
            with open(os_release_path, "r", encoding="utf-8") as f:
                for line in f:
                    key, sep, value = line.partition("=")
                    if sep and key == "PRETTY_NAME":
                        os_name = value.strip().strip('"')
                        break
        except OSError:
            os_name = None

        return {
            "os": os_name or platform.system(),
            "kernel": platform.release(),
            "arch": platform.machine(),
        }

    def get_processes_summary(self, limit=10):
        """
        Get top processes by CPU and memory usage.
        Returns a dictionary with process information in the format expected by the UI.
        """
        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available - cannot collect process stats")
            return {
                "processes": [],
                "total_processes": 0,
                "error": "psutil library not available - cannot collect process statistics",
            }

        try:
            processes = []

            # Get all processes
            for proc in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_percent", "memory_info"]
            ):
                try:
                    pinfo = proc.info
                    # Calculate memory in MB
                    memory_mb = 0
                    if pinfo["memory_info"]:
                        memory_mb = pinfo["memory_info"].rss / 1024 / 1024  # RSS in MB

                    process_data = {
                        "pid": pinfo["pid"],
                        "name": pinfo["name"] or "Unknown",
                        "cpu_percent": pinfo["cpu_percent"] or 0.0,
                        "memory_percent": pinfo["memory_percent"] or 0.0,
                        "memory_mb": round(memory_mb, 1),
                    }
                    processes.append(process_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Sort by CPU usage and get top processes
            top_processes = sorted(processes, key=lambda x: x["cpu_percent"], reverse=True)[:limit]

            return {"processes": top_processes, "total_processes": len(processes)}

        except Exception as e:
            logger.error(f"Error collecting process stats: {e}")
            return {"processes": [], "total_processes": 0, "error": str(e)}
