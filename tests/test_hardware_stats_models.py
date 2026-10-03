"""Read-only hardware model discovery, independent of host hardware."""

import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

# Load the leaf collector without unrelated daemon dependencies/package side effects.
spec = importlib.util.spec_from_file_location(
    "hardware_stats_models_test",
    Path(__file__).resolve().parents[1] / "repeater/data_acquisition/hardware_stats.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

DT = "/sys/firmware/devicetree/base/model"
PROC_DT = "/proc/device-tree/model"
DMI = "/sys/class/dmi/id/product_name"
CPUINFO = "/proc/cpuinfo"


@pytest.fixture
def sources(monkeypatch):
    files = {}
    reads = []

    def open_source(path, mode="r", **kwargs):
        reads.append(path)
        value = files.get(path, FileNotFoundError(path))
        if isinstance(value, Exception):
            raise value
        assert mode == "rb"
        return io.BytesIO(value)

    monkeypatch.setattr(module, "open", open_source, raising=False)
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    return files, reads


@pytest.fixture
def psutil_mock(monkeypatch):
    fake = Mock()
    fake.cpu_percent.return_value = 12.5
    fake.cpu_count.return_value = 4
    fake.cpu_freq.return_value = SimpleNamespace(current=1500)
    fake.virtual_memory.return_value = SimpleNamespace(
        total=1000, available=600, used=400, percent=40
    )
    fake.disk_usage.return_value = SimpleNamespace(total=2000, used=500, free=1500)
    fake.net_io_counters.return_value = SimpleNamespace(
        bytes_sent=1, bytes_recv=2, packets_sent=3, packets_recv=4
    )
    fake.getloadavg.return_value = (0.1, 0.2, 0.3)
    fake.boot_time.return_value = 100
    fake.sensors_temperatures.return_value = {}
    monkeypatch.setattr(module, "psutil", fake)
    monkeypatch.setattr(module, "PSUTIL_AVAILABLE", True)
    monkeypatch.setattr(module.time, "time", lambda: 200)
    monkeypatch.setattr(
        module.HardwareStatsCollector,
        "_get_system_info",
        staticmethod(lambda: {"os": "Test Linux", "kernel": "6.test", "arch": "aarch64"}),
    )
    return fake


def test_pi_model_in_stats_is_optional_and_cached(sources, psutil_mock):
    files, reads = sources
    files[DT] = b"Raspberry Pi 5 Model B Rev 1.0\x00"
    collector = module.HardwareStatsCollector()
    stats = collector.get_stats()
    assert stats["system"]["model"] == "Raspberry Pi 5 Model B Rev 1.0"
    assert "model" not in stats["cpu"]
    assert stats["cpu"]["usage_percent"] == 12.5
    assert stats["system"]["uptime"] == 100
    assert stats["disk"]["usage_percent"] == 25
    assert stats["network"]["bytes_recv"] == 2
    model_reads = list(reads)
    collector.get_stats()
    assert reads == model_reads


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({PROC_DT: b"FriendlyElec NanoPi\x00"}, {"system": "FriendlyElec NanoPi"}),
        ({DMI: b" OptiPlex 7050\n"}, {"system": "OptiPlex 7050"}),
        ({CPUINFO: b"model name\t: Intel(R) Xeon(R) CPU\n"}, {"cpu": "Intel(R) Xeon(R) CPU"}),
        ({CPUINFO: b"cpu model : POWER9\n"}, {"cpu": "POWER9"}),
        (
            {CPUINFO: b"Processor : ARMv7 Processor rev 5 (v7l)\n"},
            {"cpu": "ARMv7 Processor rev 5 (v7l)"},
        ),
        ({CPUINFO: b"processor : 0\nHardware : BCM2835\nSerial : private\n"}, {}),
        ({DMI: b"To Be Filled By O.E.M.\n", CPUINFO: b"model : 85\n"}, {}),
        (
            {DMI: b"QEMU\n", CPUINFO: b"model name : Virtual CPU\n"},
            {"system": "QEMU", "cpu": "Virtual CPU"},
        ),
    ],
)
def test_conservative_linux_fallbacks(sources, files, expected, monkeypatch):
    source_files, _ = sources
    source_files.update(files)
    monkeypatch.setattr(module.platform, "machine", lambda: "unusual-architecture")
    assert module.HardwareStatsCollector._get_hardware_models() == expected


@pytest.mark.parametrize("bad", [b"", b"\xff", b"bad\x00value", b"a" * 513, b"Unknown\n"])
def test_malformed_board_falls_back(sources, bad):
    files, _ = sources
    files[DT] = bad
    files[DMI] = b"Valid board\n"
    assert module.HardwareStatsCollector._get_hardware_models() == {"system": "Valid board"}


@pytest.mark.parametrize("error", [FileNotFoundError(), PermissionError(), OSError("denied")])
def test_unavailable_sources_do_not_break_stats(sources, psutil_mock, error):
    files, reads = sources
    files.update(dict.fromkeys((DT, PROC_DT, DMI, CPUINFO), error))
    collector = module.HardwareStatsCollector()
    stats = collector.get_stats()
    assert "error" not in stats
    assert "model" not in stats["system"]
    assert "model" not in stats["cpu"]
    assert set(stats) == {"cpu", "memory", "disk", "network", "system"}
    assert stats["system"] == {
        "uptime": 100,
        "boot_time": 100,
        "os": "Test Linux",
        "kernel": "6.test",
        "arch": "aarch64",
    }
    assert reads == [DT, PROC_DT, DMI, CPUINFO]
    collector.get_stats()
    assert reads == [DT, PROC_DT, DMI, CPUINFO]


def test_non_linux_does_not_probe_files(sources, monkeypatch):
    _, reads = sources
    monkeypatch.setattr(module.platform, "system", lambda: "Darwin")
    assert module.HardwareStatsCollector._get_hardware_models() == {}
    assert reads == []


def test_board_priority_cpu_priority_and_serial_ignored(sources, psutil_mock):
    files, reads = sources
    files.update(
        {
            DT: b"Pi\x00",
            DMI: b"Other\n",
            CPUINFO: (
                b"Serial : secret\nUUID : secret\nprocessor : 0\n"
                b"Processor : Generic processor\ncpu model : Other CPU\n"
                b"model name : Actual CPU\nmodel name : Second CPU\n"
            ),
        }
    )
    stats = module.HardwareStatsCollector().get_stats()
    assert stats["system"]["model"] == "Pi"
    assert stats["cpu"]["model"] == "Actual CPU"
    assert "secret" not in str(stats)
    assert reads == [DT, CPUINFO]


@pytest.mark.parametrize("raw", [b"model name : unfinished", b"model name : " + b"A" * 70000])
def test_cpuinfo_incomplete_line_is_not_a_model(sources, raw):
    files, _ = sources
    files[CPUINFO] = raw
    assert module.HardwareStatsCollector._get_hardware_models() == {}


def test_cpuinfo_is_bounded_but_retains_complete_first_cpu(sources):
    files, _ = sources
    files[CPUINFO] = b"model name : First CPU\n" + b"ignored : " + b"a" * 70000
    assert module.HardwareStatsCollector._get_hardware_models() == {"cpu": "First CPU"}


def test_malformed_cpuinfo_does_not_remove_board(sources):
    files, _ = sources
    files[DT] = b"Board\x00"
    files[CPUINFO] = b"model name : invalid\xff\n"
    assert module.HardwareStatsCollector._get_hardware_models() == {"system": "Board"}
