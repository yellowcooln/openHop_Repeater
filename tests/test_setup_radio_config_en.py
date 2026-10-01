"""Run the real shell hardware writer, never its network/service setup steps."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HARDWARE = json.loads((ROOT / "radio-settings.json").read_text())["hardware"]
SCALAR_PRESETS = [key for key, preset in HARDWARE.items() if "en_pin" in preset]


@pytest.fixture
def apply_hardware(tmp_path):
    script = (ROOT / "setup-radio-config.sh").read_text()
    start = script.index("# Extract hardware-specific settings")
    end = script.index("\n# Cleanup", start)
    # Execute the production block unchanged, with only local temporary inputs.
    # This deliberately excludes API fetching, /tmp cleanup and systemctl/sudo.
    block = script[start:end]
    config = tmp_path / "config.yaml"
    hardware = tmp_path / "radio-settings.json"

    def apply(preset, config_text):
        hardware.write_text(json.dumps({"hardware": {"test-board": preset}}))
        config.write_text(config_text)
        result = subprocess.run(
            [
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                'CONFIG_FILE="$1"; HARDWARE_CONFIG="$2"; hw_key=test-board; '
                "RADIO_TYPE=sx1262; SED_OPTS=(-i)\n" + block,
                "test-hardware-writer",
                str(config),
                str(hardware),
            ],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "LC_ALL": "C"},
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stderr == ""
        return config.read_text()

    return apply


def config_with_en(en_lines=""):
    return (
        "# Fixture configuration, not a production config\n"
        "radio_type: sx1262\n"
        "other_before:\n  en_pin: 77\n  en_pins: [78, 79]\n"
        "sx1262:\n"
        "  # Keep this hardware comment\n"
        "  custom_setting: untouched\n" + en_lines + "  rxen_pin: -1\n"
        "other_after:\n  en_pin: 80\n  en_pins: [81]\n"
    )


def assert_unrelated_preserved(output):
    assert "other_before:\n  en_pin: 77\n  en_pins: [78, 79]\n" in output
    assert output.endswith("other_after:\n  en_pin: 80\n  en_pins: [81]\n")
    assert "  # Keep this hardware comment\n  custom_setting: untouched\n" in output


@pytest.mark.parametrize("key", SCALAR_PRESETS)
@pytest.mark.parametrize("existing", ["", "  en_pin: 99 # previous board\n"])
def test_stock_scalar_en_presets_persist(apply_hardware, key, existing):
    output = apply_hardware(HARDWARE[key], config_with_en(existing))
    assert yaml.safe_load(output)["sx1262"]["en_pin"] == HARDWARE[key]["en_pin"]
    assert_unrelated_preserved(output)


@pytest.mark.parametrize("pin", [0, -1])
def test_scalar_en_edge_values_persist(apply_hardware, pin):
    output = apply_hardware({"en_pin": pin}, config_with_en())
    assert yaml.safe_load(output)["sx1262"]["en_pin"] == pin
    assert_unrelated_preserved(output)


LIST_PRESETS = [key for key, preset in HARDWARE.items() if "en_pins" in preset]


@pytest.mark.parametrize("key", LIST_PRESETS)
@pytest.mark.parametrize("existing", ["", "  en_pins: [99, 98] # previous board\n"])
def test_stock_list_en_presets_persist(apply_hardware, key, existing):
    output = apply_hardware(HARDWARE[key], config_with_en(existing))
    assert yaml.safe_load(output)["sx1262"]["en_pins"] == HARDWARE[key]["en_pins"]
    assert_unrelated_preserved(output)


@pytest.mark.parametrize("pins", [[], [0], [0, -1, 26]])
def test_list_en_edge_values_persist(apply_hardware, pins):
    output = apply_hardware({"en_pins": pins}, config_with_en())
    assert yaml.safe_load(output)["sx1262"]["en_pins"] == pins
    assert_unrelated_preserved(output)


@pytest.mark.parametrize(
    "existing",
    [
        "  en_pin: 99\n  en_pins: [98, 97]\n",
        "  en_pin: 99\n  en_pins:\n    - 98\n    - 97\n",
        "  en_pins:\n  - 98\n  - 97\n  en_pin: 99\n",
    ],
    ids=["inline-list", "indented-block-list", "indentless-block-list"],
)
@pytest.mark.parametrize("preset", [{"en_pin": 0}, {"en_pin": -1}, {"en_pins": [12, 13]}])
def test_en_selection_removes_stale_alternate(apply_hardware, existing, preset):
    output = apply_hardware(preset, config_with_en(existing))
    hardware = yaml.safe_load(output)["sx1262"]
    assert {key: value for key, value in hardware.items() if key in {"en_pin", "en_pins"}} == preset
    assert_unrelated_preserved(output)


def test_switching_scalar_list_scalar_uses_latest_selection(apply_hardware):
    output = config_with_en()
    for preset in [{"en_pin": 26}, {"en_pins": [12, 13]}, {"en_pin": -1}]:
        output = apply_hardware(preset, output)
        hardware = yaml.safe_load(output)["sx1262"]
        assert {
            key: value for key, value in hardware.items() if key in {"en_pin", "en_pins"}
        } == preset
        assert_unrelated_preserved(output)


@pytest.mark.parametrize("preset", [{}, {"en_pin": None, "en_pins": None}])
def test_unspecified_en_leaves_existing_config_unchanged(apply_hardware, preset):
    # Characterize the existing optional-field contract: absence is not disable.
    original = config_with_en("  en_pin: 26\n")
    assert apply_hardware(preset, original) == original


def test_en_block_replacement_preserves_neighbor_sequences(apply_hardware):
    original = config_with_en(
        "  en_pins:\n"
        "    # Keep this list comment\n"
        "    - 98\n"
        "\n"
        "    - 97\n"
        "  custom_list:\n"
        "    - keep\n"
        "    - these\n"
    )
    output = apply_hardware({"en_pin": 26}, original)
    hardware = yaml.safe_load(output)["sx1262"]
    assert hardware["en_pin"] == 26
    assert "en_pins" not in hardware
    assert "    # Keep this list comment\n" in output
    assert "  custom_list:\n    - keep\n    - these\n" in output
    assert_unrelated_preserved(output)
