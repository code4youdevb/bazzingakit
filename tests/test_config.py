"""Tests del sistema de configuración."""

from pathlib import Path

import pytest

from bazzingakit.config import (
    BazzingakitConfig,
    DeviceProfile,
    Platform,
    add_profile,
    load_config,
    save_config,
    set_active_profile,
)


def test_empty_config():
    cfg = BazzingakitConfig()
    assert cfg.active_profile is None
    assert cfg.profiles == {}
    assert cfg.ai.enabled is False


def test_add_profile_sets_active_first():
    cfg = BazzingakitConfig()
    p = DeviceProfile(name="nox", platform=Platform.ANDROID, adb_path="/opt/nox_adb")
    add_profile(cfg, p)
    assert cfg.active_profile == "nox"
    assert "nox" in cfg.profiles


def test_add_second_profile_keeps_first_active():
    cfg = BazzingakitConfig()
    add_profile(cfg, DeviceProfile(name="a", platform=Platform.ANDROID))
    add_profile(cfg, DeviceProfile(name="b", platform=Platform.IOS, ssh_host="1.2.3.4"))
    assert cfg.active_profile == "a"


def test_set_active_profile():
    cfg = BazzingakitConfig()
    add_profile(cfg, DeviceProfile(name="a", platform=Platform.ANDROID))
    add_profile(cfg, DeviceProfile(name="b", platform=Platform.ANDROID))
    set_active_profile(cfg, "b")
    assert cfg.active_profile == "b"


def test_set_unknown_profile_raises():
    cfg = BazzingakitConfig()
    with pytest.raises(ValueError):
        set_active_profile(cfg, "nonexistent")


def test_get_active_profile():
    cfg = BazzingakitConfig()
    p = DeviceProfile(name="nox", platform=Platform.ANDROID)
    add_profile(cfg, p)
    active = cfg.get_active_profile()
    assert active is not None
    assert active.name == "nox"


def test_save_and_load_roundtrip(tmp_path: Path):
    path = tmp_path / "config.yaml"
    cfg = BazzingakitConfig()
    add_profile(
        cfg,
        DeviceProfile(
            name="nox",
            platform=Platform.ANDROID,
            adb_path="/opt/nox_adb",
            adb_port=62001,
        ),
    )
    save_config(cfg, path)

    loaded = load_config(path)
    assert loaded.active_profile == "nox"
    assert loaded.profiles["nox"].adb_path == "/opt/nox_adb"
    assert loaded.profiles["nox"].adb_port == 62001
