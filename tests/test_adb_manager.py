"""Tests del ADBManager usando mocks de subprocess."""

from unittest.mock import MagicMock, patch

import pytest

from bazzingakit.config.models import DeviceProfile, Platform
from bazzingakit.core import ADBManager


@pytest.fixture
def profile():
    return DeviceProfile(
        name="test",
        platform=Platform.ANDROID,
        adb_path="/usr/bin/adb",
    )


@pytest.fixture
def nox_profile():
    return DeviceProfile(
        name="nox",
        platform=Platform.ANDROID,
        adb_path="/opt/nox/nox_adb",
        adb_port=62001,
    )


def test_platform(profile):
    mgr = ADBManager(profile)
    assert mgr.platform == "android"


def test_adb_binary_uses_custom_path(nox_profile):
    mgr = ADBManager(nox_profile)
    assert mgr.adb_binary == "/opt/nox/nox_adb"


def test_adb_binary_defaults_to_adb():
    profile = DeviceProfile(name="default", platform=Platform.ANDROID)
    mgr = ADBManager(profile)
    assert mgr.adb_binary == "adb"


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_is_available_returns_true_when_adb_responds(mock_run, profile):
    with patch("bazzingakit.core.adb_manager.Path") as mock_path:
        mock_path.return_value.exists.return_value = True
        mock_run.return_value = MagicMock(returncode=0, stdout="Android Debug Bridge")
        mgr = ADBManager(profile)
        assert mgr.is_available() is True


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_is_available_returns_false_when_binary_missing(mock_run, profile):
    with patch("bazzingakit.core.adb_manager.Path") as mock_path:
        mock_path.return_value.exists.return_value = False
        mgr = ADBManager(profile)
        assert mgr.is_available() is False


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_list_devices_parses_output(mock_run, profile):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=(
            "List of devices attached\n"
            "emulator-5554   device product:sdk_phone model:Pixel_3a device:generic\n"
            "192.168.1.10:5555   offline\n"
        ),
    )
    mgr = ADBManager(profile)
    devices = mgr.list_devices()

    assert len(devices) == 2
    assert devices[0].identifier == "emulator-5554"
    assert devices[0].is_online is True
    assert devices[0].model == "Pixel_3a"
    assert devices[1].is_online is False


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_list_devices_empty(mock_run, profile):
    mock_run.return_value = MagicMock(
        returncode=0, stdout="List of devices attached\n\n"
    )
    mgr = ADBManager(profile)
    assert mgr.list_devices() == []


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_shell_includes_serial_when_configured(mock_run):
    profile = DeviceProfile(
        name="test",
        platform=Platform.ANDROID,
        adb_path="/usr/bin/adb",
        device_serial="emulator-5554",
    )
    mock_run.return_value = MagicMock(returncode=0, stdout="OK", stderr="")
    mgr = ADBManager(profile)
    mgr.shell("echo hello")

    call_args = mock_run.call_args[0][0]
    assert "-s" in call_args
    assert "emulator-5554" in call_args
    assert "shell" in call_args


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_get_apk_path(mock_run, profile):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="package:/data/app/com.example.app-1/base.apk\n",
        stderr="",
    )
    mgr = ADBManager(profile)
    path = mgr.get_apk_path("com.example.app")
    assert path == "/data/app/com.example.app-1/base.apk"


@patch("bazzingakit.core.adb_manager.subprocess.run")
def test_list_packages(mock_run, profile):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=(
            "package:com.example.app1\n"
            "package:com.example.app2\n"
            "package:com.example.app3\n"
        ),
        stderr="",
    )
    mgr = ADBManager(profile)
    packages = mgr.list_packages()
    assert len(packages) == 3
    assert "com.example.app1" in packages
    assert packages == sorted(packages)
