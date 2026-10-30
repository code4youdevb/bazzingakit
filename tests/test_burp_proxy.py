"""Tests del BurpProxyManager."""

from unittest.mock import MagicMock, patch

import pytest

from bazzingakit.core import BurpProxyError, BurpProxyManager


@pytest.fixture
def mock_device():
    return MagicMock()


@pytest.fixture
def burp(mock_device):
    return BurpProxyManager(mock_device)


def test_check_openssl_present():
    with patch("bazzingakit.core.burp_proxy.shutil.which", return_value="/usr/bin/openssl"):
        ok, _ = BurpProxyManager.check_openssl()
        assert ok is True


def test_check_openssl_missing():
    with patch("bazzingakit.core.burp_proxy.shutil.which", return_value=None):
        ok, msg = BurpProxyManager.check_openssl()
        assert ok is False
        assert "openssl" in msg.lower()


def test_check_burp_unreachable():
    with patch("bazzingakit.core.burp_proxy.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = Exception("connection refused")
        ok, msg = BurpProxyManager.check_burp("127.0.0.1", 8080)
        assert ok is False
        assert "Burp" in msg


def test_check_burp_returns_empty():
    """Si Burp responde con cert vacío, falla."""
    mock_response = MagicMock()
    mock_response.read.return_value = b""
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch(
        "bazzingakit.core.burp_proxy.urllib.request.urlopen", return_value=mock_response
    ):
        ok, msg = BurpProxyManager.check_burp("127.0.0.1", 8080)
        assert ok is False


def test_check_device_ready_no_root(burp, mock_device):
    mock_device.is_connected.return_value = True
    mock_device.shell.return_value = MagicMock(ok=True, stdout="uid=2000(shell)")
    ok, msg = burp.check_device_ready()
    assert ok is False
    assert "root" in msg.lower()


def test_check_device_ready_with_root(burp, mock_device):
    mock_device.is_connected.return_value = True
    mock_device.shell.return_value = MagicMock(ok=True, stdout="uid=0(root) gid=0(root)")
    ok, _ = burp.check_device_ready()
    assert ok is True


def test_check_magisk_present(burp, mock_device):
    mock_device.shell.return_value = MagicMock(ok=True, stdout="/sbin/magisk")
    ok, _ = burp.check_magisk()
    assert ok is True


def test_check_magisk_missing(burp, mock_device):
    mock_device.shell.return_value = MagicMock(ok=True, stdout="NO\n")
    ok, msg = burp.check_magisk()
    assert ok is False
    assert "magisk" in msg.lower()


def test_status_when_disconnected(burp, mock_device):
    mock_device.is_connected.return_value = False
    info = burp.status()
    assert info["device_connected"] is False
