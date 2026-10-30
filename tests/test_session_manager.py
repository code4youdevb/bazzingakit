"""Tests del SessionManager."""

from pathlib import Path

import pytest

from bazzingakit.core import SessionManager


def test_create_session(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    s = mgr.create(package_name="com.example.app", platform="android")

    assert s.session_dir.exists()
    assert s.metadata.package_name == "com.example.app"
    assert s.metadata.platform == "android"
    assert (s.session_dir / "session.json").exists()


def test_session_add_script(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    s = mgr.create(package_name="com.example.app", platform="android")

    s.add_script("ssl_bypass.js")
    s.add_script("root_bypass.js")
    s.add_script("ssl_bypass.js")  # duplicado, no debe añadirse

    assert len(s.metadata.scripts_loaded) == 2


def test_session_append_log(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    s = mgr.create(package_name="com.example.app", platform="android")

    s.append_log("frida_output.log", "line 1")
    s.append_log("frida_output.log", "line 2")

    content = s.path("frida_output.log").read_text()
    assert "line 1" in content
    assert "line 2" in content


def test_session_close_sets_ended_at(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    s = mgr.create(package_name="com.example.app", platform="android")
    assert s.metadata.ended_at is None

    s.close()
    assert s.metadata.ended_at is not None


def test_list_sessions(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    mgr.create(package_name="com.app.a", platform="android")
    mgr.create(package_name="com.app.b", platform="android")

    sessions = mgr.list_sessions()
    assert len(sessions) == 2


def test_load_session(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    s1 = mgr.create(package_name="com.example.app", platform="android")
    s1.add_script("test.js")

    s2 = mgr.load(s1.id)
    assert s2.metadata.package_name == "com.example.app"
    assert "test.js" in s2.metadata.scripts_loaded


def test_resolve_by_substring(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    mgr.create(package_name="com.unique.app", platform="android")

    s = mgr.resolve("unique")
    assert s.metadata.package_name == "com.unique.app"


def test_resolve_nonexistent(tmp_path: Path):
    mgr = SessionManager(tmp_path)
    with pytest.raises(FileNotFoundError):
        mgr.resolve("nonexistent")
