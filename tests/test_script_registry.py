"""Tests del ScriptRegistry."""

from pathlib import Path

import pytest

from bazzingakit.core import ScriptParseError, ScriptRegistry


SAMPLE_SCRIPT = """
/**
 * @name Test Script
 * @platform android
 * @category ssl_pinning
 * @technique okhttp_bypass
 * @targets okhttp3.CertificatePinner, com.app.Pinner
 * @author tester
 * @version 1.0
 * @description Script de prueba
 */

Java.perform(function () {
    console.log("test");
});
"""

NO_HEADER_SCRIPT = """
Java.perform(function () {
    console.log("test");
});
"""

MINIMAL_SCRIPT = """
/**
 * @name Minimal
 */
console.log("hi");
"""


def test_parse_complete_header(tmp_path: Path):
    script = tmp_path / "test.js"
    script.write_text(SAMPLE_SCRIPT)

    reg = ScriptRegistry()
    meta = reg.parse_header(SAMPLE_SCRIPT, script)

    assert meta.name == "Test Script"
    assert meta.platform == "android"
    assert meta.category == "ssl_pinning"
    assert meta.technique == "okhttp_bypass"
    assert "okhttp3.CertificatePinner" in meta.targets
    assert "com.app.Pinner" in meta.targets
    assert meta.author == "tester"
    assert meta.version == "1.0"


def test_parse_minimal_header(tmp_path: Path):
    script = tmp_path / "m.js"
    script.write_text(MINIMAL_SCRIPT)

    reg = ScriptRegistry()
    meta = reg.parse_header(MINIMAL_SCRIPT, script)

    assert meta.name == "Minimal"
    assert meta.platform == "any"
    assert meta.category == "uncategorized"


def test_no_header_raises(tmp_path: Path):
    reg = ScriptRegistry()
    with pytest.raises(ScriptParseError):
        reg.parse_header(NO_HEADER_SCRIPT, tmp_path / "x.js")


def test_scan_directory(tmp_path: Path):
    (tmp_path / "a.js").write_text(SAMPLE_SCRIPT)
    (tmp_path / "b.js").write_text(MINIMAL_SCRIPT)
    (tmp_path / "c.js").write_text(NO_HEADER_SCRIPT)

    reg = ScriptRegistry()
    count = reg.scan_directory(tmp_path)

    assert count == 2


def test_find_by_category(tmp_path: Path):
    (tmp_path / "s.js").write_text(SAMPLE_SCRIPT)
    reg = ScriptRegistry()
    reg.scan_directory(tmp_path)

    results = reg.find(category="ssl_pinning")
    assert len(results) == 1
    assert results[0].name == "Test Script"

    results = reg.find(category="nonexistent")
    assert len(results) == 0


def test_builtin_scripts_load():
    """Verifica que los scripts built-in tengan headers válidos."""
    from bazzingakit.core.script_registry import default_registry
    reg = default_registry()
    all_scripts = reg.all()
    # Debe haber al menos los que creamos
    names = [s.name for s in all_scripts]
    assert "SSL Pinning Universal Bypass" in names
    assert "Root Detection Bypass" in names
    assert "Crypto Operations Hook" in names
