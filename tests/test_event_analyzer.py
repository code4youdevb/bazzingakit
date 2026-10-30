"""Tests del EventAnalyzer."""

from bazzingakit.core import EventAnalyzer


def test_empty_analysis():
    analyzer = EventAnalyzer()
    result = analyzer.analyze()
    assert result.total_events == 0
    assert result.findings == []


def test_rasp_indicator():
    analyzer = EventAnalyzer()
    analyzer.ingest({"event": "rasp_indicator", "rasp": "hst_vcs", "class": "br.com.hst.vcs.A"})
    analyzer.ingest({"event": "rasp_indicator", "rasp": "hst_vcs", "class": "br.com.hst.vcs.B"})
    result = analyzer.analyze()

    assert "hst_vcs" in result.rasps_detected
    assert any(f.category == "rasp_detected" and f.detail == "hst_vcs" for f in result.findings)


def test_ssl_exception_creates_ssl_finding():
    analyzer = EventAnalyzer()
    analyzer.ingest({
        "event": "exception",
        "type": "javax.net.ssl.SSLPeerUnverifiedException",
        "message": "Hostname not verified",
    })
    result = analyzer.analyze()
    assert any(f.category == "ssl_pinning" for f in result.findings)


def test_root_check_via_file_exists():
    analyzer = EventAnalyzer()
    analyzer.ingest({"event": "file_exists", "path": "/system/bin/su", "kind": "root_check"})
    result = analyzer.analyze()
    assert any(f.category == "root_detection" for f in result.findings)


def test_ui_blocking_string():
    analyzer = EventAnalyzer()
    analyzer.ingest({
        "event": "ui_text",
        "text": "Dispositivo no permitido",
        "blocking_keyword": "Dispositivo no permitido",
        "widget": "TextView",
    })
    result = analyzer.analyze()
    finding = next((f for f in result.findings if f.category == "ui_block_string"), None)
    assert finding is not None
    assert finding.confidence > 0.9


def test_self_kill_detected():
    analyzer = EventAnalyzer()
    analyzer.ingest({"event": "system_exit", "code": 0, "source": "System.exit"})
    result = analyzer.analyze()
    assert any(f.category == "self_kill" for f in result.findings)


def test_emulator_indicators():
    analyzer = EventAnalyzer()
    analyzer.ingest({"event": "build_prop", "fingerprint": "generic/sdk_x86/generic_x86"})
    analyzer.ingest({"event": "build_prop", "model": "Android SDK built for x86"})
    result = analyzer.analyze()
    assert any(f.category == "emulator_indicators" for f in result.findings)
