"""Tests del RASPDetector."""

import zipfile
from pathlib import Path

from bazzingakit.core import RASPDetector


def test_signatures_loaded():
    detector = RASPDetector()
    assert len(detector.signatures) > 0
    ids = [s.id for s in detector.signatures]
    assert "promon_shield" in ids
    assert "appdome" in ids


def _make_fake_apk(tmp_path: Path, libraries=None, dex_content=b"", assets=None) -> Path:
    """Crea un APK falso con contenido controlado para tests."""
    apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"fake")
        zf.writestr("classes.dex", dex_content or b"dexdata")
        for lib in libraries or []:
            zf.writestr(f"lib/arm64-v8a/{lib}", b"\x7fELF" + b"\x00" * 100)
        for asset in assets or []:
            zf.writestr(asset, b"asset content")
    return apk


def test_empty_apk_no_matches(tmp_path: Path):
    apk = _make_fake_apk(tmp_path)
    detector = RASPDetector()
    report = detector.analyze_apk(apk)
    assert not report.has_rasp


def test_detects_promon_via_library(tmp_path: Path):
    apk = _make_fake_apk(tmp_path, libraries=["libshield.so"])
    detector = RASPDetector()
    report = detector.analyze_apk(apk)

    promon_matches = [m for m in report.matches if m.signature.id == "promon_shield"]
    assert len(promon_matches) == 1
    assert "libshield.so" in promon_matches[0].matched_libraries


def test_detects_appdome_via_library(tmp_path: Path):
    apk = _make_fake_apk(
        tmp_path, libraries=["libappdome.so", "libADCPlatform.so"]
    )
    detector = RASPDetector()
    report = detector.analyze_apk(apk)

    appdome = [m for m in report.matches if m.signature.id == "appdome"]
    assert len(appdome) == 1


def test_detects_class_via_dex_strings(tmp_path: Path):
    # DEX con referencia al paquete de RootBeer
    dex = b"dexcode" + b"com/scottyab/rootbeer/RootBeer" + b"otro_stuff"
    apk = _make_fake_apk(tmp_path, dex_content=dex)

    detector = RASPDetector()
    report = detector.analyze_apk(apk)
    rootbeer = [m for m in report.matches if m.signature.id == "rootbeer"]
    assert len(rootbeer) == 1


def test_report_primary_rasp(tmp_path: Path):
    apk = _make_fake_apk(tmp_path, libraries=["libshield.so"])
    detector = RASPDetector()
    report = detector.analyze_apk(apk)

    primary = report.primary_rasp
    assert primary is not None
    assert primary.signature.id == "promon_shield"
    assert primary.confidence > 0


def test_has_rasp_false_for_only_discrete_protections(tmp_path: Path):
    # Solo RootBeer (category='root_detection', no 'rasp')
    dex = b"x" * 100 + b"com/scottyab/rootbeer/RootBeer" + b"y" * 100
    apk = _make_fake_apk(tmp_path, dex_content=dex)

    detector = RASPDetector()
    report = detector.analyze_apk(apk)
    # Hay matches pero no son RASP
    assert len(report.matches) > 0
    # Nota: has_rasp verifica category == 'rasp'
    rootbeer_only = all(m.signature.category != "rasp" for m in report.matches)
    if rootbeer_only:
        assert not report.has_rasp
