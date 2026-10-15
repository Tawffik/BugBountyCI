"""probe_results must match path-file lines across http/https and host|path keys."""
from pathlib import Path


def test_hunter_indexes_scheme_and_path_aliases():
    src = Path("pipeline/detection/hunter_queue_builder.py").read_text(encoding="utf-8")
    assert 'probe.setdefault(alt, row)' in src or "probe.setdefault(alt, row)" in src
    assert 'host}|{path_key}' in src or 'f"{host}|{path_key}"' in src


def test_export_indexes_scheme_and_path_aliases():
    src = Path("scripts/write_pipeline_exports.py").read_text(encoding="utf-8")
    assert "host}|{path_key}" in src or 'f"{host}|{path_key}"' in src
    assert "urlunparse" in src
