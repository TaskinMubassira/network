import json

import pytest

from fim.cli import EXIT_CHANGED, EXIT_CLEAN, EXIT_ERROR, main
from fim.core import BaselineError, compare, load_baseline, save_baseline, scan


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "site"
    (root / "conf").mkdir(parents=True)
    (root / "index.html").write_text("<h1>hello</h1>")
    (root / "conf" / "app.ini").write_text("debug=false")
    return root


def test_scan_hashes_files_with_relative_paths(site):
    files = scan(site)
    assert set(files) == {"index.html", "conf/app.ini"}
    assert all(len(h) == 64 for h in files.values())


def test_scan_skips_git_and_excluded(site):
    (site / ".git").mkdir()
    (site / ".git" / "HEAD").write_text("ref")
    (site / "debug.log").write_text("x")
    assert set(scan(site, ("*.log",))) == {"index.html", "conf/app.ini"}


def test_compare_detects_every_kind_of_change(site):
    before = scan(site)
    (site / "index.html").write_text("<h1>defaced</h1>")
    (site / "conf" / "app.ini").unlink()
    (site / "shell.php").write_text("<?php system($_GET['c']); ?>")
    report = compare(before, scan(site))
    assert report.modified == ["index.html"]
    assert report.removed == ["conf/app.ini"]
    assert report.added == ["shell.php"]
    assert not report.clean


def test_signed_baseline_round_trip(site, tmp_path):
    path = tmp_path / "base.json"
    save_baseline(path, site, scan(site), key=b"secret")
    assert load_baseline(path, key=b"secret") == scan(site)


def test_tampered_baseline_is_rejected(site, tmp_path):
    path = tmp_path / "base.json"
    save_baseline(path, site, scan(site), key=b"secret")
    data = json.loads(path.read_text())
    data["files"]["index.html"] = "0" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(BaselineError, match="signature"):
        load_baseline(path, key=b"secret")


def test_wrong_key_and_unsigned_baseline_are_rejected(site, tmp_path):
    path = tmp_path / "base.json"
    save_baseline(path, site, scan(site), key=b"secret")
    with pytest.raises(BaselineError):
        load_baseline(path, key=b"other")
    save_baseline(path, site, scan(site))
    with pytest.raises(BaselineError, match="not signed"):
        load_baseline(path, key=b"secret")


def test_cli_init_check_update(site, capsys):
    assert main(["init", str(site)]) == EXIT_CLEAN
    assert main(["check", str(site)]) == EXIT_CLEAN  # baseline file itself is not reported

    (site / "index.html").write_text("changed")
    assert main(["check", str(site)]) == EXIT_CHANGED
    assert "MODIFIED  index.html" in capsys.readouterr().out

    assert main(["update", str(site)]) == EXIT_CLEAN
    assert main(["check", str(site)]) == EXIT_CLEAN


def test_cli_json_output(site, capsys):
    main(["init", str(site)])
    (site / "new.txt").write_text("x")
    capsys.readouterr()
    assert main(["check", str(site), "--json"]) == EXIT_CHANGED
    out = json.loads(capsys.readouterr().out)
    assert out["clean"] is False and out["added"] == ["new.txt"]


def test_cli_errors(site, tmp_path):
    assert main(["check", str(site)]) == EXIT_ERROR  # no baseline yet
    assert main(["check", str(tmp_path / "missing")]) == EXIT_ERROR
    main(["init", str(site)])
    assert main(["init", str(site)]) == EXIT_ERROR  # refuses to overwrite without --force


def test_cli_rejects_tampered_baseline(site, monkeypatch):
    monkeypatch.setenv("FIM_KEY", "secret")
    main(["init", str(site)])
    path = site / ".fim-baseline.json"
    data = json.loads(path.read_text())
    data["files"]["index.html"] = "0" * 64
    path.write_text(json.dumps(data))
    assert main(["check", str(site)]) == EXIT_ERROR
    assert main(["update", str(site)]) == EXIT_ERROR
