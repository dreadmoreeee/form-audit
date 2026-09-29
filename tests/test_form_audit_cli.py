import json
from pathlib import Path

import pytest

from form_audit.cli import main

BAD = str(Path(__file__).resolve().parent / "fixtures" / "bad_page.json")


def test_markdown_from_saved_extraction(capsys):
    assert main(["--input", BAD]) == 1
    out = capsys.readouterr().out
    assert out.startswith("# Form audit")
    assert "nothing was typed, clicked or submitted" in out
    assert "### High" in out
    assert '- `add autocomplete="email" to input#email`' in out
    assert "| `form#contact` | GET | /send |" in out


def test_json_output(capsys):
    assert main(["--input", BAD, "--format", "json", "--fail-on", "never"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["read_only"] is True
    page = doc["pages"][0]
    assert page["counts"]["high"] >= 4
    assert doc["totals"] == page["counts"]
    assert {"severity", "rule", "target", "fix", "why", "form"} <= set(page["findings"][0])


def test_output_file(tmp_path, capsys):
    out = tmp_path / "report.md"
    main(["--input", BAD, "-o", str(out)])
    assert capsys.readouterr().out == ""
    assert out.read_text(encoding="utf-8").startswith("# Form audit")


def test_error_page_exit_2(tmp_path, capsys):
    f = tmp_path / "down.json"
    f.write_text(json.dumps([{"requested_url": "https://x.example/", "error": "net::ERR_NAME_NOT_RESOLVED"}]))
    assert main(["--input", str(f)]) == 2
    assert "ERROR: net::ERR_NAME_NOT_RESOLVED" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [[], ["ftp://example.com"], ["example.com"], ["--input", BAD, "https://a.example"],
                                  ["--format", "xml", "https://a.example"]])
def test_usage_errors_exit_2(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_unreadable_input_exit_2(tmp_path, capsys):
    assert main(["--input", str(tmp_path / "missing.json")]) == 2
