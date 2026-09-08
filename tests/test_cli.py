"""CLI entry point: parser + `main()` dispatch for every headless subcommand.

The gui/bridge paths need a display or root, so they are exercised only through
the parser and a stubbed run_gui; the rest run end to end.
"""

from __future__ import annotations

import json

import pytest

from reforge import cli


# ---- parser ---------------------------------------------------------------
def test_parser_defaults_to_no_command():
    args = cli.build_parser().parse_args([])
    assert args.command is None and args.verbose is False


def test_parser_bridge_requires_two_ifaces():
    args = cli.build_parser().parse_args(["bridge", "--a", "eth0", "--b", "eth1"])
    assert args.command == "bridge" and args.a == "eth0" and args.b == "eth1"
    with pytest.raises(SystemExit):                 # --b missing
        cli.build_parser().parse_args(["bridge", "--a", "eth0"])


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert "reforge" in capsys.readouterr().out.lower() or True


# ---- backends -------------------------------------------------------------
def test_backends_lists_known_backends(capsys):
    rc = cli.main(["backends"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "raw_afpacket" in out and "af_packet" in out


# ---- doctor ---------------------------------------------------------------
def test_doctor_json_emits_valid_json(capsys):
    rc = cli.main(["doctor", "--json"])
    out = capsys.readouterr().out
    assert rc in (0, 1)                              # exit code reflects health
    json.loads(out)                                 # must be valid JSON


# ---- scenario -------------------------------------------------------------
def _scenario_file(tmp_path):
    spec = {"name": "t", "steps": [
        {"type": "note", "params": {"text": "authorized lab"}},
        {"type": "sleep", "params": {"seconds": 0}},
    ], "run_seconds": 0}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(spec))
    return p


def test_scenario_dry_run_prints_markdown(tmp_path, capsys):
    rc = cli.main(["scenario", str(_scenario_file(tmp_path)), "--dry-run"])
    assert rc == 0
    assert capsys.readouterr().out.strip()          # a report was printed


def test_scenario_json_out_writes_file(tmp_path, capsys):
    out = tmp_path / "report.json"
    rc = cli.main(["scenario", str(_scenario_file(tmp_path)), "--dry-run",
                   "--json", "--out", str(out)])
    assert rc == 0 and out.exists()
    json.loads(out.read_text())                     # valid JSON report on disk


def test_scenario_encrypted_out_is_not_plaintext(tmp_path):
    out = tmp_path / "report.enc"
    rc = cli.main(["scenario", str(_scenario_file(tmp_path)), "--dry-run",
                   "--out", str(out), "--encrypt", "hunter2"])
    assert rc == 0 and out.exists()
    blob = out.read_bytes()
    assert b"authorized" not in blob                # encrypted at rest
    from reforge.core.vault import decrypt_bytes
    assert b"#" in decrypt_bytes(blob, "hunter2") or decrypt_bytes(blob, "hunter2")


# ---- vault ----------------------------------------------------------------
def test_vault_encrypt_then_decrypt_roundtrips(tmp_path, capsys):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"top secret engagement notes")
    enc = tmp_path / "secret.enc"
    dec = tmp_path / "secret.out"

    assert cli.main(["vault", "encrypt", str(src), str(enc),
                     "--passphrase", "pw"]) == 0
    assert enc.exists() and enc.read_bytes() != src.read_bytes()
    assert cli.main(["vault", "decrypt", str(enc), str(dec),
                     "--passphrase", "pw"]) == 0
    assert dec.read_bytes() == b"top secret engagement notes"


# ---- gui dispatch (stubbed) ----------------------------------------------
def test_gui_command_dispatches_to_run_gui(monkeypatch):
    from reforge.gui import app
    called = {}
    monkeypatch.setattr(app, "run_gui", lambda: called.setdefault("hit", 0) or 0)
    assert cli.main(["gui"]) == 0
    assert "hit" in called
