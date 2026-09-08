"""Plugin manager: load success/failure paths, dir scan, transform lookup."""

from __future__ import annotations

from reforge.plugins import PluginManager, transform


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return p


def test_load_file_registers_transform_and_protocol(tmp_path):
    pf = _write(tmp_path, "good.py", '''
def register(api):
    def bump(pkt):
        return pkt
    api.register_transform("bump", bump)
    api.register_protocol({"name": "PZ", "fields": [{"name": "k", "type": "u8"}],
                           "bind": {"over": "UDP", "dport": 9911}})
''')
    mgr = PluginManager()
    assert mgr.load_file(pf) is True
    assert str(pf) in mgr.loaded
    assert callable(transform("bump"))
    assert any(s["name"] == "PZ" for s in mgr.api.protocols)


def test_load_file_without_register_fails(tmp_path):
    pf = _write(tmp_path, "noreg.py", "X = 1\n")
    assert PluginManager().load_file(pf) is False


def test_load_file_with_import_error_fails(tmp_path):
    pf = _write(tmp_path, "boom.py", "raise RuntimeError('nope')\n")
    assert PluginManager().load_file(pf) is False


def test_load_file_register_raises_fails(tmp_path):
    pf = _write(tmp_path, "badreg.py", "def register(api):\n    raise ValueError('x')\n")
    assert PluginManager().load_file(pf) is False


def test_load_dir_skips_underscored_and_counts(tmp_path):
    _write(tmp_path, "_hidden.py", "def register(api):\n    pass\n")
    _write(tmp_path, "a.py", 'def register(api):\n    api.register_transform("a", lambda p: p)\n')
    _write(tmp_path, "b.py", 'def register(api):\n    api.register_transform("b", lambda p: p)\n')
    mgr = PluginManager()
    assert mgr.load_dir(tmp_path) == 2                 # underscored one skipped


def test_transform_lookup_missing_is_none():
    assert transform("definitely-not-registered") is None
