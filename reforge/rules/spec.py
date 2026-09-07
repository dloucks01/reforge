"""Build Rule objects from plain dict specs, and serialize them back.

Specs are what the GUI produces and what sessions persist (JSON-friendly).

Example:
    {
      "name": "redirect-dns",
      "enabled": true,
      "match": {"type": "field", "layer": "UDP", "field": "dport",
                "op": "eq", "value": 53},
      "actions": [
        {"type": "set_field", "layer": "IP", "field": "dst", "value": "10.0.0.9"},
        {"type": "delay", "seconds": 0.05}
      ]
    }
"""

from __future__ import annotations

from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules.base import Match, Rule


def build_match(spec: dict) -> Match:
    t = spec.get("type", "all")
    if t == "all":
        return M.AllMatch()
    if t == "layer":
        return M.LayerMatch(spec["layer"])
    if t == "field":
        return M.FieldMatch(spec["layer"], spec["field"], spec["op"], spec.get("value"))
    if t == "and":
        return M.AndMatch([build_match(s) for s in spec["of"]])
    if t == "or":
        return M.OrMatch([build_match(s) for s in spec["of"]])
    if t == "not":
        return M.NotMatch(build_match(spec["inner"]))
    raise ValueError(f"unknown match type: {t}")


def build_action(spec: dict):
    t = spec["type"]
    if t == "set_field":
        return A.SetField(spec["layer"], spec["field"], spec.get("value"))
    if t == "payload_replace":
        return A.PayloadReplace(spec["find"], spec["replace"], spec.get("count", -1))
    if t == "drop":
        return A.Drop()
    if t == "hold":
        return A.Hold()
    if t == "delay":
        return A.Delay(spec.get("seconds", 0.0))
    if t == "duplicate":
        return A.Duplicate(spec.get("times", 1))
    if t == "fuzz":
        from reforge.craft.fuzz import Fuzz

        return Fuzz(spec.get("mutations", 1), spec.get("seed"))
    if t == "plugin":
        return A.Plugin(spec["name"])
    if t == "strip_starttls":
        from reforge.attacks.starttls import StripStartTLS

        return StripStartTLS()
    if t.startswith("http_"):
        from reforge.attacks import http_actions as H

        if t == "http_sslstrip":
            return H.SslStrip()
        if t == "http_strip_encoding":
            return H.StripAcceptEncoding()
        if t == "http_inject":
            return H.InjectHtml(spec.get("snippet", ""), spec.get("marker", "</body>"))
        if t == "http_replace_body":
            return H.ReplaceBody(spec.get("body", ""), spec.get("content_type"))
        if t == "http_strip_cookie":
            return H.StripSecureCookie()
        if t == "http_remove_sec_headers":
            return H.RemoveSecurityHeaders()
    raise ValueError(f"unknown action type: {t}")


def build_rule(spec: dict) -> Rule:
    return Rule(
        name=spec.get("name", "rule"),
        match=build_match(spec.get("match", {"type": "all"})),
        actions=[build_action(a) for a in spec.get("actions", [])],
        enabled=spec.get("enabled", True),
    )


def build_rules(specs: list[dict]) -> list[Rule]:
    return [build_rule(s) for s in specs]


# --- human summaries for the GUI table --------------------------------------
def match_summary(spec: dict) -> str:
    t = spec.get("type", "all")
    if t == "all":
        return "any packet"
    if t == "layer":
        return f"has {spec['layer']}"
    if t == "field":
        return f"{spec['layer']}.{spec['field']} {spec['op']} {spec.get('value')}"
    if t in ("and", "or"):
        return f" {t} ".join(match_summary(s) for s in spec["of"])
    if t == "not":
        return f"not ({match_summary(spec['inner'])})"
    return t


def action_summary(spec: dict) -> str:
    t = spec["type"]
    if t == "set_field":
        return f"set {spec['layer']}.{spec['field']}={spec.get('value')}"
    if t == "payload_replace":
        return f"payload {spec['find']}→{spec['replace']}"
    if t == "delay":
        return f"delay {spec.get('seconds')}s"
    if t == "duplicate":
        return f"duplicate x{spec.get('times', 1)}"
    if t == "fuzz":
        return f"fuzz x{spec.get('mutations', 1)}"
    if t == "plugin":
        return f"plugin {spec.get('name')}"
    if t == "http_inject":
        return f"http:inject {str(spec.get('snippet',''))[:24]}"
    if t == "http_replace_body":
        return "http:replace-body"
    if t.startswith("http_"):
        return t.replace("http_", "http:").replace("_", "-")
    return t
