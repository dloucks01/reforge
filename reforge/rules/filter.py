"""Compile a short filter expression into a rule-engine Match.

Lets the operator type an intercept/search condition instead of clicking a rule
builder, e.g.:

    TCP.dport == 80
    IP.src cidr 10.0.0.0/24 and TCP.dport == 80
    Raw.load contains "login" or Raw.load contains "password"
    DNS and not IP.src == 10.0.0.1
    TCP.dport in [80, 443, 8080]

Grammar (recursive descent, precedence not > and > or):

    expr   := or
    or     := and ("or" and)*
    and    := unary ("and" unary)*
    unary  := "not" unary | primary
    primary:= "(" expr ")" | comparison | layer
    comparison := IDENT "." IDENT OP value
    layer  := IDENT
    OP     := == | != | < | <= | > | >= | in | contains | cidr
    value  := STRING | NUMBER | "[" value ("," value)* "]" | TOKEN

Errors raise FilterError with a message suitable for the GUI status line.
"""

from __future__ import annotations

import re

from reforge.rules import matchers as M
from reforge.rules.base import Match

_OP_MAP = {
    "==": "eq", "!=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge",
    "in": "in", "contains": "contains", "cidr": "cidr",
}
_KEYWORDS = {"and", "or", "not", "in", "contains", "cidr"}

# order matters: multi-char operators before single-char
_TOKEN_RE = re.compile(r"""
    \s*(?:
        (?P<str>"[^"]*"|'[^']*')                 # quoted string
      | (?P<addr>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?   # IPv4 / IPv4 CIDR
              |[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,}(?:/\d{1,3})?)  # IPv6 / MAC / v6 CIDR
      | (?P<op><=|>=|==|!=|<|>)                   # comparison operators
      | (?P<punc>[()\[\],.])                      # structural punctuation
      | (?P<num>0[xX][0-9a-fA-F]+|\d+)            # int / hex int
      | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)         # identifier / keyword
      | (?P<other>[^\s()\[\],]+)                  # bare word (hostname, etc.)
    )
""", re.VERBOSE)


class FilterError(ValueError):
    """Raised for a malformed filter expression."""


def _tokenize(text: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    pos = 0
    n = len(text)
    while pos < n:
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"cannot parse near {text[pos:pos + 12]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(m.lastgroup)
        if kind == "str":
            toks.append(("str", val[1:-1]))
        elif kind == "ident":
            toks.append(("kw" if val.lower() in _KEYWORDS else "ident", val))
        else:
            toks.append((kind, val))
    return toks


class _Parser:
    def __init__(self, toks: list[tuple[str, str]]):
        self.toks = toks
        self.i = 0

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def _next(self):
        t = self._peek()
        self.i += 1
        return t

    def _eat(self, val: str):
        _kind, v = self._peek()
        if v != val:
            raise FilterError(f"expected {val!r}, got {v!r}" if v else f"expected {val!r}")
        self.i += 1

    def parse(self) -> Match:
        if not self.toks:
            raise FilterError("empty filter")
        node = self._or()
        if self.i != len(self.toks):
            _, v = self._peek()
            raise FilterError(f"unexpected {v!r}")
        return node

    def _or(self) -> Match:
        node = self._and()
        terms = [node]
        while self._peek()[0] == "kw" and self._peek()[1].lower() == "or":
            self._next()
            terms.append(self._and())
        return M.OrMatch(terms) if len(terms) > 1 else node

    def _and(self) -> Match:
        node = self._unary()
        terms = [node]
        while self._peek()[0] == "kw" and self._peek()[1].lower() == "and":
            self._next()
            terms.append(self._unary())
        return M.AndMatch(terms) if len(terms) > 1 else node

    def _unary(self) -> Match:
        if self._peek()[0] == "kw" and self._peek()[1].lower() == "not":
            self._next()
            return M.NotMatch(self._unary())
        return self._primary()

    def _primary(self) -> Match:
        kind, val = self._peek()
        if val == "(":
            self._eat("(")
            node = self._or()
            self._eat(")")
            return node
        if kind != "ident":
            raise FilterError(f"expected a layer name, got {val!r}" if val else "expected a layer name")
        self._next()
        # bare layer, or LAYER.field OP value
        if self._peek() == ("punc", "."):
            self._eat(".")
            fk, field = self._next()
            if fk != "ident":
                raise FilterError(f"expected a field name after {val!r}.")
            _opk, op = self._next()
            op_l = (op or "").lower()
            if op_l not in _OP_MAP:
                raise FilterError(f"unknown operator {op!r}")
            value = self._value()
            return M.FieldMatch(val, field, _OP_MAP[op_l], value)
        return M.LayerMatch(val)

    def _value(self):
        kind, val = self._next()
        if val == "[":
            items = []
            while self._peek() != ("punc", "]"):
                items.append(self._scalar(*self._next()))
                if self._peek() == ("punc", ","):
                    self._next()
                elif self._peek() != ("punc", "]"):
                    raise FilterError("expected ',' or ']' in list")
            self._eat("]")
            return items
        if kind is None:
            raise FilterError("expected a value")
        return self._scalar(kind, val)

    @staticmethod
    def _scalar(kind, val):
        if kind == "num":
            return int(val, 0)
        if kind == "str":
            return val
        # ident / other (e.g. an address or CIDR like 10.0.0.0/24) -> string
        return val


def parse_filter(text: str) -> Match:
    """Compile a filter expression to a Match. Raises FilterError on bad syntax."""
    return _Parser(_tokenize(text.strip())).parse()
