"""netem parameters: validation, CLI parsing, merging and tc arguments."""
import re

from . import SchemaError
from .util import suggest, type_name

_TIME = re.compile(r"^\d+(\.\d+)?(us|ms|s)$")
_PCT = re.compile(r"^\d+(\.\d+)?%$")
_RATE = re.compile(r"^\d+(\.\d+)?([kmgt]?bit|[kmgt]?bps)$", re.I)

# key -> (kind, example)
KEYS = {
    "delay": ("time", "40ms"),
    "jitter": ("time", "5ms"),
    "loss": ("pct", "1%"),
    "reorder": ("pct", "25%"),
    "duplicate": ("pct", "1%"),
    "corrupt": ("pct", "0.1%"),
    "rate": ("rate", "20mbit"),
    "limit": ("int", "10000"),
}
DEFAULT_LIMIT = 10000  # packets; the kernel default (1000) is too small for delay x bandwidth


def _value(key, v, path):
    kind, example = KEYS[key]
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        raise SchemaError(f"{path}.{key}: expected a value like '{example}', got {type_name(v)}")
    if kind == "int":
        if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
            if int(v) > 0:
                return str(int(v))
        raise SchemaError(f"{path}.{key}: expected a positive packet count, got '{v}'")
    if isinstance(v, (int, float)):
        v = f"{v}{'ms' if kind == 'time' else '%' if kind == 'pct' else 'mbit'}"
    v = v.strip()
    rx = {"time": _TIME, "pct": _PCT, "rate": _RATE}[kind]
    if not rx.match(v):
        raise SchemaError(f"{path}.{key}: bad value '{v}' (expected something like '{example}')")
    return v


def normalize(value, path):
    """Validate a netem mapping from YAML. None means no netem."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SchemaError(f"{path}: expected a mapping like {{delay: 40ms, loss: 1%}}, got {type_name(value)}")
    out = {}
    for k, v in value.items():
        if k not in KEYS:
            raise SchemaError(f"{path}: unknown netem key '{k}'" + suggest(k, KEYS))
        out[k] = _value(k, v, path)
    check(out, path)
    return out


def check(p, path):
    for k in ("jitter", "reorder"):
        if k in p and "delay" not in p:
            raise SchemaError(f"{path}: '{k}' needs 'delay' as well")


def parse_update(value, path):
    """Parse a runtime change.

    Accepts 'reset' (back to the topology), 'clear' (remove netem), a mapping, or
    tokens like ['loss', '3%', 'delay', '40ms'] / ['loss=3%']. A value of
    off/none/null removes that key. Returns ('reset'|'clear'|'set', dict).
    """
    if isinstance(value, str):
        value = value.split()
    if isinstance(value, list):
        if len(value) == 1 and value[0] in ("reset", "clear"):
            return value[0], {}
        tokens = []
        for t in value:
            tokens += str(t).split("=", 1) if "=" in str(t) else [str(t)]
        if not tokens or len(tokens) % 2:
            raise SchemaError(f"{path}: expected 'reset', 'clear' or key/value pairs like 'loss 3%', got {' '.join(map(str, value)) or 'nothing'}")
        value = dict(zip(tokens[::2], tokens[1::2]))
    if not isinstance(value, dict) or not value:
        raise SchemaError(f"{path}: expected 'reset', 'clear' or a mapping like {{loss: 3%}}")
    upd = {}
    for k, v in value.items():
        if k not in KEYS:
            raise SchemaError(f"{path}: unknown netem key '{k}'" + suggest(k, KEYS))
        upd[k] = None if v is None or str(v).lower() in ("off", "none", "null") else _value(k, v, path)
    return "set", upd


def merge(current, upd, path):
    out = dict(current)
    for k, v in upd.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    check(out, path)
    return out


def tc_args(p):
    """Arguments after 'netem' for tc."""
    a = ["limit", p.get("limit", str(DEFAULT_LIMIT))]
    if "delay" in p:
        a += ["delay", p["delay"]] + ([p["jitter"]] if "jitter" in p else [])
    for k in ("loss", "duplicate", "corrupt", "reorder"):
        if k in p:
            a += [k, p[k]]
    if "rate" in p:
        a += ["rate", p["rate"]]
    return a


def describe(p):
    return " ".join(f"{k}={v}" for k, v in p.items()) or "none"
