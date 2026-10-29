"""Small helpers shared by the topology and scenario loaders."""
import difflib
import re

from . import SchemaError

VAR_RE = re.compile(r"\$\$|\$\{([^}]*)\}")


def type_name(v):
    if v is None:
        return "nothing"
    return {dict: "a mapping", list: "a list", str: "a string", bool: "a boolean",
            int: "a number", float: "a number"}.get(type(v), type(v).__name__)


def suggest(word, choices):
    hit = difflib.get_close_matches(str(word), list(choices), 1)
    if hit:
        return f" (did you mean '{hit[0]}'?)"
    return f" (known: {', '.join(sorted(choices)) or 'none'})"


def check_map(d, path, allowed, required=()):
    """Require a mapping with only known keys; report the first problem clearly."""
    if not isinstance(d, dict):
        raise SchemaError(f"{path}: expected a mapping, got {type_name(d)}")
    for k in d:
        if k not in allowed:
            raise SchemaError(f"{path}: unknown key '{k}'" + suggest(k, allowed))
    for k in required:
        if k not in d:
            raise SchemaError(f"{path}: missing required key '{k}'")
    return d


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def subst(value, resolve, path):
    """Expand ${name} and ${name:-default} in every string of a YAML tree.

    `$$` is a literal `$`. Bare `$NAME` is left alone for the shell.
    """
    if isinstance(value, dict):
        return {k: subst(v, resolve, f"{path}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [subst(v, resolve, f"{path}[{i}]") for i, v in enumerate(value)]
    if not isinstance(value, str):
        return value

    def rep(m):
        if m.group(0) == "$$":
            return "$"
        name, default = m.group(1).strip(), None
        if ":-" in name:
            name, default = name.split(":-", 1)
        val = resolve(name)
        if val is None:
            if default is not None:
                return default
            raise SchemaError(f"{path}: unknown variable '${{{name}}}'")
        return str(val)

    return VAR_RE.sub(rep, value)
