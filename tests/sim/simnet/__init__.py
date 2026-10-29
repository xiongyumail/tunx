"""Network namespace simulation: topology YAML -> namespaces, bridges, veths, netem."""


class SchemaError(Exception):
    """A topology or scenario file is invalid. The message names the offending path."""


class SimError(Exception):
    """A command failed while building or driving a topology."""
