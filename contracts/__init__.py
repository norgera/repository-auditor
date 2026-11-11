"""Shared JSON contracts, with a small validator for the schema subset they use."""
import json
import pathlib

_DIR = pathlib.Path(__file__).parent
SCHEMAS = {p.name.split(".")[0]: json.loads(p.read_text()) for p in _DIR.glob("*.schema.json")}

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def _check(value, schema, path, errors):
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: not one of {schema['enum']}")
        return
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[t](value) for t in types):
            errors.append(f"{path}: expected {types}")
            return
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: required")
        for key, sub in schema.get("properties", {}).items():
            if key in value:
                _check(value[key], sub, f"{path}.{key}", errors)
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _check(item, schema["items"], f"{path}[{i}]", errors)


def validate(instance, schema_name):
    """Return a list of contract violations. An empty list means the instance is valid."""
    errors = []
    _check(instance, SCHEMAS[schema_name], "$", errors)
    return errors
