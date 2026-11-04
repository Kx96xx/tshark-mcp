"""The tool list a client sees: compact by default, full on request.

Every tool publishes a typed ``outputSchema`` built from :mod:`models`. In full, the
33 schemas weigh about 150 KB, and clients that forward the tool list to the model or
index it for tool search pay for that on every session. The ``compact`` profile (the
default, ``--schema-profile``) publishes the same tools with:

* the output schema cut to its top-level keys: scalars keep their JSON type; a nested
  object or a list of rows becomes ``object`` / ``array`` of ``object`` with a one-line
  ``description`` naming its keys. The keys every tool may return and the server
  instructions already explain (``truncated``, ``warnings``, ``redaction``, ...) are left
  out; ``error`` and the paging keys stay. ``additionalProperties`` stays true, so every
  result that matches the full schema also matches the compact one;
* the input schema without the generated ``title`` keys, and an optional argument
  (``anyOf`` string or null, default null) written as ``"type": ["string", "null"]``; enums,
  defaults and descriptions are unchanged;
* the description up to its ``Details:`` paragraph, which moves to the resource.

``schema://tools/<name>`` serves the full description, input and output schema of a
tool in either profile; ``--schema-profile full`` publishes the full tool list as before.
"""

from __future__ import annotations

import inspect
import re
from typing import Any

PROFILES = ("compact", "full")
DEFAULT_PROFILE = "compact"
URI_PREFIX = "schema://tools/"

# Keys of ToolResult that the server instructions describe for every tool.
COMMON_KEYS = frozenset({"truncated", "truncated_reason", "warnings", "trimmed", "untrusted_text_fields",
                         "text_values_shortened", "redaction"})

_DETAILS = re.compile(r"\n[ \t]*Details:[ \t]*")
_MAX_KEYS_LISTED = 40


def check_profile(value: str, what: str = "schema profile") -> str:
    if value not in PROFILES:
        raise ValueError(f"{what} must be one of {', '.join(PROFILES)}, not {value!r}")
    return value


def split_description(doc: str | None) -> tuple[str, str]:
    """``(summary, details)``: the text before a ``Details:`` paragraph and the text after it."""
    text = inspect.cleandoc(doc or "")
    parts = _DETAILS.split(text, maxsplit=1)
    return parts[0].strip(), (parts[1].strip() if len(parts) > 1 else "")


def compact_description(name: str, doc: str | None) -> str:
    summary, details = split_description(doc)
    return f"{summary}\nMore detail: resource {URI_PREFIX}{name}." if details else summary


def full_description(doc: str | None) -> str:
    """The whole description with the ``Details:`` marker kept as a plain paragraph."""
    summary, details = split_description(doc)
    return f"{summary}\n\n{details}" if details else summary


def _resolve(schema: Any, defs: dict[str, Any]) -> dict[str, Any]:
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema and seen < 32:
        schema = defs.get(str(schema["$ref"]).rsplit("/", 1)[-1], {})
        seen += 1
    return schema if isinstance(schema, dict) else {}


def _keys(schema: dict[str, Any], defs: dict[str, Any]) -> list[str]:
    return list(_resolve(schema, defs).get("properties", {}))


def _key_list(keys: list[str]) -> str:
    shown = keys[:_MAX_KEYS_LISTED]
    more = f", ... ({len(keys) - len(shown)} more)" if len(keys) > len(shown) else ""
    return ", ".join(shown) + more


def _is_object(schema: dict[str, Any]) -> bool:
    return schema.get("type") == "object" or "properties" in schema


def _shallow(schema: Any, defs: dict[str, Any]) -> dict[str, Any]:
    schema = _resolve(schema, defs)
    variants = schema.get("anyOf") or schema.get("oneOf")
    if variants:
        parts = [_shallow(v, defs) for v in variants]
        types: set[str] = set()
        for part in parts:
            t = part.get("type")
            if not t:
                return {}  # one variant takes anything: so does the union
            types.update(t if isinstance(t, list) else [t])
        out: dict[str, Any] = {"type": sorted(types)[0] if len(types) == 1 else sorted(types)}
        described = next((p["description"] for p in parts if "description" in p), None)
        if described:
            out["description"] = described
        return out
    if _is_object(schema):
        out = {"type": "object"}
        keys = _keys(schema, defs)
        if keys:
            out["description"] = "keys: " + _key_list(keys)
        return out
    if schema.get("type") == "array":
        items = _resolve(schema.get("items", {}), defs)
        out = {"type": "array"}
        if _is_object(items):
            out["items"] = {"type": "object"}
            keys = _keys(items, defs)
            if keys:
                out["description"] = "rows with keys: " + _key_list(keys)
        elif isinstance(items.get("type"), (str, list)):
            out["items"] = {"type": items["type"]}
        return out
    t = schema.get("type")
    return {"type": t} if isinstance(t, (str, list)) else {}


def compact_output_schema(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """The top-level keys of ``schema`` with their JSON types (see the module docstring)."""
    if not schema:
        return schema
    defs = schema.get("$defs", {})
    props = {name: _shallow(prop, defs) for name, prop in schema.get("properties", {}).items()
             if name not in COMMON_KEYS}
    if "error" in props:
        props["error"] = {"type": "object"}
    out: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": True}
    required = [k for k in schema.get("required", []) if k in props]
    if required:
        out["required"] = required
    return out


def strip_titles(schema: Any) -> Any:
    """``schema`` without the ``title`` keys pydantic generates (a property named title stays)."""
    if isinstance(schema, dict):
        return {k: (strip_titles(v) if k != "properties" else {pk: strip_titles(pv) for pk, pv in v.items()})
                for k, v in schema.items() if not (k == "title" and isinstance(v, str))}
    if isinstance(schema, list):
        return [strip_titles(v) for v in schema]
    return schema


def _simple_union(prop: dict[str, Any]) -> dict[str, Any]:
    """``anyOf`` of bare types becomes one ``type`` list; a ``null`` default is dropped (absent means null)."""
    variants = prop.get("anyOf")
    if isinstance(variants, list) and variants and all(isinstance(v, dict) and set(v) == {"type"}
                                                       and isinstance(v["type"], str) for v in variants):
        prop = {k: v for k, v in prop.items() if k != "anyOf"}
        prop["type"] = [v["type"] for v in variants]
    if "default" in prop and prop["default"] is None:
        prop = {k: v for k, v in prop.items() if k != "default"}
    return prop


def compact_input_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """``schema`` without generated titles, with ``X | None`` arguments written as a type list."""
    out = strip_titles(schema)
    if isinstance(out.get("properties"), dict):
        out["properties"] = {name: _simple_union(prop) if isinstance(prop, dict) else prop
                             for name, prop in out["properties"].items()}
    return out


def compact_tool(tool: Any) -> Any:
    """A copy of an SDK ``Tool`` (the listed type) in the compact profile."""
    return tool.model_copy(update={
        "description": compact_description(tool.name, tool.description),
        "input_schema": compact_input_schema(tool.input_schema),
        "output_schema": compact_output_schema(tool.output_schema),
    })


def full_tool(tool: Any) -> Any:
    return tool.model_copy(update={"description": full_description(tool.description)})
