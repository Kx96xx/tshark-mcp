"""Tools that live in their own module, found by discovery.

Each module here defines one tool (or a few closely related ones) with the ``@_tool``
decorator of :mod:`tshark_mcp.server`, which registers it on the server, adds it to
``server.TOOLS`` and makes it reachable as ``server.<name>``. :func:`load`, called once at the
end of server.py, imports every module of this package in name order, so adding a tool means
adding a module: no import line, registration list or expected-tools set to edit.

A module may import anything from ``..server`` (helpers such as ``_tool``, ``_guarded``,
``_resolve``, ``_fields_run``, ``_envelope``, ``state``) because it is imported after server.py
defined them. Modules whose name starts with an underscore are skipped.
"""

from __future__ import annotations

import importlib
import pkgutil


def modules() -> list[str]:
    """Names of the tool modules of this package, in the order :func:`load` imports them."""
    return sorted(m.name for m in pkgutil.iter_modules(__path__) if not m.name.startswith("_"))


def load() -> list[str]:
    """Import every tool module; each registers its tools as it is imported."""
    names = modules()
    for name in names:
        importlib.import_module(f"{__name__}.{name}")
    return names
