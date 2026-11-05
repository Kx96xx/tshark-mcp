"""server.json (official MCP registry metadata) and glama.json stay valid and in step.

The registry refuses a publish whose server.json breaks its schema, and it proves
PyPI ownership by finding `mcp-name: <server name>` in the package README, so the
marker, the name, the versions and the package identifier must all agree.
The schema is vendored (tests/data) so the check needs no network.
"""
import json
import re
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
SCHEMA = ROOT / "tests" / "data" / "server.schema.2025-12-11.json"


def _server():
    return json.loads((ROOT / "server.json").read_text(encoding="utf-8"))


def _project():
    # tomllib is 3.11+; the three keys needed are simple enough to read directly.
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    scripts = dict(re.findall(r'^([\w-]+) = "(tshark_mcp[^"]*)"$', text, re.M))
    return {
        "name": re.search(r'^name = "([^"]+)"$', text, re.M).group(1),
        "version": re.search(r'^version = "([^"]+)"$', text, re.M).group(1),
        "scripts": scripts,
    }


def test_server_json_matches_the_registry_schema():
    server = _server()
    assert server["$schema"] == SCHEMA_URL
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator.check_schema(schema)
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(server), key=str)
    assert not errors, [e.message for e in errors]


def test_the_schema_check_catches_a_broken_server_json():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    broken = dict(_server(), description="x" * 101)  # the registry caps it at 100
    assert list(jsonschema.Draft7Validator(schema).iter_errors(broken))


def test_server_json_versions_and_package_match_pyproject():
    server, project = _server(), _project()
    assert server["version"] == project["version"]
    (pkg,) = server["packages"]
    assert pkg["registryType"] == "pypi"
    assert pkg["identifier"] == project["name"]
    assert pkg["version"] == project["version"]
    assert pkg["transport"] == {"type": "stdio"}
    # uvx runs the command named after the distribution.
    assert project["scripts"][project["name"]] == project["scripts"]["tshark-mcp"]


def test_readme_carries_the_mcp_name_marker():
    name = _server()["name"]
    assert name == "io.github.Kx96xx/tshark-mcp"  # the namespace is case-sensitive
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"mcp-name: " + re.escape(name) + r"(\s|-->|<)", readme)


def test_server_json_documents_the_required_allowlist():
    env = {e["name"]: e for e in _server()["packages"][0]["environmentVariables"]}
    assert env["TSHARK_MCP_ALLOW_DIRS"]["isRequired"] is True
    server_py = (ROOT / "src" / "tshark_mcp" / "server.py").read_text(encoding="utf-8")
    for name in env:
        assert name in server_py, f"{name} is documented in server.json but not read by the server"
    from tshark_mcp import redact
    assert env["TSHARK_MCP_REDACT"]["choices"] == list(redact.MODES)


def test_glama_json_names_the_maintainer():
    glama = json.loads((ROOT / "glama.json").read_text(encoding="utf-8"))
    assert glama == {"$schema": "https://glama.ai/mcp/schemas/server.json", "maintainers": ["Kx96xx"]}
