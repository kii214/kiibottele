"""Tests for KIIBOT tool registry."""

from kiibot.tools.registry import get_registry


def test_registry_loading():
    registry = get_registry()
    tools = registry.all_tools()
    assert len(tools) > 50  # Should have 100+ registered tools


def test_registry_lookup():
    registry = get_registry()
    nmap = registry.get("nmap")
    assert nmap is not None
    assert nmap.name == "nmap"
    assert nmap.category == "recon"
    assert nmap.risk == "medium"

    missing = registry.get("non_existent_tool_xyz")
    assert missing is None


def test_registry_category_filtering():
    registry = get_registry()
    web_tools = registry.by_category("web")
    assert len(web_tools) > 0
    for t in web_tools:
        assert t.category == "web"


def test_registry_search():
    registry = get_registry()
    results = registry.search("port scanner")
    assert len(results) > 0
    names = [r.name for r in results]
    assert "nmap" in names
