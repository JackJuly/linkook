# tests/test_outputer.py

from linkook.provider.provider import Provider
from linkook.outputer.console_printer import ConsolePrinter
from linkook.outputer.visualize_output import Neo4jVisualizer


def make_provider(name="GitHub", **overrides):
    data = {
        "profileUrl": "https://github.com/^USER^",
        "mainUrl": "https://github.com/",
        "keyword": {"Match": ["found"]},
        "isConnected": True,
    }
    data.update(overrides)
    return Provider.from_dict(name, data)


# --- Neo4jVisualizer --------------------------------------------------------


def test_visualizer_builds_nodes_and_relationships():
    result = {
        "GitHub": {
            "found": True,
            "profile_url": "https://github.com/alice",
            "infos": {"emails": {"alice@example.com": True}},
            "other_links": {},
        }
    }
    viz = Neo4jVisualizer(result)
    viz.all_providers = {"GitHub": make_provider()}
    viz.process_result("alice")

    labels = [n["labels"][0] for n in viz.nodes]
    assert "User" in labels
    assert "SocialMediaAccount" in labels
    assert "Email" in labels
    assert len(viz.relationships) >= 2


def test_visualizer_skips_unknown_provider():
    result = {
        "Ghost": {
            "found": True,
            "profile_url": "https://ghost.com/alice",
            "infos": {"emails": {}},
            "other_links": {},
        }
    }
    viz = Neo4jVisualizer(result)
    viz.all_providers = {}  # provider missing on purpose
    # Must not raise AttributeError on a None provider.
    viz.process_result("alice")
    # Only the root user node is created.
    assert [n["labels"][0] for n in viz.nodes] == ["User"]


def test_visualizer_convert_sets():
    viz = Neo4jVisualizer({})
    converted = viz.convert_sets({"a": {1, 2}, "b": [{"c": {3}}]})
    assert sorted(converted["a"]) == [1, 2]
    assert sorted(converted["b"][0]["c"]) == [3]


# --- ConsolePrinter.browse_results ------------------------------------------


def test_browse_results_caps_at_ten(monkeypatch):
    opened = []
    monkeypatch.setattr(
        "linkook.outputer.console_printer.webbrowser.open", opened.append
    )
    printer = ConsolePrinter()
    results = {
        f"Site{i}": {"found": True, "profile_url": f"https://s{i}.com/u"}
        for i in range(15)
    }
    printer.browse_results(results)
    assert len(opened) == ConsolePrinter.MAX_BROWSE_TABS == 10


def test_browse_results_opens_only_found(monkeypatch):
    opened = []
    monkeypatch.setattr(
        "linkook.outputer.console_printer.webbrowser.open", opened.append
    )
    printer = ConsolePrinter()
    results = {
        "A": {"found": True, "profile_url": "https://a.com/u"},
        "B": {"found": False, "profile_url": "https://b.com/u"},
        "C": {"found": True, "profile_url": ""},  # no URL -> skipped
    }
    printer.browse_results(results)
    assert opened == ["https://a.com/u"]
