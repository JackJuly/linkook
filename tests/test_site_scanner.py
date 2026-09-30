# tests/test_site_scanner.py

import threading

import pytest

from linkook.provider.provider import Provider
from linkook.scanner.site_scanner import SiteScanner


def make_provider(**overrides):
    data = {
        "profileUrl": "https://example.com/^USER^",
        "mainUrl": "https://example.com/",
        "keyword": {"Match": ["found"]},
        "isConnected": True,
        "hasEmail": False,
    }
    data.update(overrides)
    return Provider.from_dict(overrides.get("name", "Example"), data)


# --- check_availability -----------------------------------------------------


def test_check_availability_network_error():
    scanner = SiteScanner()
    provider = make_provider()
    res = scanner.check_availability(None, None, provider)
    assert res["found"] is False
    assert res["error"] is not None


def test_check_availability_bad_status():
    scanner = SiteScanner()
    provider = make_provider()
    res = scanner.check_availability(404, "found", provider)
    assert res["found"] is False
    assert res["error"] is None


def test_check_availability_match_keyword():
    scanner = SiteScanner()
    provider = make_provider(keyword={"Match": ["hello"]})
    assert scanner.check_availability(200, "hello world", provider)["found"] is True
    assert scanner.check_availability(200, "bye world", provider)["found"] is False


def test_check_availability_not_match_keyword():
    scanner = SiteScanner()
    provider = make_provider(keyword={"notMatch": ["missing"]})
    assert scanner.check_availability(200, "missing user", provider)["found"] is False
    assert scanner.check_availability(200, "a profile", provider)["found"] is True


def test_check_availability_no_keyword_config():
    scanner = SiteScanner()
    provider = make_provider(keyword={})
    assert scanner.check_availability(200, "anything", provider)["found"] is False


# --- deep_scan --------------------------------------------------------------


def test_deep_scan_found_and_visited_dedup(monkeypatch):
    scanner = SiteScanner()
    provider = make_provider(keyword={"Match": ["found"]})
    scanner.all_providers = {"Example": provider}

    calls = []

    def fake_fetch(user, prov):
        calls.append(user)
        return 200, "profile found"

    monkeypatch.setattr(scanner, "fetch_user_profile", fake_fetch)

    result = scanner.deep_scan("alice", provider)
    assert result["found"] is True
    assert result["profile_url"] == "https://example.com/alice"
    assert "https://example.com/alice" in scanner.visited_urls
    assert scanner.found_accounts["Example"] == {"https://example.com/alice"}

    # Second scan of the same URL must be skipped (no extra fetch).
    result2 = scanner.deep_scan("alice", provider)
    assert result2["found"] is False
    assert len(calls) == 1


def test_deep_scan_records_emails_as_dict(monkeypatch):
    scanner = SiteScanner()
    provider = make_provider(hasEmail=True, keyword={"Match": ["found"]})
    scanner.all_providers = {"Example": provider}

    def fake_fetch(user, prov):
        return 200, "found, contact alice@example.com"

    monkeypatch.setattr(scanner, "fetch_user_profile", fake_fetch)

    result = scanner.deep_scan("alice", provider)
    assert isinstance(scanner.found_emails, dict)
    # check_breach is False -> email recorded as not-breached
    assert scanner.found_emails.get("alice@example.com") is False
    assert "alice@example.com" in result["infos"]["emails"]


def test_deep_scan_unknown_linked_provider_does_not_crash(monkeypatch):
    scanner = SiteScanner()
    provider = make_provider(keyword={"Match": ["found"]})
    scanner.all_providers = {"Example": provider}

    def fake_search(html, prov):
        return {
            "other_links": {"NonExistentProvider": ["https://nope.com/x"]},
            "other_usernames": set(),
            "infos": {"emails": {}, "passwords": {}, "breach_count": {}},
        }

    monkeypatch.setattr(scanner, "fetch_user_profile", lambda u, p: (200, "found"))
    monkeypatch.setattr(scanner, "search_in_response", fake_search)

    # Should not raise even though the linked provider is unknown.
    result = scanner.deep_scan("alice", provider)
    assert result["found"] is True


# --- concurrency ------------------------------------------------------------


def test_concurrent_deep_scan_same_url_fetches_once(monkeypatch):
    scanner = SiteScanner()
    provider = make_provider(keyword={"Match": ["found"]})
    scanner.all_providers = {"Example": provider}

    fetch_lock = threading.Lock()
    fetch_count = {"n": 0}

    def fake_fetch(user, prov):
        with fetch_lock:
            fetch_count["n"] += 1
        return 200, "found"

    monkeypatch.setattr(scanner, "fetch_user_profile", fake_fetch)

    threads = [
        threading.Thread(target=scanner.deep_scan, args=("alice", provider))
        for _ in range(25)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # The visited-URL guard must ensure a single fetch despite the race.
    assert fetch_count["n"] == 1
    assert scanner.found_accounts["Example"] == {"https://example.com/alice"}


# --- external lookups (mocked) ---------------------------------------------


def test_check_hudsonrock_missing_message_key(monkeypatch):
    scanner = SiteScanner()

    class FakeResp:
        status_code = 200

        def json(self):
            return {}  # no "message" key

    monkeypatch.setattr(
        "linkook.scanner.site_scanner.requests.get", lambda *a, **k: FakeResp()
    )
    assert scanner.check_HudsonRock("a@b.com") is False


def test_check_proxynova_parses_passwords(monkeypatch):
    scanner = SiteScanner()

    class FakeResp:
        status_code = 200

        def json(self):
            return {"lines": ["a@b.com:secret1", "a@b.com:secret2", "other:x"]}

    monkeypatch.setattr(
        "linkook.scanner.site_scanner.requests.get", lambda *a, **k: FakeResp()
    )
    result = scanner.check_ProxyNova("a@b.com")
    assert set(result) == {"secret1", "secret2"}
