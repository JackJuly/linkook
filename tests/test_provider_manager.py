# tests/test_provider_manager.py

import json

import pytest

from linkook.provider.provider_manager import ProviderManager


SAMPLE = {
    "GitHub": {
        "profileUrl": "https://github.com/^USER^",
        "mainUrl": "https://github.com/",
        "keyword": {"Match": ["found"]},
        "isConnected": True,
    },
    "NoKeyword": {
        "profileUrl": "https://nokw.com/^USER^",
        "mainUrl": "https://nokw.com/",
        "isConnected": True,
    },
    "UserIdSite": {
        "profileUrl": "https://uid.com/^USER^",
        "mainUrl": "https://uid.com/",
        "keyword": {"Match": ["found"]},
        "isConnected": True,
        "isUserId": True,
    },
    "NotConnected": {
        "profileUrl": "https://nc.com/^USER^",
        "mainUrl": "https://nc.com/",
        "keyword": {"Match": ["found"]},
        "isConnected": False,
    },
}


@pytest.fixture
def local_json(tmp_path):
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(SAMPLE), encoding="utf-8")
    return str(path)


def test_load_local_providers(local_json):
    manager = ProviderManager(local_json_path=local_json, force_local=True)
    providers = manager.load_providers()
    assert set(providers) == set(SAMPLE)
    assert manager.get_provider("GitHub").profile_url == "https://github.com/^USER^"


def test_filter_providers_excludes_no_keyword_userid_and_disconnected(local_json):
    manager = ProviderManager(local_json_path=local_json, force_local=True)
    manager.load_providers()
    filtered = manager.filter_providers(is_connected=True)
    # Only GitHub passes: has keyword, not userid, connected, has profile_url.
    assert set(filtered) == {"GitHub"}


def test_filter_providers_scan_all_includes_disconnected(local_json):
    manager = ProviderManager(local_json_path=local_json, force_local=True)
    manager.load_providers()
    filtered = manager.filter_providers(is_connected=False)
    assert set(filtered) == {"GitHub", "NotConnected"}


def test_missing_custom_local_path_raises(tmp_path):
    manager = ProviderManager(
        local_json_path=str(tmp_path / "does_not_exist.json"), force_local=True
    )
    with pytest.raises(FileNotFoundError):
        manager.load_providers()
