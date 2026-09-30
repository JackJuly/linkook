# tests/test_provider.py

from linkook.provider.provider import Provider


def make_provider(**overrides):
    data = {
        "profileUrl": "https://github.com/^USER^",
        "mainUrl": "https://github.com/",
        "keyword": {"Match": ["found"]},
    }
    data.update(overrides)
    return Provider.from_dict(overrides.get("name", "GitHub"), data)


def test_build_url_substitutes_username():
    p = make_provider()
    assert p.build_url("alice") == "https://github.com/alice"


def test_build_url_with_explicit_template():
    p = make_provider()
    assert (
        p.build_url("bob", "https://api.github.com/users/^USER^")
        == "https://api.github.com/users/bob"
    )


def test_interpolate_user_handles_dict_and_list():
    p = make_provider()
    payload = {"user": "^USER^", "extra": ["^USER^", "static"]}
    assert p.interpolate_user(payload, "carol") == {
        "user": "carol",
        "extra": ["carol", "static"],
    }


def test_extract_user_finds_multiple_usernames():
    p = make_provider()
    text = "see https://github.com/alice and https://github.com/bob here"
    assert p.extract_user(text) == {"alice", "bob"}


def test_extract_user_escapes_literal_dots():
    """A literal '.' in the URL must not match an arbitrary character."""
    p = make_provider()
    # 'githubXcom' would match if '.' were treated as a regex wildcard.
    assert p.extract_user("https://githubXcom/alice") == set()


def test_extract_user_handles_query_string_metachars():
    p = make_provider(profileUrl="https://x.com/?u=^USER^")
    assert p.extract_user("https://x.com/?u=alice") == {"alice"}


def test_extract_single_user_returns_none_when_no_match():
    p = make_provider()
    assert p.extract_single_user("no url in here") is None


def test_extract_single_user_returns_a_match():
    p = make_provider()
    assert p.extract_single_user("https://github.com/alice") == "alice"


def test_extract_links_deduplicates():
    p = make_provider()
    text = "https://github.com/alice https://github.com/alice"
    assert p.extract_links(text) == ["https://github.com/alice"]


def test_build_regex_none_when_no_template():
    p = make_provider(profileUrl="", regexUrl="")
    assert p.extract_user("anything") == set()
    assert p.extract_links("anything") == []
    assert p.extract_single_user("anything") is None
