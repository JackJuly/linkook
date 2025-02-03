# provider.py

import re
import logging
from typing import Set, List, Dict, Any, Optional


class Provider:
    """
    Provider class represents a single social media or website configuration.
    It holds URL templates, regex patterns, keyword matching rules, and flags indicating additional behavior.

    Attributes:
        name: The name of the provider (e.g. "GitHub").
        main_url: The main site URL (e.g. "https://github.com/").
        profile_url: URL template to visit a user's profile, containing "{}" to insert username.
        query_url: URL template to query for a user, containing "{}" to insert username.
        regex_url: URL template to visit a user's profile, containing "^USER^" to insert username.
        is_connected: If True, the user's profile on this provider usually contains other links.
        is_userid: If True, the username is actually a user ID, not a username.
        has_email: If True, the user's profile on this provider usually contains an email.
        links: An optional list of other providers that this site commonly references or supports linking to.
        options: Optional parameters or extra info that might be required for advanced requests.
        keywords: An optional dictionary containing 'Match' and 'notMatch' lists for keyword-based existence checks.
        handle_regex: An optional dictionary containing regex patterns to extract the handle from the profile page.
        request_method: The HTTP method to use for requests (e.g. "GET" or "POST").
        request_payload: The payload to send with the request, if any.
        headers: The headers to send with the request, if any.
    """

    def __init__(
        self,
        name: str,
        profile_url: str,
        main_url: str,
        regex_url: str,
        query_url: str,
        is_connected: bool,
        is_userid: bool,
        has_email: bool,
        links: List[str] = None,
        options: List[Any] = None,
        keyword: Dict[str, List[str]] = None,
        handle_regex: Dict[str, str] = None,
        request_method: str = "GET",
        request_payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize a Provider instance.

        :param name: Name of the provider (e.g. "GitHub").
        :param main_url: Main site URL (e.g. "https://github.com/").
        :param profile_url: Profile URL template for the user, containing "^USER^" for insertion.
        :param query_url: URL template to query for a user, containing "^USER^" to insert username.
        :param regex_url: URL template to visit a user's profile, containing "^USER^" to insert username.
        :param is_connected: Indicates if this provider's profile page typically contains external links.
        :param is_userid: Indicates if the username is actually a user ID, not a username.
        :param has_email: Indicates if the user's profile on this provider usually contains an email.
        :param links: A list of provider names that can be linked from this provider's profile.
        :param options: Additional options or data used for advanced scanning or requests.
        :param keywords: Dictionary with 'Match' and 'notMatch' lists for existence checks.
        :param handle_regex: Dictionary with regex patterns to extract the handle from the profile page.
        :param request_method: The HTTP method to use for requests (e.g. "GET" or "POST").
        :param request_payload: The payload to send with the request, if any.
        :param headers: The headers to send with the request, if any.
        """
        self.name = name
        self.main_url = main_url
        self.profile_url = profile_url
        self.regex_url = regex_url
        self.query_url = query_url
        self.is_connected = is_connected
        self.is_userid = is_userid
        self.has_email = has_email
        self.links = links if links else []
        self.options = options if options else []
        self.keyword = keyword if keyword else {}
        self.handle_regex = handle_regex if handle_regex else {}
        self.request_method = request_method if request_method else "GET"
        self.request_payload = request_payload if request_payload else {}
        self.headers = headers if headers else {}

        self._link_regex = None
        self._user_regex = None

        self.build_regex()

    def build_regex_url(self, user: str) -> str:
        """
        Build the complete regex URL by substituting the user
        into this provider's regex URL template.

        :param user: The username to insert.
        :return: A full regex URL, or empty string if regex_url is not set.
        """
        if not self.regex_url:
            url = self.profile_url
        else:
            url = self.regex_url

        return self.interpolate_user(url, user)

    def build_url(self, user: str, url: str = None) -> str:
        """
        Build the complete profile URL by substituting the user
        into this provider's profile URL template.

        :param user: The username to insert.
        :param url: The URL template to insert the user into.
        :return: A full profile URL, or empty string if profile_url is not set.
        """
        if url is None:
            url = self.profile_url

        return self.interpolate_user(url, user)

    def build_payload(self, user: str) -> str:
        """
        Build the complete payload by substituting the user
        into this provider's payload template.

        :param user: The username to insert.
        :return: A full payload, or empty string if request_payload is not set.
        """
        if not self.request_payload:
            return ""
        return self.interpolate_user(self.request_payload, user)

    def build_regex(self) -> str:
        """
        Build the complete regex by substituting the user
        into this provider's regex template.

        :return: A full regex, or empty string if user_regex is not set.
        """
        # regex_pattern = "(?:(?!&quot;)[^<>()\[\]'?\"\\\\])+"
        regex_pattern = r"[A-Za-z0-9._=+\-]+"
        link_pattern = self.build_regex_url(regex_pattern)
        self._link_regex = re.compile(link_pattern) if link_pattern else None

        regex_pattern_catch = f"({regex_pattern})"
        user_pattern = self.build_regex_url(regex_pattern_catch)
        self._user_regex = re.compile(user_pattern) if user_pattern else None

    def interpolate_user(self, input_object, user):

        pattern = "^USER^"
        if isinstance(input_object, str):
            return input_object.replace(pattern, user)
        elif isinstance(input_object, dict):
            return {k: self.interpolate_user(v, user) for k, v in input_object.items()}
        elif isinstance(input_object, list):
            return [self.interpolate_user(i, user) for i in input_object]
        return input_object

    def extract_links(self, text: str) -> List[str]:
        """
        Find all matches of this provider's link pattern in the given text.

        :param text: A string that might contain URLs to this provider.
        :return: A list of all matched links.
        """
        if not self._link_regex:
            return []

        result = self._link_regex.findall(text)

        unique_links = list(set(result))
        return unique_links

    def extract_user(self, text: str) -> Set[str]:
        """
        Extract the username from a given html, using the user_regex pattern.

        :param text: A string that might contain URLs to this provider.
        :return: The extracted username, or an empty string if no match was found.
        """
        if not self._user_regex:
            return set()

        result = self._user_regex.findall(text)
        unique_username = set(result)
        return unique_username

    def extract_handle(self, prov_name: str, text: str) -> str:
        """
        Extract the username from a given html, using the handle_regex pattern.

        :param prov_name: The name of the provider to extract the handle for.
        :param text: A string that might contain URLs to this provider.
        :return: The extracted username, or an empty string if no match was found.
        """
        if not self.handle_regex:
            return ""

        handle_regex_pattern = self.handle_regex.get(prov_name)
        if not handle_regex_pattern:
            logging.warning(f"Handle regex pattern not found for {prov_name}")
            return ""

        regex = re.compile(handle_regex_pattern)
        match_handle = regex.search(text)

        if match_handle and match_handle.groups():
            return match_handle.group(1)

        return ""

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "Provider":
        """
        Create a Provider instance from a dictionary typically loaded from JSON.

        :param name: Provider name (key in the JSON, e.g. "GitHub").
        :param data: A dictionary containing fields that describe this provider.
        :return: A fully constructed Provider instance.
        """
        main_url = data.get("mainUrl", "")
        profile_url = data.get("profileUrl", "")
        query_url = data.get("queryUrl", "")
        regex_url = data.get("regexUrl", "")
        is_connected = data.get("isConnected", False)
        is_userid = data.get("isUserId", False)
        has_email = data.get("hasEmail", True)
        links = data.get("links", [])
        options = data.get("options", [])
        keyword = data.get("keyword", {})
        handle_regex = data.get("handle_regex", {})
        request_method = data.get("request_method", "GET")
        request_payload = data.get("request_payload", {})
        headers = data.get("headers", {})

        return cls(
            name=name,
            main_url=main_url,
            profile_url=profile_url,
            query_url=query_url,
            regex_url=regex_url,
            is_connected=is_connected,
            is_userid=is_userid,
            has_email=has_email,
            links=links,
            options=options,
            keyword=keyword,
            handle_regex=handle_regex,
            request_method=request_method,
            request_payload=request_payload,
            headers=headers,
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert this Provider instance back to a serializable dictionary structure,
        which can be used for debugging or re-saving JSON.

        :return: A dictionary containing the Provider's data.
        """
        return {
            "name": self.name,
            "mainUrl": self.main_url,
            "profileUrl": self.profile_url,
            "queryUrl": self.query_url,
            "keyword": self.keyword,
            "request_method": self.request_method,
            "request_payload": self.request_payload,
            "headers": self.headers,
            "isConnected": self.is_connected,
            "isUserId": self.is_userid,
            "hasEmail": self.has_email,
            "links": self.links,
            "handle_regex": self.handle_regex,
            "options": self.options,
        }
