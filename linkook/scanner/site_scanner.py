# site_scanner.py

import re
import logging
import requests
from linkook.provider.provider import Provider
from typing import Set, Dict, Any, Optional, Tuple, List


class SiteScanner:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        """
        Initialize SiteScanner with optional timeout and proxy.
        Add data structures to track visited URLs and discovered accounts.
        """
        self.timeout = timeout
        self.proxy = proxy
        self.all_providers = {}  # Dictionary of all providers
        self.to_scan = {}  # Dictionary of providers to scan
        self.visited_urls = set()  # Set of visited URLs
        self.found_accounts = {}  # Dictionary of found accounts
        self.found_usernames = set()  # Set of found usernames
        self.found_emails = set()  # Set of found emails
        self.found_passwords = set()  # Set of found passwords
        self.check_breach = False  # Flag to check Hudson Rock breach
        self.hibp_key = None  # HaveIBeenPwned API key

        self.email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    def deep_scan(self, user: str, current_provider: Provider) -> dict:

        result: Dict[str, Any] = {
            "found": False,
            "profile_url": "",
            "other_links": {},
            "other_usernames": set(),
            "infos": {},
            "error": None,
        }

        provider = current_provider

        profile_url = provider.build_url(user)

        if profile_url in self.visited_urls:
            logging.debug(f"URL {profile_url} already visited")
            return result
        self.visited_urls.add(profile_url)

        result["profile_url"] = profile_url

        status_code, html_content = self.fetch_user_profile(user, provider)
        check_res = self.check_availability(status_code, html_content, provider)

        result["found"] = check_res["found"]
        result["error"] = check_res["error"]

        if result["error"]:
            return result

        if not check_res["found"]:
            return result

        search_res = self.search_in_response(html_content, provider)

        result["other_links"] = search_res["other_links"]
        result["other_usernames"] = search_res["other_usernames"]
        result["infos"] = search_res["infos"]

        self.found_usernames.update(result["other_usernames"])
        if result["infos"]["emails"]:
            found_email_tuple = tuple(sorted(result["infos"]["emails"].items()))
            self.found_emails.update(found_email_tuple)

        if result["infos"]["passwords"]:
            found_pass_tuple = tuple((key, tuple(value)) for key, value in result["infos"]["passwords"].items())
            self.found_passwords.update(found_pass_tuple)

        if provider.name not in self.found_accounts:
            self.found_accounts[provider.name] = set()
        self.found_accounts[provider.name].add(profile_url)

        for pname, urls in result["other_links"].items():
            provider = self.all_providers.get(pname)
            if pname not in self.found_accounts:
                self.found_accounts[pname] = set()
            if isinstance(urls, list):
                for url in urls:
                    username = provider.extract_user(url).pop()
                    url = provider.build_url(username)
                    self.found_accounts[pname].add(url)
            else:
                username = provider.extract_user(url).pop()
                url = provider.build_url(username)
                self.found_accounts[pname].add(urls)

        return result

    def check_availability(self, status_code: int, html_content: str, current_provider: Provider) -> dict:
        """
        This method checks if a given username is available on a specific provider.
        """

        result: Dict[str, Any] = {
            "found": False,
            "error": None,
        }

        provider = current_provider

        # Check status code

        if status_code is None:
            result["error"] = (
                "Failed to retrieve the profile page (network error/timeout)."
            )
            result["found"] = False
            logging.error(f"Network error while fetching URL")
            return result

        if not (200 <= status_code < 400):
            result["found"] = False
            logging.info(f"Profile not found based on status code: {status_code}")
            return result

        # Check keywords
        keyword_conf = getattr(provider, "keyword", None)
        if keyword_conf is None:
            result["found"] = False
            logging.warning(f"No keyword configuration for provider: {provider.name}")
            return result

        match_list = keyword_conf.get("Match", [])
        not_match_list = keyword_conf.get("notMatch", [])

        if not_match_list:
            if any(bad_kw in html_content for bad_kw in not_match_list):
                result["found"] = False
                logging.info(
                    f"User not found based on notMatch keywords for provider: {provider.name}"
                )
                return result
            else:
                result["found"] = True
                logging.info(
                    f"User found based on notMatch keywords for provider: {provider.name}"
                )
                return result

        if match_list:
            if any(good_kw in html_content for good_kw in match_list):
                result["found"] = True
                logging.info(
                    f"User found based on Match keywords for provider: {provider.name}"
                )
                return result
            else:
                result["found"] = False
                logging.info(
                    f"User not found based on Match keywords for provider: {provider.name}"
                )
                return result
        return result

    def fetch_user_profile(
        self, user: str, current_provider: Provider
    ) -> Tuple[Optional[int], Optional[str], list]:
        """
        Overrides the base method to return status_code, HTML content, and redirect history.
        If an exception occurs or the request fails, returns (None, None, []).

        :param user: The username to fetch.
        :return: A tuple (status_code, html_content, redirect_history).
        """

        provider = current_provider
        method = provider.request_method or "GET"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
        }
        if provider.headers:
            headers.update(provider.headers)

        payload = provider.build_payload(user) or {}

        if provider.query_url:
            url = provider.build_url(user, provider.query_url)
        else:
            url = provider.build_url(user)

        try:
            session = requests.Session()
            if self.proxy:
                session.proxies = {
                    "http": self.proxy,
                    "https": self.proxy,
                }
            if method == "GET":
                logging.info(f"Fetching URL: {url}")
                resp = session.get(
                    url, headers=headers, timeout=self.timeout, allow_redirects=True
                )
            elif method.upper() == "POST":
                logging.info(f"Fetching URL: {url}")
                resp = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            logging.info(f"Response status code: {resp.status_code}")
            return resp.status_code, resp.text
        except Exception as e:
            logging.error(f"Failed to fetch profile page for URL {url}: {e}")
            return None, None

    def search_in_response(self, html: str, current_provider: Provider) -> bool:

        result: Dict[str, Any] = {
            "other_links": {},
            "other_usernames": set(),
            "infos": {
                "emails": {},
                "passwords": {}
                },
        }

        provider = current_provider

        if not provider.is_connected:
            return result

        if provider.has_email:
            emails_set = self.search_info(html)["emails"]
            for email in emails_set:
                if email in self.found_emails:
                    result["infos"]["emails"][email] = self.found_emails[email]

                if self.check_breach:
                    if self.hibp_key is not None:
                        result["infos"]["emails"][email] = self.check_HaveIBeenPwned(email)
                    else:
                        result["infos"]["emails"][email] = self.check_HudsonRock(email)
                    if result["infos"]["emails"][email] == True:
                        check_pass = self.check_ProxyNova(email)
                        if check_pass is not None:
                            result["infos"]["passwords"][email] = check_pass
                else:
                    result["infos"]["emails"][email] = False

        if provider.handle_regex:

            for prov_name in provider.handle_regex.keys():
                handle = provider.extract_handle(prov_name, html)
                if handle:
                    mactch_provider = self.all_providers.get(prov_name)
                    logging.debug(f"Matched provider: {prov_name},{mactch_provider}")
                    if not mactch_provider:
                        continue
                    if not mactch_provider.is_userid:
                        result["other_usernames"].add(handle)
                    links = mactch_provider.build_url(handle)
                    result["other_links"][prov_name] = [links]
            return result

        if hasattr(provider, "links") and provider.links:
            provs_to_search = [
                self.all_providers[name]
                for name in provider.links
                if name in self.all_providers
            ]
        else:
            provs_to_search = [
                p for pname, p in self.all_providers.items() if pname != provider.name
            ]

        result["other_links"] = self.search_new_links(html, provs_to_search)

        other_usernames_set = self.search_new_usernames(html, provs_to_search)

        result["other_usernames"].update(other_usernames_set)


        return result

    def search_new_links(
        self, html: str, provider_list: List[Provider]
    ) -> Dict[str, List[str]]:
        """
        Search link patterns from a list of providers.
        """
        discovered = {}
        for prov in provider_list:
            matches = prov.extract_links(html)
            matches = matches
            if matches:
                discovered[prov.name] = matches
        return discovered

    def search_new_usernames(
        self, html: str, provider_list: List[Provider]
    ) -> Set[str]:
        """
        Extract all unique usernames from the given HTML content using the provided list of providers.

        :param html: HTML content to search within.
        :param provider_list: List of Provider instances to use for extracting usernames.
        :return: A set of unique usernames discovered.
        """
        discovered = set()
        for prov in provider_list:
            if prov.is_userid:
                continue
            matches = prov.extract_user(html)
            if matches:
                discovered.update(matches)
        return discovered

    def search_info(self, html: str) -> Dict[str, Any]:
        """
        Search for related personal information in the HTML content.
        """
        result = {"emails": set()}

        matches = re.findall(self.email_regex, html)
        if matches:
            result["emails"].update(matches)
        return result

    def check_HaveIBeenPwned(self, email: str) -> bool:
        """
        Check if the user's data has been leaked in the HaveIBeenPwned database.
        """
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.hibp_key,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
        }
        try:
            res = requests.get(url, headers=headers, timeout=5)
        except requests.exceptions.RequestException:
            return False
        status_code = res.status_code
        if status_code is None:
            return False
        if status_code == 404:
            return False
        if status_code == 200:
            return True
        return False

    def check_HudsonRock(self, email: str) -> bool:
        """
        Check if the user's data has been leaked in the Hudson Rock database.
        """
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
        associated_string = "This email address is associated with a computer that was infected by an info-stealer, all the credentials saved on this computer are at risk of being accessed by cybercriminals. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data."
        not_associated_string = "This email address is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data."
        try:
            res = requests.get(url, timeout=5)
        except requests.exceptions.RequestException:
            return False
        status_code = res.status_code
        if status_code is None:
            return False
        if status_code == 404:
            return False
        if status_code == 200:
            json_content = res.json()
            if json_content["message"] == associated_string:
                return True
            elif json_content["message"] == not_associated_string:
                return False
        return False

    def check_ProxyNova(self, email: str) -> List[str]:
        """
        Check ProxyNova for leaked credentials.
        """
        url = f"https://api.proxynova.com/comb?query={email}"
        try:
            res = requests.get(url, timeout=5)
        except requests.exceptions.RequestException:
            return None
        if res.status_code is None or res.status_code == 404:
            return None
        if res.status_code == 200:
            json_content = res.json()
            lines = json_content.get("lines", [])
            password_set = set()
            prefix = f"{email}:"
            for line in lines:
                if line.startswith(prefix):
                    parts = line.split(":", 1)  
                    if len(parts) == 2:
                        pass_part = parts[1].strip()
                        if pass_part:
                            password_set.add(pass_part)
            return list(password_set)
        return None