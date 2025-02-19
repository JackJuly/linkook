# provider_manager.py

import os
import json
import logging
import requests
from typing import Dict
from colorama import Fore, Style
from importlib.resources import files
from linkook.provider.provider import Provider
from requests.exceptions import RequestException


class ProviderManager:
    """
    ProviderManager is responsible for loading and managing provider configurations.
    By default, it attempts to load from a remote URL, and if it fails, it falls back
    to a local JSON file. It also supports a 'force_local' flag to skip remote loading.
    """

    def __init__(
        self,
        remote_json_url: str = "https://raw.githubusercontent.com/JackJuly/linkook/refs/heads/main/linkook/provider/provider.json",
        local_json_path: str = "linkook/provider/provider.json",
        force_local: bool = False,
        timeout: int = 10,
    ):
        """
        Initialize the ProviderManager with both remote and local paths.

        :param remote_json_url: A string representing the default remote URL to load provider.json.
        :param local_json_path: A string representing the local file path as a fallback or forced option.
        :param force_local: If True, skip remote loading and only use the local JSON file.
        :param timeout: Timeout in seconds for remote requests.
        """
        self.remote_json_url = remote_json_url
        self.local_json_path = local_json_path
        self.force_local = force_local
        self.timeout = timeout

        if local_json_path is None:
            self.local_json_path = files("linkook.provider").joinpath("provider.json")

        self._providers: Dict[str, Provider] = {}

    def load_providers(self) -> Dict[str, Provider]:
        """
        Load providers from either the remote URL (by default) or local file, depending
        on force_local or if a network request fails.

        :return: A dictionary mapping provider_name -> Provider object.
        """
        # If user forces local, skip remote attempt.
        if self.force_local:
            data = self._load_local_json(self.local_json_path)
        else:
            # Try loading from remote URL
            try:
                data = self._load_remote_json(self.remote_json_url, self.timeout)
            except (RequestException, ValueError) as e:
                # If any network or JSON parsing error occurs, we fallback to local
                print(
                    f"{Fore.YELLOW}Remote loading failed! Falling back to local provider.json...{Style.RESET_ALL}"
                )
                logging.warning(f"Remote loading failed: {e}")
                data = self._load_local_json(self.local_json_path)

        # Now that we have 'data', convert it into Provider objects
        self._providers = {}
        for provider_name, provider_conf in data.items():
            provider_obj = Provider.from_dict(provider_name, provider_conf)
            self._providers[provider_name] = provider_obj

        return self._providers

    def _load_remote_json(self, url: str, timeout: int) -> dict:
        """
        Perform an HTTP GET to retrieve JSON data from the given URL.

        :param url: The remote URL to fetch.
        :param timeout: Timeout in seconds.
        :return: A dictionary parsed from the JSON response.
        """
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()  # Raises an HTTPError for 4xx/5xx responses
        data = response.json()  # Could raise a ValueError if invalid JSON
        return data

    def _load_local_json(self, path: str) -> dict:
        """
        Load JSON from a local file.

        :param path: The file path of the local JSON.
        :return: A dictionary parsed from the JSON file.
        """
        if not os.path.isfile(path):
            if path != "linkook/provider/provider.json":
                print(f"{Fore.RED}Local provider.json not found at: {path}{Style.RESET_ALL}")
                raise FileNotFoundError
            else:
                path = files("linkook.provider").joinpath("provider.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def get_all_providers(self) -> Dict[str, Provider]:
        """
        Retrieve the internal dictionary of all loaded providers.

        :return: A dictionary mapping provider_name -> Provider object.
        """
        return self._providers

    def get_provider(self, provider_name: str) -> Provider:
        """
        Retrieve a specific Provider object by its name.

        :param provider_name: The name of the provider to look up.
        :return: The corresponding Provider object, or None if not found.
        """
        return self._providers.get(provider_name)

    def filter_providers(
        self, have_profile_url: bool = True, is_connected: bool = True
    ) -> Dict[str, Provider]:
        """
        Return a subset of providers that match certain criteria.
        For example, if have_profile_url=True, only those with a non-empty profileUrl will be returned.
        If have_connect=True, only providers with have_connect=True will be returned.

        :param have_profile_url: If True, filter out any provider with no profileUrl set.
        :param is_connected: If True, filter out any provider that does not have 'have_connect' set to True.
        :return: A dictionary mapping provider_name -> Provider object that meet the given criteria.
        """
        filtered = {}
        for name, p in self._providers.items():
            if not p.keyword:
                continue
            if p.is_userid:
                continue
            if have_profile_url and not p.profile_url:
                continue
            if is_connected and not p.is_connected:
                continue
            filtered[name] = p

        return filtered
