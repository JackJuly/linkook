# console_print.py

import logging
import argparse
import webbrowser
from colorama import Fore, Style
from typing import Optional, Any, Dict


class CustomHelpFormatter(argparse.HelpFormatter):
    def format_help(self):

        description = "Linkook: Scan connected social accounts for a given username."
        usage = f"Usage: {self._prog} username [options]"
        help_text = super().format_help()
        return f"\n{description}\n\n{usage}\n\n{help_text}"


class ConsolePrinter:
    """
    ConsolePrint class handles printing scan results to the console.
    It supports debug logging and conditional printing based on user preferences.
    """

    def __init__(
        self,
        debug: bool = False,
        print_all: bool = False,
        silent: bool = False,
        concise: bool = False,
        browse: bool = False,
    ):
        """
        Initialize the ConsolePrint notifier.

        :param debug: If True, print detailed debugging information.
        :param print_all: If True, print all results, including not found.
        :param silent: If True, print minimal output.
        :param concise: If True, print concise output.
        :param browse: If True, trigger browsing to found profiles (implementation needed).
        """
        self.debug = debug
        self.print_all = print_all
        self.silent = silent
        self.concise = concise
        self.browse = browse
        self.current_username: Optional[str] = None

    def banner(self):
        """
        Print the Linkook banner.
        """
        banner = r""" __         __     __   __     __  __     ______     ______     __  __    
/\ \       /\ \   /\ "-.\ \   /\ \/ /    /\  __ \   /\  __ \   /\ \/ /    
\ \ \____  \ \ \  \ \ \-.  \  \ \  _"-.  \ \ \/\ \  \ \ \/\ \  \ \  _"-.  
 \ \_____\  \ \_\  \ \_\\"\_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\ \_\ 
  \/_____/   \/_/   \/_/ \/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/ 

v1.1.0                                                     - by @JackJu1y
"""
        print(f"{Fore.CYAN}{Style.BRIGHT}{banner}{Style.RESET_ALL}")

    def start(self, username: str):
        """
        Notify that scanning for a username has started.

        :param username: The username being scanned.
        """
        self.current_username = username
        print(
            f"{Fore.CYAN}\rScanning for username: {Style.BRIGHT}{username}{Style.RESET_ALL}"
        )

    def start_other_links(self):

        if self.silent:
            return
        print("-" * 55)
        print(f"{Fore.YELLOW}Scanning for connected links...{Style.RESET_ALL}")

    def update(self, result: Dict[str, Any]):
        """
        Update the scan results.

        :param result: A dictionary containing scan results for a specific site.
        """
        site = result.get("site_name", "Unknown Site")
        status = result.get("status", "UNKNOWN")
        profile_url = result.get("profile_url", "")
        other_links = result.get("other_links", {})
        other_links_flag = result.get("other_links_flag", False)
        infos = result.get("infos", {})
        hibp = result.get("hibp", None)
        status_text = ""

        if self.print_all or status == "FOUND":
            if status == "FOUND":
                if other_links_flag:
                    flag_color = Fore.YELLOW
                else:
                    flag_color = Fore.GREEN
                color = Fore.GREEN
                status_text = "Profile URL"
                status_flag = f"{flag_color}{Style.BRIGHT}[+]{Style.RESET_ALL}"
            elif status == "NOT FOUND":
                color = Fore.RED
                status_text = "Profile Not Found"
                status_flag = f"{color}{Style.BRIGHT}[x]{Style.RESET_ALL}"
            else:
                color = Fore.MAGENTA
                status_text = "Unknown Status"
                status_flag = f"{color}{Style.BRIGHT}[?]{Style.RESET_ALL}"

            if not self.concise:
                print("-" * 55)
                print(
                    f"{status_flag} Site Name: {color}{Style.BRIGHT}{site}{Style.RESET_ALL}"
                )
                print(f"{status_text}: {color}{profile_url}{Style.RESET_ALL}")
            else:
                print(
                    f"{status_flag} {color}{Style.BRIGHT}{site}:{Style.RESET_ALL} {color}{profile_url}{Style.RESET_ALL}"
                )

            emails = infos.get("emails", {})
            if emails:
                if not self.concise:
                    message = "Found Emails:"
                else:
                    message = f"{Fore.CYAN}{Style.BRIGHT}[i] Emails:{Style.RESET_ALL}"
                message_str = []
                for email, isbreached in emails.items():
                    if isbreached:
                        if hibp is not None:
                            message_str.append(
                                f"{Fore.RED}{email}(HIBP detected){Style.RESET_ALL}"
                            )
                        else:
                            message_str.append(
                                f"{Fore.RED}{email}(Breach detected){Style.RESET_ALL}"
                            )
                    else:
                        message_str.append(f"{Fore.CYAN}{email}{Style.RESET_ALL}")

                email_str = ", ".join(message_str)
                print(f"{message} {email_str}")
            
            passwords = infos.get("passwords", {})
            if passwords:
                if not self.concise:
                    message = "Leaked Passwords:\n"
                else:
                    message = f"{Fore.RED}{Style.BRIGHT}[!] Passwords:{Style.RESET_ALL}"
                message_str = []
                for email, password in passwords.items():

                    password_part = f", ".join(password)
                    if not self.concise:
                        message_str.append(f"+ {email}: {Fore.MAGENTA}{password_part}{Style.RESET_ALL}")
                        password_str = "\n".join(message_str)
                    else:
                        message_str.append(f" {Fore.RED}{email}({Fore.MAGENTA}{password_part}{Fore.RED}){Style.RESET_ALL}")
                        password_str = ",".join(message_str)

                print(f"{message}{password_str}")

            if other_links:
                if not self.concise:
                    print(f"Linked Accounts:")

                for provider, urls in other_links.items():

                    if isinstance(urls, list):
                        urls_str = ", ".join(urls)
                    else:
                        urls_str = urls
                    if not self.concise:
                        print(f"+ {provider}: {Fore.YELLOW}{urls_str}{Style.RESET_ALL}")
                    else:
                        print(
                            f"{Fore.YELLOW}{Style.BRIGHT}[+] {provider}:{Style.RESET_ALL} {Fore.YELLOW}{urls_str}{Style.RESET_ALL}"
                        )


    def finish_username(self, username: str):
        """
        Notify that scanning for a specific username has finished.

        :param username: The username that was scanned.
        """
        print(
            f"\n{Fore.MAGENTA}Finished scanning for username: {username}.{Style.RESET_ALL}\n"
        )

    def finish_all(self, print_content: dict, print_summary: bool = False):
        """
        Notify that all scanning processes are complete.

        :param print_content: A dictionary containing all scan results.
        :param print_summary: If True, print a summary of the scan results.
        """
        username = print_content.get("username")
        found_accounts = print_content.get("found_accounts", {})
        found_usernames = print_content.get("found_usernames", set())
        found_emails = print_content.get("found_emails", set())
        found_passwords = print_content.get("found_passwords", set())

        passwords_dict = {email: passwords for email, passwords in found_passwords}

        total_links = sum(len(urls) for urls in found_accounts.values())
        total_sites = len(found_accounts)

        found_usernames.discard(username)
        breached_emails = [email for email, status in found_emails if status]

        count_usernames = len(found_usernames)
        count_emails = len(found_emails)
        count_breached_emails = len(breached_emails)

        count_passwords = sum(len(passwords) for _, passwords in found_passwords)

        total_links_text = f"{Fore.GREEN}{Style.BRIGHT}{total_links}{Style.RESET_ALL}"
        total_sites_text = f"{Fore.GREEN}{Style.BRIGHT}{total_sites}{Style.RESET_ALL}"
        count_usernames_text = (
            f"{Fore.YELLOW}{Style.BRIGHT}{count_usernames}{Style.RESET_ALL}"
        )
        count_emails_text = f"{Fore.CYAN}{Style.BRIGHT}{count_emails}{Style.RESET_ALL}"
        count_breached_emails_text = (
            f"{Fore.RED}{Style.BRIGHT}{count_breached_emails}{Style.RESET_ALL}"
        )
        count_passwords_text = (
            f"{Fore.RED}{Style.BRIGHT}{count_passwords}{Style.RESET_ALL}"
        )

        email_message = (
            f"{Fore.MAGENTA}Found {count_emails_text} {Fore.MAGENTA}related emails"
        )
        if breached_emails:
            email_message += f", {count_breached_emails_text} {Fore.MAGENTA}of them may have been breached{Style.RESET_ALL}"
        email_message += f"{Fore.MAGENTA}.{Style.RESET_ALL}"

        password_message = (
            f"{Fore.MAGENTA}Found {count_passwords_text} {Fore.MAGENTA}leaked passwords.{Style.RESET_ALL}"
        )

        if print_summary:
            print(
                f"\n{Fore.CYAN}{Style.BRIGHT}========================= Scan Summary ========================={Style.RESET_ALL}"
            )
            print(f"\n{Fore.CYAN}Username: {Style.BRIGHT}{username}{Style.RESET_ALL}")
            print(
                f"{Fore.MAGENTA}Found {total_links_text} {Fore.MAGENTA}accounts on {total_sites_text} {Fore.MAGENTA}sites, obtained {count_usernames_text} {Fore.MAGENTA}related usernames.{Style.RESET_ALL}"
            )
            if count_emails > 0:
                print(f"{email_message}")
            if count_passwords > 0:
                print(f"{password_message}")
            if found_usernames:
                print(
                    f"{Fore.YELLOW}Related Usernames: {Style.BRIGHT}{', '.join(found_usernames)}{Style.RESET_ALL}"
                )
            if found_emails:
                print(
                    f"{Fore.CYAN}Related Emails: {Style.BRIGHT}{', '.join(email for email, _ in found_emails)}{Style.RESET_ALL}"
                )
            if breached_emails:
                breached_str = []
                for email in breached_emails:
                    if email in passwords_dict:
                        str = ", ".join(passwords_dict[email])
                        breached_str.append(f"{email}({Fore.MAGENTA}{str}{Fore.RED})")
                    else:
                        breached_str.append(email)
                    
                print(
                    f"{Fore.RED}Breached Emails: {Style.BRIGHT}{', '.join(breached_str)}{Style.RESET_ALL}"
                )
            if found_accounts:
                print(f"{Fore.GREEN}All Found Accounts:{Style.RESET_ALL}\n")
                for provider, urls in found_accounts.items():
                    print(
                        f"{Fore.GREEN}{Style.BRIGHT}{provider}:{Style.RESET_ALL} {', '.join(urls)}"
                    )
            print("")

        else:
            print(
                f"\n{Fore.MAGENTA}Finished all scans. Found {total_links_text} {Fore.MAGENTA}accounts on {total_sites_text} {Fore.MAGENTA}sites, obtained {count_usernames_text} {Fore.MAGENTA}related usernames.{Style.RESET_ALL}"
            )
            print(f"{email_message}\n")

    def browse_results(self, results: Dict[str, Dict[str, Any]]):
        """
        Browse to all found profile URLs in the default web browser.

        :param results: A dictionary containing scan results for each site.
        """
        for site, data in results.items():
            if data["found"]:
                try:
                    webbrowser.open(data["profile_url"])
                    logging.info(f"Opened browser for {site}: {data['profile_url']}")
                except Exception as e:
                    logging.error(f"Failed to open browser for {site}: {e}")
