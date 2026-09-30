# visualize_output.py

import json
from typing import Dict


class Neo4jVisualizer:
    def __init__(self, result: Dict):
        """
        Initialize the Neo4jVisualizer class.

        :param result: The scan result dictionary.
        """
        self.result = result
        self.nodes = []
        self.relationships = []
        self.node_id = 1
        self.relationship_id = 1
        self.account_map = (
            {}
        )  # Tracks created SocialMediaAccount nodes to avoid duplicates
        self.all_providers = {}  # Dictionary of all providers

    def create_user_node(self, username: str) -> str:
        """
        Create a User node.

        :param username: The username of the user.
        """
        user_id = f"u{self.node_id}"
        user_node = {
            "id": user_id,
            "labels": ["User"],
            "properties": {"username": username},
        }
        self.nodes.append(user_node)
        self.node_id += 1
        return user_id

    def create_social_media_account_node(
        self, platform: str, username: str, profile_url: str
    ) -> str:
        """
        Create a SocialMediaAccount node.

        :param platform: The social media platform.
        :param username: The username on the platform.
        :param profile_url: The profile URL.
        """
        # Check if the account has already been created
        if profile_url in self.account_map:
            return self.account_map[profile_url]

        account_id = f"a{self.node_id}"
        account_node = {
            "id": account_id,
            "labels": ["SocialMediaAccount"],
            "properties": {
                "platform": platform,
                "username": username,
                "profile_url": profile_url,
            },
        }
        self.nodes.append(account_node)
        self.account_map[profile_url] = account_id
        self.node_id += 1
        return account_id

    def create_email_node(self, email: str, is_breached: bool) -> str:
        """
        Create an Email node.

        :param email: The email address.
        :param is_breached: Whether the email has been breached.
        """
        # Check if the email has already been created
        for node in self.nodes:
            if node["labels"] == ["Email"] and node["properties"]["address"] == email:
                return node["id"]

        email_id = f"e{self.node_id}"
        email_node = {
            "id": email_id,
            "labels": ["Email"],
            "properties": {"address": email, "is_breached": is_breached},
        }
        self.nodes.append(email_node)
        self.node_id += 1
        return email_id

    def add_has_email_relationship(self, user_id: str, email_id: str) -> None:
        """
        Create a HAS_EMAIL relationship between a User and an Email node.

        :param user_id: The ID of the User node.
        :param email_id: The ID of the Email node.
        """
        relationship = {
            "id": f"r{self.relationship_id}",
            "type": "HAS_EMAIL",
            "startNode": user_id,
            "endNode": email_id,
        }
        self.relationships.append(relationship)
        self.relationship_id += 1

    def add_has_account_relationship(self, user_id: str, account_id: str) -> None:
        """
        Create a HAS_ACCOUNT relationship between a User and a SocialMediaAccount node.

        :param user_id: The ID of the User node.
        :param account_id: The ID of the SocialMediaAccount node.
        """
        relationship = {
            "id": f"r{self.relationship_id}",
            "type": "HAS_ACCOUNT",
            "startNode": user_id,
            "endNode": account_id,
        }
        self.relationships.append(relationship)
        self.relationship_id += 1

    def add_connected_to_relationship(
        self, start_account_id: str, end_account_id: str
    ) -> None:
        """
        Create a CONNECTED_TO relationship between two SocialMediaAccount nodes.

        :param start_account_id: The ID of the start SocialMediaAccount node.
        :param end_account_id: The ID of the end SocialMediaAccount node.
        """
        relationship = {
            "id": f"r{self.relationship_id}",
            "type": "CONNECTED_TO",
            "startNode": start_account_id,
            "endNode": end_account_id,
        }
        self.relationships.append(relationship)
        self.relationship_id += 1

    def process_result(self, username: str) -> None:
        """
        Process the scan result and create nodes and relationships in the graph.

        :param username: The main username.
        """
        user_id = self.create_user_node(username)
        username_list = [username]

        for platform, data in self.result.items():
            if not data.get("found", False):
                continue

            profile_url = data.get("profile_url", "")
            # Dynamically extract the username using the Provider class
            provider = self.all_providers.get(platform)
            if provider is None:
                continue
            if not provider.is_userid:
                sm_username = provider.extract_single_user(profile_url) or ""
            else:
                sm_username = ""

            # Create SocialMediaAccount node
            account_id = self.create_social_media_account_node(
                platform, sm_username, profile_url
            )
            # Create HAS_ACCOUNT relationship
            self.add_has_account_relationship(user_id, account_id)

            # Process other_usernames information
            if sm_username != "" and sm_username not in username_list:
                username_list.append(sm_username)
                new_userid = self.create_user_node(sm_username)
                self.add_connected_to_relationship(user_id, new_userid)
                self.add_connected_to_relationship(new_userid, account_id)

            # Process emails information
            emails = data.get("infos", {}).get("emails", {})
            for email, breached in emails.items():
                email_id = self.create_email_node(email, breached)
                self.add_has_email_relationship(user_id, email_id)

            # Process other_links relationships
            other_links = data.get("other_links", {})
            for linked_platform, urls in other_links.items():
                for url in urls:
                    provider = self.all_providers.get(linked_platform)
                    if provider is None:
                        continue
                    if not provider.is_userid:
                        linked_username = provider.extract_single_user(url) or ""
                    else:
                        linked_username = ""
                    # Create associated SocialMediaAccount node
                    linked_account_id = self.create_social_media_account_node(
                        linked_platform, linked_username, url
                    )
                    # Create HAS_ACCOUNT relationship
                    self.add_has_account_relationship(user_id, linked_account_id)
                    # Create CONNECTED_TO relationship
                    self.add_connected_to_relationship(account_id, linked_account_id)
                    if linked_username != "" and linked_username not in username_list:
                        username_list.append(linked_username)
                        new_userid = self.create_user_node(linked_username)
                        self.add_connected_to_relationship(user_id, new_userid)
                        self.add_connected_to_relationship(
                            new_userid, linked_account_id
                        )

    def convert_sets(self, obj):
        """
        Recursively convert sets in the data structure to lists.

        :param obj: The object to convert.
        """
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, dict):
            return {k: self.convert_sets(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.convert_sets(elem) for elem in obj]
        else:
            return obj

    def export_to_json(self, file_path: str = "neo4j_export.json") -> None:
        """
        Export the graph data to a JSON file.

        :param file_path: The output file path.
        """
        graph_data = {
            "nodes": self.convert_sets(self.nodes),
            "relationships": self.convert_sets(self.relationships),
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=4, ensure_ascii=False)
        print(f"Neo4j JSON data has been generated and saved as '{file_path}'")

    def visualize(self, username: str, output_file: str = "neo4j_export.json") -> None:
        """
        Process the scan results and export them in a Neo4j-compatible JSON format.

        :param username: The main username.
        :param output_file: The output file path.
        """
        self.process_result(username)
        self.export_to_json(output_file)
