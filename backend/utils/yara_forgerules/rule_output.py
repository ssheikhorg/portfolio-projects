"""
This module contains functions for writing YARA rules into separate files.
"""

import datetime
import logging
import os

from plyara.utils import rebuild_yara_rule


def write_yara_packages(processed_yara_repos, yaraqa_commit, YARA_FORGE_CONFIG):
    """
    Writes YARA rules into separate files.
    """

    # List of files that were written
    package_files = []

    # Create the directory for the rule package
    package_dir = os.path.join("/ziv/shared/packages", "combined")
    if not os.path.exists(package_dir):
        os.makedirs(package_dir)
    # Create the rule file name
    rule_file_name = "yara-rules-combined.yar"
    # Create the rule file path
    rule_file_path = os.path.join(package_dir, rule_file_name)

    # Write information about the rule package, the output file name
    # and the output file path to the console
    logging.info(
        "------------------------------------------------------------------------"
    )
    logging.info("Creating YARA rule package '%s': %s", "combined", rule_file_path)
    logging.info("Description: %s", "Default YARA Rule Package")
    # List of strings composed of the rules from each repository
    output_rule_set_strings = []

    # Loop over the repositories
    for repo in processed_yara_repos:
        # Debug output
        logging.info("Writing YARA rules from repository: %s", repo["name"])

        # Repo rule set string
        repo_rules_strings = []
        # Loop over the rule sets in the repository and modify the rules
        for rule_sets in repo["rules_sets"]:
            # Debug output
            logging.debug(
                "Writing YARA rules from rule set: %s", rule_sets["file_path"]
            )
            # List of required private rules
            required_private_rules = []
            # Loop over the rules in the rule set
            for rule in rule_sets["rules"]:

                # Debug output
                # pprint(rule)

                # Skip private rules
                if "scopes" in rule and "private" in rule["scopes"]:
                    continue

                # Write the rule into the output file
                repo_rules_strings.append(rebuild_yara_rule(rule))

        # Only write the rule set if there's at least one rule in the set
        if len(repo_rules_strings) > 0:
            # Prepend header to the output string
            repo_rule_set_header = YARA_FORGE_CONFIG["repo_header"].format(
                repo_name=repo["name"],
                repo_url=repo["url"],
                retrieval_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                repo_commit=yaraqa_commit,
                total_rules=len(repo_rules_strings),
                repo_license=repo["license"],
            )
            # Append the rule set string to the list of rule set strings
            output_rule_set_strings.append(repo_rule_set_header)
            output_rule_set_strings.extend(repo_rules_strings)

    # Only write the rule file if there's at least one rule in all sets in the package
    if output_rule_set_strings:
        with open(rule_file_path, "w", encoding="utf-8") as f:
            # Write the output rule set strings to the file
            f.write("".join(output_rule_set_strings))

            # Add the name of the repo and the file path to the output file to the list
            package_files.append(
                {
                    "name": "combined",
                    "file_path": rule_file_path,
                }
            )

    return package_files
