#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-

__version__ = "0.8.1"

import argparse
import logging
import os
import sys

import yaml

sys.path.append("/app")
from utils.yara_forgerules import rule_output, run_collector, yara_compile


def write_section_header(title, divider_with=72):
    print("\n" + "=" * divider_with)
    print(title.center(divider_with).upper())
    print("=" * divider_with + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="enable debug output", action="store_true")
    parser.add_argument(
        "-c",
        "--config",
        help="specify a different config file",
        default="/app/config_files/yara-forge-config.yml",
    )
    args = parser.parse_args()

    # Create a new logger to log into the log file /var/log/yara-forge.log
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    # Set the level of the plyara logger to warning
    logging.getLogger("plyara").setLevel(logging.WARNING)
    logging.getLogger("tzlocal").setLevel(logging.CRITICAL)

    # Create a handler for the log file
    fh = logging.FileHandler("/var/log/yara-forge.log")
    fh.setLevel(logging.DEBUG)

    # Create a formatter for the log messages that go to the log file
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    fh.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(fh)

    logger.info("Starting YARA Forge script")

    # Read configuration file
    logger.debug("Reading configuration file: %s", args.config)
    with open(args.config, "r") as f:
        YARA_FORGE_CONFIG = yaml.safe_load(f)

    # Retrieve the YARA rule sets
    write_section_header("Retrieving YARA rule sets")
    logger.info("Retrieving YARA rule sets from configuration")
    yara_rule_repo_sets = run_collector.retrieve_yara_rule_sets(
        YARA_FORGE_CONFIG["repo_staging_dir"], YARA_FORGE_CONFIG["yara_repositories"]
    )
    logger.debug("Retrieved YARA rule sets: %s", yara_rule_repo_sets)

    # Write the YARA packages
    write_section_header("Writing YARA packages")
    repo_file = rule_output.write_yara_rules_to_single_file(
        yara_rule_repo_sets,
        output_dir=YARA_FORGE_CONFIG["fetched_rule_dir"],
        output_file="yara_rules.yar",
    )

    # We quality check the output files and look for errors
    # write_section_header("Quality checking YARA packages")
    test_successful = yara_compile.check_yara_packages(
        {
            "file_path": os.path.join(
                YARA_FORGE_CONFIG["fetched_rule_dir"], "yara_rules.yar"
            ),
            "name": "",
        }
    )
    if test_successful:
        logging.log(logging.INFO, "Quality check finished successfully")
        sys.exit(0)
    else:
        logging.log(logging.ERROR, "Quality check failed")
        sys.exit(1)
