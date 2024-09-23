#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-

__version__ = "0.0.1"

import argparse
import os
import sys

import yaml

sys.path.append("/app")
from utils.yara_forgerules import rule_output, run_collector, yara_compile

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="enable debug output", action="store_true")
    parser.add_argument(
        "-c",
        "--config",
        help="specify a different config file",
        default="/app/config_files/yara-forge-config.yml",
    )
    args = parser.parse_args()

    # Setup logging based on command line argument or default
    loglevel = "Debug" if args.debug else "Info"

    # Log script version and config file

    # Load YARA Forge config from YAML file
    with open(args.config, "r") as f:
        YARA_FORGE_CONFIG = yaml.safe_load(f)

    # Retrieve YARA rule sets
    yara_rule_repo_sets = run_collector.retrieve_yara_rule_sets(
        YARA_FORGE_CONFIG["repo_staging_dir"],
        YARA_FORGE_CONFIG["yara_repositories"],
    )

    # Write YARA rules to a single file
    logs("Info", "Writing YARA rules to file...")
    repo_file = rule_output.write_yara_rules_to_single_file(
        yara_rule_repo_sets,
        logs,
        output_dir=YARA_FORGE_CONFIG["fetched_rule_dir"],
        output_file="yara_rules.yar",
    )

    # Check YARA packages
    logs("Info", "Checking YARA packages...")
    test_successful = yara_compile.check_yara_packages(
        {
            "file_path": os.path.join(
                YARA_FORGE_CONFIG["fetched_rule_dir"], "yara_rules.yar"
            ),
            "name": "",
        }
    )

    # Exit with appropriate status code based on test success
    exit_code = 0 if test_successful else 1
    logs("Info", f"Script completed with exit code: {exit_code}")
    sys.exit(exit_code)
