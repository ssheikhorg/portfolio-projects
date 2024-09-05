import os
import traceback

import yara
from plyara.utils import rebuild_yara_rule


def write_yara_rules_to_single_file(
    yara_rule_repo_sets,
    logs,
    output_dir="/ziv/shared/packages",
    output_file="yara_rules.yara",
):
    logs("Info", "Starting to write YARA rules to a single file.")
    if not os.path.exists(output_dir):
        logs(
            "Info", f"Output directory does not exist. Creating directory: {output_dir}"
        )
        os.makedirs(output_dir)

    output_path = os.path.join(output_dir, output_file)
    logs("Info", f"Output path set to: {output_path}")

    yara_rule_file_content = ""

    dummy = ""  # Placeholder for external variables

    for repo in yara_rule_repo_sets:
        logs("Info", f"Processing repository: {repo['name']}")
        for rule_set in repo["rules_sets"]:
            logs("Debug", f"Processing rule set from file: {rule_set['file_path']}")
            for rule in rule_set["rules"]:
                yara_rule_str = rebuild_yara_rule(rule)
                # Try to compile the YARA rule
                try:
                    yara.compile(
                        source=yara_rule_str,
                        externals={
                            "filename": dummy,
                            "filepath": dummy,
                            "extension": dummy,
                            "filetype": dummy,
                            "md5": dummy,
                        },
                    )
                    yara_rule_file_content += yara_rule_str + "\n"
                    logs(
                        "Debug",
                        f"Successfully compiled YARA rule from file: {rule_set['file_path']}",
                    )
                except Exception as e:
                    logs("Error", f"Error in YARA rule: {rule_set['file_path']}")
                    traceback.print_exc()

    # Write the successfully compiled YARA rules to the output file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(yara_rule_file_content)
    logs("Info", f"Successfully wrote YARA rules to file: {output_path}")
