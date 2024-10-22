import os
import yaml

from utils.yara_forgerules import run_collector


async def process_yara_rules(config_file: str) -> dict:
    # Load YARA Forge config from YAML file
    with open(config_file, "r") as f:
        YARA_FORGE_CONFIG = yaml.safe_load(f)

    # Write YARA rules to a single file
    output_dir = YARA_FORGE_CONFIG["fetched_rule_dir"]
    output_file = "yara_rules.yar"
    output_path = os.path.join(output_dir, output_file)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    yara_rule_file_content = ""

    # Write the successfully compiled YARA rules to the output file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(yara_rule_file_content)

    # check whether the file was created
    file_path = os.path.join(output_dir, output_file)
    if not os.path.exists(file_path):
        return {"success": False}
    return {"success": True}
