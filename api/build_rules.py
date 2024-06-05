# -*- coding: utf-8 -*-

import logging
import os
import sys
import traceback

import yara

YARA_RULE_DIRECTORIES = [r"./yara"]


def walk_error(err):
    try:
        if "Error 3" in str(err):
            logging.error(removeNonAsciiDrop(str(err)))
            print("Directory walk error")
            sys.exit(1)
    except UnicodeError as e:
        print("Unicode decode error in walk error message")
        sys.exit(1)


def removeNonAsciiDrop(string):
    nonascii = "error"
    try:
        # Generate a new string without disturbing characters
        nonascii = "".join(i for i in string if ord(i) < 127 and ord(i) > 31)

    except Exception as e:
        traceback.print_exc()
        pass
    return nonascii


def initialize_yara_rules():
    yaraRules = ""
    dummy = ""

    try:
        for yara_rule_directory in YARA_RULE_DIRECTORIES:
            if not os.path.exists(yara_rule_directory):
                continue
            logging.info("Processing YARA rules folder {0}".format(yara_rule_directory))
            for root, directories, files in os.walk(
                yara_rule_directory, onerror=walk_error, followlinks=False
            ):
                for file in files:
                    try:

                        # Full Path
                        yaraRuleFile = os.path.join(root, file)

                        # Skip hidden, backup or system related files
                        if (
                            file.startswith(".")
                            or file.startswith("~")
                            or file.startswith("_")
                        ):
                            continue

                        # Extension
                        extension = os.path.splitext(file)[1].lower()

                        # Test Compile
                        try:
                            compiledRules = yara.compile(
                                yaraRuleFile,
                                externals={
                                    "filename": dummy,
                                    "filepath": dummy,
                                    "extension": dummy,
                                    "filetype": dummy,
                                    "md5": dummy,
                                },
                            )
                            logging.info("Initializing Yara rule %s" % file)
                        except Exception as e:
                            logging.error("Error in YARA rule: %s" % yaraRuleFile)
                            traceback.print_exc()
                            sys.exit(1)

                        # Encrypted
                        if extension == ".yar":
                            with open(yaraRuleFile, "r") as rulefile:
                                data = rulefile.read()
                                yaraRules += data

                    except Exception as e:
                        logging.error(
                            "Error reading signature file %s ERROR: %s" % yaraRuleFile
                        )
                        traceback.print_exc()
                        sys.exit(1)

        # Compile
        try:
            logging.info(
                "Initializing all YARA rules at once (composed string of all rule files)"
            )
            compiledRules = yara.compile(
                source=yaraRules,
                externals={
                    "filename": dummy,
                    "filepath": dummy,
                    "extension": dummy,
                    "filetype": dummy,
                    "md5": dummy,
                },
            )
            logging.info("Initialized all Yara rules at once")

        except Exception as e:
            traceback.print_exc()
            logging.error(
                "Error during YARA rule compilation when all YARA rules are are combined in a single file"
            )
            sys.exit(1)

    except Exception as e:
        traceback.print_exc()
        logging.error("Unexpected error while walking the directories")
        sys.exit(1)


# MAIN ################################################################
if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger("sigbase").addHandler(console)

    # Compile YARA rules
    initialize_yara_rules()
