# Description
"""
Hive Metasploit connector console client
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from argparse import ArgumentParser

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a1"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"


# Main function
def main() -> None:
    # Parse script arguments
    parser: ArgumentParser = ArgumentParser(
        description="Import/Export Hive from/to MSF"
    )

    # Hive arguments
    parser.add_argument(
        "-hs", "--hive_server", type=str, help="Set Hive server URL", required=True
    )
    parser.add_argument(
        "-hu", "--hive_username", type=str, help="Set Hive username", required=True
    )
    parser.add_argument(
        "-hp", "--hive_password", type=str, help="Set Hive password", required=True
    )
    parser.add_argument(
        "-hn", "--hive_project", type=str, help="Set Hive project name", required=True
    )

    # MSF arguments
    parser.add_argument(
        "-mu",
        "--msf_api_url",
        type=str,
        help="set MSF REST API server URL",
        required=True,
    )
    parser.add_argument(
        "-mk", "--msf_api_key", type=str, help="set MSF REST API key", required=True
    )
    parser.add_argument(
        "-mw", "--msf_workspace", type=str, help="set MSF Workspace name", required=True
    )

    # Import or Export
    parser.add_argument(
        "-I",
        "--import_from_msf",
        action="store_true",
        help="import to Hive from MSF workspace",
    )
    parser.add_argument(
        "-E",
        "--export_to_msf",
        action="store_true",
        help="export from Hive to MSF workspace",
    )

    # Proxy
    parser.add_argument("-p", "--proxy", type=str, help="Set proxy URL", default=None)
    args = parser.parse_args()
