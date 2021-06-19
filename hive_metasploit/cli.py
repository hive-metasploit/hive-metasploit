# Description
"""
Hive Metasploit connector console client
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from argparse import ArgumentParser
from hive_metasploit import HiveMetasploit, HiveHost
from hive_metasploit.color import Color
from libmsf import MsfData
from typing import List

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
        "-hs", "--hive_server", type=str, help="Set Hive server URL", default=None
    )
    parser.add_argument(
        "-hu", "--hive_username", type=str, help="Set Hive username", default=None
    )
    parser.add_argument(
        "-hp", "--hive_password", type=str, help="Set Hive password", default=None
    )
    parser.add_argument(
        "-hn",
        "--hive_project",
        type=str,
        help="Set Hive project name",
        default="msf_project",
    )

    # Hive tags
    parser.add_argument(
        "-hht",
        "--hive_host_tag",
        type=str,
        help="Set tag for Hive host",
        default=None,
    )
    parser.add_argument(
        "-hpt",
        "--hive_port_tag",
        type=str,
        help="Set tag for Hive port",
        default=None,
    )
    parser.add_argument(
        "-hnt",
        "--hive_no_tags",
        action="store_true",
        help="Disable Hive tags for host and port",
    )

    # MSF arguments
    parser.add_argument(
        "-mu",
        "--msf_api_url",
        type=str,
        help="set MSF REST API server URL",
        default=None,
    )
    parser.add_argument(
        "-mk", "--msf_api_key", type=str, help="set MSF REST API key", default=None
    )
    parser.add_argument(
        "-mw",
        "--msf_workspace",
        type=str,
        help="set MSF Workspace name",
        default="default",
    )

    # Import or Export
    parser.add_argument(
        "-I",
        "--import_to_hive",
        action="store_true",
        help="import data form MSF workspace to Hive project",
    )
    parser.add_argument(
        "-E",
        "--export_from_hive",
        action="store_true",
        help="export data form Hive project to MSF workspace",
    )

    # Proxy
    parser.add_argument("-p", "--proxy", type=str, help="Set proxy URL", default=None)
    args = parser.parse_args()

    # Init HiveMetasploit and Color class
    hive_metasploit: HiveMetasploit = HiveMetasploit(
        msf_api_key=args.msf_api_key,
        msf_api_url=args.msf_api_url,
        hive_username=args.hive_username,
        hive_password=args.hive_password,
        hive_server=args.hive_server,
        proxy=args.proxy,
    )
    color: Color = Color()

    # Arguments import or export not set
    if not args.import_to_hive and not args.export_from_hive:
        color.print_error(
            "Not specified what will be import or export! Please set argument -I or -E"
        )
        exit(1)

    # Import or export
    else:

        # Import data from metasploit workspace to hive project
        if args.import_to_hive:
            hive_hosts: List[HiveHost] = hive_metasploit.import_from_metasploit_to_hive(
                hive_project_name=args.hive_project,
                metasploit_workspace_name=args.msf_workspace,
                hive_host_tag=args.hive_host_tag,
                hive_port_tag=args.hive_port_tag,
                hive_auto_tag=not args.hive_no_tags,
            )
            color.print_info(
                "Imported data from Metasploit workspace:",
                args.msf_workspace,
                "to Hive project:",
                args.hive_project,
            )

            for hive_host in hive_hosts:
                for hive_port in hive_host.ports:
                    if hive_host.import_result:
                        color.print_success(
                            "Successfully imported host:",
                            str(hive_host.ip),
                            "port:",
                            str(hive_port.port),
                        )
                    else:
                        color.print_error(
                            "Failed to import host:",
                            str(hive_host.ip),
                            "port:",
                            str(hive_port.port),
                        )

        # Export data from hive project to metasploit workspace
        elif args.export_from_hive:
            msf_data: MsfData = hive_metasploit.export_from_hive_to_metasploit(
                hive_project_name=args.hive_project,
                metasploit_workspace_name=args.msf_workspace,
            )
            color.print_info(
                "Exported data from Hive project:",
                args.hive_project,
                "to Metasploit workspace:",
                args.msf_workspace,
            )

            # Print exported MSF hosts
            for msf_host in msf_data.hosts:
                if msf_host.id != -1:
                    color.print_success(
                        "Successfully exported host:", str(msf_host.address)
                    )
                else:
                    color.print_error("Failed to export host:", str(msf_host.address))

            # Print exported MSF services
            for msf_service in msf_data.services:
                if msf_service.id != -1:
                    color.print_success(
                        "Successfully exported service:",
                        f"{msf_service.port} ({msf_service.proto})",
                        "for host:",
                        str(msf_service.host),
                    )
                else:
                    color.print_error(
                        "Failed to export service:",
                        f"{msf_service.port} ({msf_service.proto})",
                        "for host:",
                        str(msf_service.host),
                    )

            # Print exported MSF vulnerabilities
            for msf_vuln in msf_data.vulns:
                refs: List[str] = list()
                for reference in msf_vuln.refs:
                    if not reference.startswith("URL"):
                        refs.append(reference)
                vuln: str = f"{msf_vuln.name}"
                if len(refs) > 0:
                    vuln += f" {refs}"
                if msf_vuln.id != -1:
                    color.print_success(
                        "Successfully exported vulnerability:",
                        f"{vuln}",
                        "for host:",
                        str(msf_vuln.host),
                    )
                else:
                    color.print_error(
                        "Failed to export vulnerability:",
                        f"{vuln}",
                        "for host:",
                        str(msf_vuln.host),
                    )

            # Print exported MSF loots
            for msf_loot in msf_data.loots:
                if msf_loot.id != -1:
                    color.print_success(
                        "Successfully exported loot:",
                        f"{msf_loot.path} ({msf_loot.ltype})",
                        "for host:",
                        str(msf_loot.host),
                    )
                else:
                    color.print_error(
                        "Failed to export loot:",
                        f"{msf_loot.path} ({msf_loot.ltype})",
                        "for host:",
                        str(msf_loot.host),
                    )

            # Print exported MSF notes
            for msf_note in msf_data.notes:
                if msf_note.id != -1:
                    color.print_success(
                        "Successfully exported note:",
                        f"{msf_note.data} ({msf_note.ntype})",
                        "for host:",
                        str(msf_note.host),
                    )
                else:
                    color.print_error(
                        "Failed to export note:",
                        f"{msf_note.data} ({msf_note.ntype})",
                        "for host:",
                        str(msf_note.host),
                    )

            # Print exported MSF credentials
            for msf_cred in msf_data.creds:
                if msf_cred.id != -1:
                    color.print_success(
                        "Successfully exported credential:",
                        f"{msf_cred.username}/{msf_cred.private_data}",
                        "for host:",
                        str(msf_cred.address),
                    )
                else:
                    color.print_error(
                        "Failed to export credential:",
                        f"{msf_cred.username}/{msf_cred.private_data}",
                        "for host:",
                        str(msf_cred.address),
                    )
