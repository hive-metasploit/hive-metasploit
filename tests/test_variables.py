# Description
"""
Variables for unit tests
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from typing import Optional
from libmsf import Msf
from hive_library import HiveLibrary
from ipaddress import IPv4Address
from datetime import datetime

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a1"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"


# Class MsfVariablesForTest
class MsfVariablesForTest:

    api_url: Optional[str] = None
    api_key: Optional[str] = None
    proxy: Optional[str] = "http://127.0.0.1:8888"

    workspace: Msf.Workspace = Msf.Workspace(
        name="unit_test_workspace", description="Workspace for unit tests"
    )

    host: Msf.Host = Msf.Host(
        workspace=workspace.name,
        address=IPv4Address("192.168.1.1"),
        mac="00:11:22:33:44:55",
        name="unit.test.com",
        os_name="linux",
        os_family="posix",
        os_flavor="test",
        os_sp="test",
        os_lang="English",
        purpose="device",
        info="Host for unit tests",
        comments="Host for unit tests",
        scope="unit tests scope",
        virtual_host="unittest",
        arch="x86",
        state="alive",
        comm="unittest",
    )

    service: Msf.Service = Msf.Service(
        workspace=workspace.name,
        host=host.address,
        port=12345,
        proto="tcp",
        state="open",
        name="http",
        info="Unit test",
    )

    vuln: Msf.Vuln = Msf.Vuln(
        workspace=workspace.name,
        host=host.address,
        port=service.port,
        name="Unit test vuln name",
        info="Unit test vuln info",
        refs=["CVE-2020-2020", "URL-https://unit.test.com/vuln"],
    )

    loot: Msf.Loot = Msf.Loot(
        workspace=workspace.name,
        host=host.address,
        port=service.port,
        ltype="unit.test.type",
        data="dGVzdA==",
        name="/tmp/unit.test",
        info="Unit test file",
        content_type="text/plain",
        path="path.txt",
    )

    note: Msf.Note = Msf.Note(
        workspace=workspace.name,
        host=host.address,
        ntype="host.comments",
        data="Unit test host comment",
        critical=True,
        seen=True,
    )

    login: Msf.Login = Msf.Login(
        address=host.address,
        port=service.port,
        last_attempted_at=datetime.strptime(
            "2021-01-01T11:11:11.111Z", "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        service_name=service.name,
        protocol=service.proto,
        status="Successful",
        access_level="admin",
    )

    cred: Msf.Cred = Msf.Cred(
        address=host.address,
        port=service.port,
        username="UnitTestUser",
        private_data="UnitTestPassword",
        private_type="password",
        module_fullname="auxiliary/scanner/http/http_login",
        service_name=service.name,
        protocol=service.proto,
        origin_type="service",
    )


# Class HiveVariablesForTest
class HiveVariablesForTest:
    server: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    proxy: Optional[str] = "http://127.0.0.1:8888"

    project: HiveLibrary.Project = HiveLibrary.Project(
        name="unit_test_project", description="Project for unit test"
    )

    host: HiveLibrary.Host = HiveLibrary.Host(
        ip=IPv4Address("192.168.1.1"),
        records=[
            HiveLibrary.Record(
                name="Host information",
                tool_name="metasploit",
                record_type="nested",
                value=[
                    HiveLibrary.Record(
                        name="Host IP address",
                        tool_name="metasploit",
                        record_type="string",
                        value="192.168.1.1",
                    ),
                    HiveLibrary.Record(
                        name="Host MAC address",
                        tool_name="metasploit",
                        record_type="string",
                        value="00:11:22:33:44:55",
                    ),
                    HiveLibrary.Record(
                        name="Host OS common",
                        tool_name="metasploit",
                        record_type="string",
                        value="unittest",
                    ),
                    HiveLibrary.Record(
                        name="Host name",
                        tool_name="metasploit",
                        record_type="string",
                        value="unit.test.com",
                    ),
                    HiveLibrary.Record(
                        name="Host state",
                        tool_name="metasploit",
                        record_type="string",
                        value="alive",
                    ),
                    HiveLibrary.Record(
                        name="Host OS name",
                        tool_name="metasploit",
                        record_type="string",
                        value="linux",
                    ),
                    HiveLibrary.Record(
                        name="Host OS flavor",
                        tool_name="metasploit",
                        record_type="string",
                        value="test",
                    ),
                    HiveLibrary.Record(
                        name="Host OS service pack",
                        tool_name="metasploit",
                        record_type="string",
                        value="test",
                    ),
                    HiveLibrary.Record(
                        name="Host OS language",
                        tool_name="metasploit",
                        record_type="string",
                        value="English",
                    ),
                    HiveLibrary.Record(
                        name="Host architecture",
                        tool_name="metasploit",
                        record_type="string",
                        value="x86",
                    ),
                    HiveLibrary.Record(
                        name="Host purpose",
                        tool_name="metasploit",
                        record_type="string",
                        value="device",
                    ),
                    HiveLibrary.Record(
                        name="Host info",
                        tool_name="metasploit",
                        record_type="string",
                        value="Host for unit tests",
                    ),
                    HiveLibrary.Record(
                        name="Host comments",
                        tool_name="metasploit",
                        record_type="string",
                        value="Host for unit tests",
                    ),
                    HiveLibrary.Record(
                        name="Host scope",
                        tool_name="metasploit",
                        record_type="string",
                        value="unit tests scope",
                    ),
                    HiveLibrary.Record(
                        name="Host virtual host",
                        tool_name="metasploit",
                        record_type="string",
                        value="unittest",
                    ),
                    HiveLibrary.Record(
                        name="Host OS family",
                        tool_name="metasploit",
                        record_type="string",
                        value="posix",
                    ),
                ],
            ),
            HiveLibrary.Record(
                name="Loot",
                tool_name="metasploit",
                record_type="nested",
                value=[
                    HiveLibrary.Record(
                        name="Loot type",
                        tool_name="metasploit",
                        record_type="string",
                        value="unit.test.type",
                    ),
                    HiveLibrary.Record(
                        name="Loot data",
                        tool_name="metasploit",
                        record_type="string",
                        value="test",
                    ),
                    HiveLibrary.Record(
                        name="Loot name",
                        tool_name="metasploit",
                        record_type="string",
                        value="/tmp/unit.test",
                    ),
                    HiveLibrary.Record(
                        name="Loot path",
                        tool_name="metasploit",
                        record_type="string",
                        value="/Users/vladimir/.msf4/loot/0e278c9513ffdc98c2d4-path.txt",
                    ),
                    HiveLibrary.Record(
                        name="Loot info",
                        tool_name="metasploit",
                        record_type="string",
                        value="Unit test file",
                    ),
                    HiveLibrary.Record(
                        name="Loot content type",
                        tool_name="metasploit",
                        record_type="string",
                        value="text/plain",
                    ),
                ],
            ),
            HiveLibrary.Record(
                name="Note",
                tool_name="metasploit",
                record_type="nested",
                value=[
                    HiveLibrary.Record(
                        name="Note type",
                        tool_name="metasploit",
                        record_type="string",
                        value="host.comments",
                    ),
                    HiveLibrary.Record(
                        name="Note data",
                        tool_name="metasploit",
                        record_type="string",
                        value="Unit test host comment",
                    ),
                ],
            ),
        ],
        names=[
            HiveLibrary.Host.Name(
                hostname="unit.test.com",
                records=[],
                tags=[],
            )
        ],
        ports=[
            HiveLibrary.Host.Port(
                port=12345,
                service=HiveLibrary.Host.Port.Service(
                    name="http", product="Unit test", version=None, cpelist=None
                ),
                protocol="tcp",
                state="open",
                records=[
                    HiveLibrary.Record(
                        name="Vulnerability",
                        tool_name="metasploit",
                        record_type="nested",
                        value=[
                            HiveLibrary.Record(
                                name="Vulnerability name",
                                tool_name="metasploit",
                                record_type="string",
                                value="Unit test vuln name",
                            ),
                            HiveLibrary.Record(
                                name="Vulnerability info",
                                tool_name="metasploit",
                                record_type="string",
                                value="Unit test vuln info",
                            ),
                            HiveLibrary.Record(
                                name="Vulnerability references",
                                tool_name="metasploit",
                                record_type="list",
                                value=[
                                    "CVE-2020-2020",
                                    "URL-https://unit.test.com/vuln",
                                ],
                            ),
                        ],
                    ),
                    HiveLibrary.Record(
                        name="Credentials",
                        tool_name="metasploit",
                        record_type="nested",
                        value=[
                            HiveLibrary.Record(
                                name="Username",
                                tool_name="metasploit",
                                record_type="string",
                                value="UnitTestUser",
                            ),
                            HiveLibrary.Record(
                                name="Password",
                                tool_name="metasploit",
                                record_type="string",
                                value="UnitTestPassword",
                            ),
                            HiveLibrary.Record(
                                name="Module",
                                tool_name="metasploit",
                                record_type="string",
                                value="auxiliary/scanner/http/http_login",
                            ),
                        ],
                    ),
                ],
                tags=[],
            )
        ],
        tags=[
            HiveLibrary.Tag(name="Vulnerable: Unit test vuln name"),
            HiveLibrary.Tag(name="Credential: UnitTestUser"),
        ],
    )
