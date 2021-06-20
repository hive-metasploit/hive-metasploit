# Description
"""
Hive Metasploit connector class
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from dataclasses import dataclass
from typing import Optional, List
from libmsf import Msf, MsfData
from libmsf.rest import MsfRestApi
from datetime import datetime
from uuid import UUID
from hive_library import HiveLibrary
from hive_library.enum import RecordTypes
from hive_library.rest import HiveRestApi
from hive_metasploit.color import Color
from base64 import b64decode, b64encode
from ipaddress import IPv4Address
from time import sleep

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a1"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"


@dataclass
class MetasploitRecords:
    tool_name: str = "metasploit"
    host: str = "Host information"
    note: str = "Note"
    vuln: str = "Vulnerability"
    cred: str = "Credentials"
    loot: str = "Loot"

    @dataclass
    class Host:
        address: str = "Host IP address"
        mac: str = "Host MAC address"
        comm: str = "Host OS common"
        name: str = "Host name"
        state: str = "Host state"
        os_name: str = "Host OS name"
        os_flavor: str = "Host OS flavor"
        os_sp: str = "Host OS service pack"
        os_lang: str = "Host OS language"
        arch: str = "Host architecture"
        purpose: str = "Host purpose"
        info: str = "Host info"
        comments: str = "Host comments"
        scope: str = "Host scope"
        virtual_host: str = "Host virtual host"
        detected_arch: str = "Host detected architecture"
        os_family: str = "Host OS family"

    @dataclass
    class Note:
        ntype: str = "Note type"
        data: str = "Note data"

    @dataclass
    class Vuln:
        name: str = "Vulnerability name"
        info: str = "Vulnerability info"
        refs: str = "Vulnerability references"

    @dataclass
    class Cred:
        username: str = "Username"
        private_type: str = "Credentials private type"
        private_data: str = "Credentials private data"
        module_full_name: str = "Module"

    @dataclass
    class Loot:
        ltype: str = "Loot type"
        data: str = "Loot data"
        name: str = "Loot name"
        path: str = "Loot path"
        info: str = "Loot info"
        content_type: str = "Loot content type"


@dataclass
class HiveHost(HiveLibrary.Host):
    import_result: bool = False


# Class HiveMetasploit
class HiveMetasploit:
    def __init__(
        self,
        msf_api_key: Optional[str] = None,
        msf_api_url: Optional[str] = None,
        hive_username: Optional[str] = None,
        hive_password: Optional[str] = None,
        hive_server: Optional[str] = None,
        proxy: Optional[str] = None,
    ):
        """
        Init HiveMetasploit class
        Args:
            msf_api_key: MSF REST API key string, example: '5c28984c3b034d2f30eff0070bd779c8080489bcff6bd79872d62f1411331901fa242ae39b6c6a62'
            msf_api_url: MSF REST API server URL string, example: 'https://msf.corp.test.com:5443'
            hive_username: Hive username string, example: 'user@mail.com'
            hive_password: Hive password string, example: 'Password'
            hive_server: Hive server URL string, example: 'https://hive.corp.test.com:443'
            proxy:HTTP Proxy URL string, example: 'http://127.0.0.1:8080'
        """
        self._color: Color = Color()
        self.msf_records: MetasploitRecords = MetasploitRecords()
        self.msf_api: MsfRestApi = MsfRestApi(
            api_key=msf_api_key, api_url=msf_api_url, proxy=proxy
        )
        self.hive_api: HiveRestApi = HiveRestApi(
            username=hive_username,
            password=hive_password,
            server=hive_server,
            proxy=proxy,
        )

    @staticmethod
    def _hive_add_record(
        record: HiveLibrary.Record,
        data: dataclass,
        hive_hosts: List[HiveHost],
        msf_services: List[Msf.Service],
        hive_tag: Optional[str] = None,
    ) -> List[HiveHost]:

        # Check record value
        if len(record.value) == 0:
            return hive_hosts

        # Add record for port of hive host
        if "service_id" in data.__dict__ and isinstance(
            data.__dict__["service_id"], int
        ):

            # Get service by service_id
            data_service: Msf.Service = Msf.Service()
            for service in msf_services:
                if service.id == data.service_id:
                    data_service = service

            # Not found service by service_id
            if data_service.port == -1:
                return hive_hosts

            # Enumerate hive hosts
            for host_index in range(len(hive_hosts)):

                # Check MSF data service address is address of host for import
                if hive_hosts[host_index].ip == data_service.host.address:

                    # Enumerate ports for hive host
                    for port_index in range(len(hive_hosts[host_index].ports)):

                        # Check MSF data service port is port of host for import
                        if (
                            hive_hosts[host_index].ports[port_index].port
                            == data_service.port
                        ):

                            # Add record for port
                            hive_hosts[host_index].ports[port_index].records.append(
                                record
                            )

                            # Add tag
                            if hive_tag is not None:
                                hive_hosts[host_index].tags.append(
                                    HiveLibrary.Tag(name=hive_tag)
                                )

        # Add record for hive host
        elif "host" in data.__dict__ and isinstance(data.__dict__["host"], Msf.Host):

            # Enumerate hive hosts
            for host_index in range(len(hive_hosts)):

                # Check MSF data service address is address of host for import
                if hive_hosts[host_index].ip == data.host.address:

                    # Add record for host
                    hive_hosts[host_index].records.append(record)

                    # Add tag
                    if hive_tag is not None:
                        hive_hosts[host_index].tags.append(
                            HiveLibrary.Tag(name=hive_tag)
                        )

        return hive_hosts

    # Parse Hive records
    def _parse_hive_record(
        self, record: HiveLibrary.Record, result_object: dataclass
    ) -> dataclass:
        for child_record in record.value:
            # If record value is not a record return empty object
            if not isinstance(child_record, HiveLibrary.Record):
                return result_object
            field_name = child_record.name
            field_value = child_record.value

            # Parse MSF host record
            if isinstance(result_object, Msf.Host):
                for key, value in self.msf_records.Host.__dict__.items():
                    if field_name == value:
                        result_object.__dict__[key] = field_value

            # Parse MSF loot record
            if isinstance(result_object, Msf.Loot):
                for key, value in self.msf_records.Loot.__dict__.items():
                    if field_name == self.msf_records.Loot.data:
                        field_value = b64encode(
                            child_record.value.encode("utf-8")
                        ).decode("utf-8")
                    if field_name == value:
                        result_object.__dict__[key] = field_value

            # Parse MSF note record
            if isinstance(result_object, Msf.Note):
                for key, value in self.msf_records.Note.__dict__.items():
                    if field_name == value:
                        result_object.__dict__[key] = field_value

            # Parse MSF vuln record
            if isinstance(result_object, Msf.Vuln):
                for key, value in self.msf_records.Vuln.__dict__.items():
                    if field_name == value:
                        result_object.__dict__[key] = field_value

            # Parse MSF cred record
            if isinstance(result_object, Msf.Cred):
                if field_name == self.msf_records.Cred.username:
                    result_object.username = field_value
                if field_name == self.msf_records.Cred.module_full_name:
                    result_object.module_fullname = field_value
                if field_name == self.msf_records.Cred.private_type:
                    result_object.private_type = field_value
                if field_name == self.msf_records.Cred.private_data:
                    result_object.private_data = field_value
                if field_name == "Password":
                    result_object.private_type = "password"
                    result_object.private_data = field_value

        return result_object

    def import_from_metasploit_to_hive(
        self,
        hive_project_name: str,
        metasploit_workspace_name: str = "default",
        hive_host_tag: Optional[str] = None,
        hive_port_tag: Optional[str] = None,
        hive_auto_tag: bool = True,
    ) -> List[HiveHost]:
        """
        Import data from metasploit workspace to hive project
        Args:
            hive_project_name: Hive project name string, example: 'test_project'
            metasploit_workspace_name: Metasploit workspace name string, example: 'test_workspace'
            hive_host_tag: Set Hive tag for host, example: 'host_tag'
            hive_port_tag: Set Hive tag for port, example: 'port_tag'
            hive_auto_tag: Automatically add tag for Hive hosts

        Returns: List of Hive hosts, example:
        [HiveHost(checkmarks=[], files=[], id=None, uuid=None, notes=[], ip=IPv4Address('192.168.1.1'), ip_binary=None,
                  records=[HiveLibrary.Record(children=[], create_time=None, creator_uuid=None, extra=None, id=None,
                                              uuid=None, import_type=None, name='Host information',
                                              tool_name='metasploit', record_type='nested',
                                              value=[ .... ])],
                  names=[HiveLibrary.Host.Name(checkmarks=[], files=[], id=None, ips=None, uuid=None, notes=[],
                                               hostname='unit.test.com', records=[], sources=[], tags=[])],
                  ports=[HiveLibrary.Host.Port(ip=None, checkmarks=[], files=[], id=None, uuid=None, notes=[], port=12345,
                                               service=HiveLibrary.Host.Port.Service(name='http', product='Unit test',
                                                                                     version=None, cpelist=None),
                                               protocol='tcp', state='open',
                                               records=[HiveLibrary.Record(children=[], create_time=None,
                                                                           creator_uuid=None, extra=None, id=None,
                                                                           uuid=None, import_type=None,
                                                                           name='Vulnerability',
                                                                           tool_name='metasploit',
                                                                           record_type='nested',
                                                                           value=[ .... ])],
                                               sources=[], tags=[])],
                  sources=[], tags=[], import_result=True)]

        """
        hive_hosts: List[HiveHost] = list()
        try:
            # Get Hive project id by name
            hive_project_id: Optional[UUID] = self.hive_api.get_project_id_by_name(
                project_name=hive_project_name
            )

            # Create Hive project if project by name is not found
            if hive_project_id is None:
                self.hive_api.create_project(
                    project=HiveLibrary.Project(name=hive_project_name)
                )
                hive_project_id: Optional[UUID] = self.hive_api.get_project_id_by_name(
                    project_name=hive_project_name
                )
                assert (
                    hive_project_id is not None
                ), f"Failed to create Hive project with name: {hive_project_name}"

            # Get all MSF data
            msf_data: MsfData = self.msf_api.get_all_data(
                workspace=metasploit_workspace_name
            )

            # Add MSF hosts in host for import
            for msf_host in msf_data.hosts:
                hive_host: HiveHost = HiveHost()
                # Set hive host ip address
                hive_host.ip = msf_host.address
                # Set hive host name
                if msf_host.name is not None:
                    hive_host.names = [HiveHost.Name(hostname=msf_host.name)]
                # Set hive host records
                hive_host.records = [
                    HiveLibrary.Record(
                        name=self.msf_records.host,
                        tool_name=self.msf_records.tool_name,
                        record_type=RecordTypes.NESTED.value,
                        value=list(),
                    )
                ]
                # Set hive host tag
                if hive_host_tag is not None:
                    hive_host.tags.append(HiveLibrary.Tag(name=hive_host_tag))
                # Set hive host record value
                for host_key, record_name in self.msf_records.Host.__dict__.items():
                    if (
                        msf_host.__dict__.get(host_key) is not None
                        and msf_host.__dict__.get(host_key) != ""
                    ):
                        hive_host.records[0].value.append(
                            HiveLibrary.Record(
                                name=record_name,
                                tool_name=self.msf_records.tool_name,
                                record_type=RecordTypes.STRING.value,
                                value=str(msf_host.__dict__[host_key]),
                            )
                        )
                hive_hosts.append(hive_host)

            # Add MSF services in host for import
            for msf_service in msf_data.services:
                for host_index in range(len(hive_hosts)):

                    # Check MSF service host ip address is ipv4 address of host for import
                    if hive_hosts[host_index].ip == msf_service.host.address:

                        # Make hive port
                        hive_port: HiveHost.Port = HiveHost.Port(
                            port=msf_service.port,
                            service=HiveHost.Port.Service(),
                        )

                        # Add proto in port if msf_service.proto is not empty
                        if msf_service.proto is not None:
                            hive_port.protocol = msf_service.proto

                        # Add state in port if msf_service.state is not empty
                        if msf_service.state is not None:
                            hive_port.state = msf_service.state

                        # Add service name in port if msf_service.name is not empty
                        if msf_service.name is not None:
                            hive_port.service.name = msf_service.name

                        # Add service product in port if msf_service.info is not empty
                        if msf_service.info is not None:
                            hive_port.service.product = msf_service.info

                        # Add port tag
                        if hive_port_tag is not None:
                            hive_port.tags.append(HiveLibrary.Tag(name=hive_port_tag))

                        # Add port in ports list for host
                        hive_hosts[host_index].ports.append(hive_port)

            # Add MSF vulnerabilities in host for import
            for msf_vuln in msf_data.vulns:

                # Make Hive record for MSF vulnerability information
                record: HiveLibrary.Record = HiveLibrary.Record(
                    name=self.msf_records.vuln,
                    tool_name=self.msf_records.tool_name,
                    record_type=RecordTypes.NESTED.value,
                    value=list(),
                )

                # Make Vuln record value
                for key, record_name in self.msf_records.Vuln.__dict__.items():

                    # Add string records
                    if (
                        isinstance(msf_vuln.__dict__.get(key), str)
                        and msf_vuln.__dict__.get(key) != ""
                    ):
                        record.value.append(
                            HiveLibrary.Record(
                                name=record_name,
                                tool_name=self.msf_records.tool_name,
                                record_type=RecordTypes.STRING.value,
                                value=msf_vuln.__dict__.get(key),
                            )
                        )

                # Add vulnerability references in Vuln record value
                if isinstance(msf_vuln.refs, List) and len(msf_vuln.refs) > 0:
                    record.value.append(
                        HiveLibrary.Record(
                            name=self.msf_records.Vuln.refs,
                            tool_name=self.msf_records.tool_name,
                            record_type=RecordTypes.LIST.value,
                            value=msf_vuln.refs,
                        )
                    )

                # Set hive tag
                if hive_auto_tag:
                    hive_tag = f"Vulnerable: {msf_vuln.name}"
                else:
                    hive_tag = None

                # Add vulnerability record
                hive_hosts = self._hive_add_record(
                    record=record,
                    data=msf_vuln,
                    hive_hosts=hive_hosts,
                    msf_services=msf_data.services,
                    hive_tag=hive_tag,
                )

            # Add MSF loots in host for import
            for msf_loot in msf_data.loots:

                # Make Hive record for MSF loots
                record: HiveLibrary.Record = HiveLibrary.Record(
                    name=self.msf_records.loot,
                    tool_name=self.msf_records.tool_name,
                    record_type=RecordTypes.NESTED.value,
                    value=list(),
                )

                # Make Loot record
                for key, record_name in self.msf_records.Loot.__dict__.items():
                    if (
                        isinstance(msf_loot.__dict__.get(key), str)
                        and msf_loot.__dict__.get(key) != ""
                    ):
                        record_value: str = msf_loot.__dict__.get(key)
                        if key == "data" and msf_loot.content_type.startswith("text/"):
                            record_value: str = b64decode(
                                msf_loot.data.encode("utf-8")
                            ).decode("utf-8")
                        record.value.append(
                            HiveLibrary.Record(
                                name=record_name,
                                tool_name=self.msf_records.tool_name,
                                record_type=RecordTypes.STRING.value,
                                value=record_value,
                            )
                        )

                # Add loot record
                hive_hosts = self._hive_add_record(
                    record=record,
                    data=msf_loot,
                    hive_hosts=hive_hosts,
                    msf_services=msf_data.services,
                )

            # Add MSF notes in host for import
            for msf_note in msf_data.notes:

                # Make Hive record for MSF note
                record: HiveLibrary.Record = HiveLibrary.Record(
                    name=self.msf_records.note,
                    tool_name=self.msf_records.tool_name,
                    record_type=RecordTypes.NESTED.value,
                    value=list(),
                )

                # Make Loot record
                if not msf_note.ntype.startswith("nmap."):
                    for key, record_name in self.msf_records.Note.__dict__.items():
                        if (
                            isinstance(msf_note.__dict__.get(key), str)
                            and msf_note.__dict__.get(key) != ""
                        ):
                            record.value.append(
                                HiveLibrary.Record(
                                    name=record_name,
                                    tool_name=self.msf_records.tool_name,
                                    record_type=RecordTypes.STRING.value,
                                    value=msf_note.__dict__.get(key),
                                )
                            )

                # Add note record
                hive_hosts = self._hive_add_record(
                    record=record,
                    data=msf_note,
                    hive_hosts=hive_hosts,
                    msf_services=msf_data.services,
                )

            # Add credentials in host for import
            for msf_login in msf_data.logins:

                # Check login status is SUCCESS
                if msf_login.status != "Successful":
                    continue

                # Set none variables
                msf_service: Msf.Service = Msf.Service()
                msf_cred: Msf.Cred = Msf.Cred()

                # Get login service by service id
                if msf_login.service_id != -1:
                    for service in msf_data.services:
                        if service.id == msf_login.service_id:
                            msf_service = service

                # Get login credentials by credential id
                if msf_login.core_id != -1:
                    for cred in msf_data.creds:
                        if cred.id == msf_login.core_id:
                            msf_cred = cred

                # Add record if service and credential is not None
                if msf_service.id != -1 and msf_cred.id != -1:

                    # Set service id for this credential
                    msf_cred.service_id = msf_service.id

                    # Make Hive record for MSF credentials
                    record: HiveLibrary.Record = HiveLibrary.Record(
                        name=self.msf_records.cred,
                        tool_name=self.msf_records.tool_name,
                        record_type=RecordTypes.NESTED.value,
                        value=list(),
                    )

                    # Add username if username is not empty
                    if isinstance(msf_cred.public, Msf.Public):
                        if msf_cred.public.username is not None:
                            record.value.append(
                                HiveLibrary.Record(
                                    name=self.msf_records.Cred.username,
                                    tool_name=self.msf_records.tool_name,
                                    record_type=RecordTypes.STRING.value,
                                    value=msf_cred.public.username,
                                )
                            )

                    # Add credentials private type if private type is not empty
                    if isinstance(msf_cred.private, Msf.Private):
                        if (
                            msf_cred.private.data is not None
                            and msf_cred.private.type is not None
                        ):
                            credential_private_type = msf_cred.private.type
                            if (
                                credential_private_type
                                != "Metasploit::Credential::Password"
                            ):
                                record.value.append(
                                    HiveLibrary.Record(
                                        name=self.msf_records.Cred.private_type,
                                        tool_name=self.msf_records.tool_name,
                                        record_type=RecordTypes.STRING.value,
                                        value=msf_cred.private.type,
                                    )
                                )

                            # Add private data if private data is not empty
                            if (
                                credential_private_type
                                == "Metasploit::Credential::Password"
                            ):
                                self.msf_records.Cred.private_data = "Password"

                            record.value.append(
                                HiveLibrary.Record(
                                    name=self.msf_records.Cred.private_data,
                                    tool_name=self.msf_records.tool_name,
                                    record_type=RecordTypes.STRING.value,
                                    value=msf_cred.private.data,
                                )
                            )

                    # Add module if module is not empty
                    if isinstance(msf_cred.origin, Msf.Origin):
                        record.value.append(
                            HiveLibrary.Record(
                                name=self.msf_records.Cred.module_full_name,
                                tool_name=self.msf_records.tool_name,
                                record_type=RecordTypes.STRING.value,
                                value=msf_cred.origin.module_full_name,
                            )
                        )

                    # Set hive tag
                    if hive_auto_tag:
                        hive_tag = f"Credential: {msf_cred.public.username}"
                    else:
                        hive_tag = None

                    # Add credentials record
                    hive_hosts = self._hive_add_record(
                        record=record,
                        data=msf_cred,
                        hive_hosts=hive_hosts,
                        msf_services=msf_data.services,
                        hive_tag=hive_tag,
                    )

            # Create hive hosts
            for host_index in range(len(hive_hosts)):
                task_id: Optional[UUID] = self.hive_api.create_host(
                    project_id=hive_project_id, host=hive_hosts[host_index]
                )
                if isinstance(task_id, UUID):
                    for _ in range(10):
                        hive_hosts[
                            host_index
                        ].import_result = self.hive_api.task_is_completed(
                            project_id=hive_project_id, task_id=task_id
                        )
                        if hive_hosts[host_index].import_result:
                            break
                        else:
                            sleep(1)

            return hive_hosts

        except AssertionError as error:
            self._color.print_error("Assertion error:", f"{error}")
        return hive_hosts

    def export_from_hive_to_metasploit(
        self,
        hive_project_name: str,
        metasploit_workspace_name: str = "default",
    ) -> MsfData:
        """
        Export data from metasploit workspace to hive project
        Args:
            hive_project_name: Hive project name string, example: 'test_project'
            metasploit_workspace_name: Metasploit workspace name string, example: 'test_workspace'

        Returns: None if error or MsfData object, example:

        """
        msf_data: MsfData = MsfData(workspace=metasploit_workspace_name)
        try:
            # Get Hive project id by name
            hive_project_id: Optional[UUID] = self.hive_api.get_project_id_by_name(
                project_name=hive_project_name
            )

            # Not found Hive project
            assert (
                hive_project_id is not None
            ), f"Not found Hive project with name: {hive_project_name}"

            # Get MSF workspace or create it
            msf_workspaces: Optional[
                List[Msf.Workspace]
            ] = self.msf_api.get_workspaces()

            # Get list of MSF workspaces and check workspace with this name is exist or not
            msf_workspace_id: int = -1
            for msf_workspace in msf_workspaces:
                msf_data.workspaces.append(msf_workspace)
                if msf_workspace.name == metasploit_workspace_name:
                    msf_workspace_id = msf_workspace.id

            # Create MSF workspace if workspace with this name is not exist
            if msf_workspace_id == -1:
                msf_workspace: Msf.Workspace = Msf.Workspace(
                    name=metasploit_workspace_name
                )
                msf_workspace.id = self.msf_api.create_workspace(
                    workspace=msf_workspace
                )
                assert (
                    msf_workspace.id != 1
                ), f"Failed to create Metasploit workspace with name: {metasploit_workspace_name}"
                msf_workspace_id = msf_workspace.id
                msf_data.workspaces.append(msf_workspace)

            # Get Hive hosts
            hive_hosts: Optional[List[HiveLibrary.Host]] = self.hive_api.get_hosts(
                project_id=hive_project_id
            )

            # Failed to get hosts from Hive project
            assert (
                hive_hosts is not None
            ), f"Failed to get hosts from Hive project: {hive_project_name} ({hive_project_id})"

            # Parse Hive hosts
            for hive_host in hive_hosts:

                # Make MSF objects
                msf_host: Msf.Host = Msf.Host(workspace=msf_data.workspace)
                msf_loot: Msf.Loot = Msf.Loot(workspace=msf_data.workspace)
                msf_note: Msf.Note = Msf.Note(workspace=msf_data.workspace)
                msf_vuln: Msf.Vuln = Msf.Vuln(workspace=msf_data.workspace)
                msf_cred: Msf.Cred = Msf.Cred(workspace_id=msf_workspace_id)

                # Get host address
                if isinstance(hive_host.ip, IPv4Address):
                    msf_host.host = hive_host.ip
                    msf_host.address = hive_host.ip
                    msf_loot.host = hive_host.ip
                    msf_note.host = hive_host.ip
                    msf_vuln.host = hive_host.ip
                    msf_cred.address = hive_host.ip
                else:
                    continue

                # Get hostname
                if len(hive_host.names) > 0:
                    msf_host.name = hive_host.names[0].hostname

                # Parse host records
                host_node = self.hive_api.get_host(
                    project_id=hive_project_id, host_id=hive_host.id
                )
                if len(host_node.records) > 0:
                    for record in host_node.records:
                        if record.import_type == self.msf_records.tool_name:

                            # Parse MSF Host information record
                            if record.name == self.msf_records.host:
                                msf_host = self._parse_hive_record(
                                    record=record, result_object=msf_host
                                )

                            # Parse MSF Loot record
                            if record.name == self.msf_records.loot:
                                msf_loot = self._parse_hive_record(
                                    record=record, result_object=msf_loot
                                )
                                if msf_loot.name is not None:
                                    msf_data.loots.append(msf_loot)

                            # Parse MSF Credential record
                            if record.name == self.msf_records.cred:
                                msf_cred = self._parse_hive_record(
                                    record=record, result_object=msf_cred
                                )
                                if msf_cred.username is not None:
                                    msf_data.creds.append(msf_cred)

                            # Parse MSF Note record
                            if record.name == self.msf_records.note:
                                msf_note = self._parse_hive_record(
                                    record=record, result_object=msf_note
                                )
                                if msf_note.data is not None:
                                    msf_data.notes.append(msf_note)

                            # Parse MSF vulnerability record
                            if record.name == self.msf_records.vuln:
                                msf_vuln = self._parse_hive_record(
                                    record=record, result_object=msf_vuln
                                )
                                if msf_vuln.name is not None:
                                    msf_data.vulns.append(msf_vuln)

                # Add host to hosts for export list
                if msf_host.host is not None:
                    msf_data.hosts.append(msf_host)

                # Make MSF services list for this host
                if len(hive_host.ports) > 0:
                    for hive_port in hive_host.ports:

                        # Init MSF service object
                        msf_service: Msf.Service = Msf.Service(
                            workspace=msf_data.workspace,
                            host=hive_host.ip
                        )

                        # Add port
                        if isinstance(hive_port.port, int):
                            msf_service.port = hive_port.port
                            msf_cred.port = msf_service.port
                            msf_vuln.port = msf_service.port

                        # Add state
                        if isinstance(hive_port.state, str):
                            msf_service.state = hive_port.state

                        # Add proto
                        if isinstance(hive_port.protocol, str):
                            msf_service.proto = hive_port.protocol
                            msf_cred.protocol = msf_service.proto

                        # Add service name
                        if isinstance(hive_port.service.name, str):
                            msf_service.name = hive_port.service.name
                            msf_cred.service_name = msf_service.name

                        # Add service info
                        if isinstance(hive_port.service.product, str):
                            msf_service.info = hive_port.service.product

                        # Append current service in list for export
                        if msf_service.port is not None:
                            msf_data.services.append(msf_service)

                        # Get port records
                        port_node = self.hive_api.get_port(
                            project_id=hive_project_id, port_id=hive_port.id
                        )
                        for record in port_node.records:
                            if record.import_type == self.msf_records.tool_name:

                                # Parse MSF Credential record
                                if record.name == self.msf_records.cred:
                                    msf_cred = self._parse_hive_record(
                                        record=record, result_object=msf_cred
                                    )
                                    if msf_cred.username is not None:
                                        msf_data.creds.append(msf_cred)

                                # Parse MSF Vulnerability record
                                if record.name == self.msf_records.vuln:
                                    msf_vuln = self._parse_hive_record(
                                        record=record, result_object=msf_vuln
                                    )
                                    if msf_vuln.name is not None:
                                        msf_data.vulns.append(msf_vuln)

                # Analyze credentials

                # Add msf logins
                for msf_cred in msf_data.creds:
                    msf_login: Msf.Login = Msf.Login(workspace_id=msf_workspace_id)
                    msf_login.service_name = msf_cred.service_name
                    msf_login.port = msf_cred.port
                    msf_login.protocol = msf_cred.protocol
                    msf_login.address = msf_cred.address
                    msf_login.last_attempted_at = datetime.utcnow()
                    msf_login.public = msf_cred.username
                    msf_login.private = msf_cred.private_data
                    msf_data.logins.append(msf_login)

                # Credentials for export contains only uniq credentials
                uniq_creds = list(
                    {
                        cred.username or cred.private_data or cred.port: cred
                        for cred in msf_data.creds
                    }.values()
                )
                msf_data.creds = uniq_creds

                # Export hosts
                for host_index in range(len(msf_data.hosts)):
                    msf_data.hosts[host_index].id = self.msf_api.create_host(
                        msf_data.hosts[host_index]
                    )

                # Export services
                for service_index in range(len(msf_data.services)):
                    msf_data.services[service_index].id = self.msf_api.create_service(
                        msf_data.services[service_index]
                    )

                # Export vulnerabilities
                for vuln_index in range(len(msf_data.vulns)):
                    msf_data.vulns[vuln_index].id = self.msf_api.create_vuln(
                        msf_data.vulns[vuln_index]
                    )

                # Export loots
                for loot_index in range(len(msf_data.loots)):
                    msf_data.loots[loot_index].id = self.msf_api.create_loot(
                        msf_data.loots[loot_index]
                    )

                # Export notes
                for note_index in range(len(msf_data.notes)):
                    msf_data.notes[note_index].id = self.msf_api.create_note(
                        msf_data.notes[note_index]
                    )

                # Export credentials
                for cred_index in range(len(msf_data.creds)):
                    msf_data.creds[cred_index].id = self.msf_api.create_cred(
                        msf_data.creds[cred_index]
                    )
                    if msf_data.creds[cred_index].id is None:
                        continue

                    # Export logins
                    for login_index in range(len(msf_data.logins)):
                        msf_data.logins[login_index].core_id = msf_data.creds[
                            cred_index
                        ].id
                        if (
                            msf_data.logins[login_index].public
                            == msf_data.creds[cred_index].username
                            and msf_data.logins[login_index].private
                            == msf_data.creds[cred_index].private_data
                            and msf_data.logins[login_index].port
                            == msf_data.creds[cred_index].port
                        ):
                            msf_data.logins[login_index].id = self.msf_api.create_login(
                                msf_data.logins[login_index]
                            )

                return msf_data

        except AssertionError as error:
            self._color.print_error("Assertion error:", f"{error}")
        return msf_data
