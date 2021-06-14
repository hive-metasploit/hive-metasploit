# Description
"""
Hive Metasploit connector class
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from dataclasses import dataclass
from typing import Optional, List, Dict
from libmsf import Msf, MsfData
from libmsf.rest import MsfRestApi
from hive_library.rest import HiveRestApi
from datetime import datetime
from re import compile, search, finditer, MULTILINE
from urllib.parse import urlparse, ParseResult
from uuid import UUID
from hive_library import HiveLibrary
from hive_library.enum import RecordTypes
from hive_library.rest import HiveRestApi, AuthenticationError
from base64 import b64decode
from socket import gethostbyname, gethostbyaddr, herror
from ipaddress import IPv4Address, ip_address
from marshmallow import fields, pre_load, post_load, EXCLUDE
from marshmallow.exceptions import ValidationError
from marshmallow import Schema as MarshmallowSchema
from json import loads, JSONDecodeError
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

    def import_from_metasploit(
        self,
        hive_project_name: str,
        metasploit_workspace_name: str = "default",
        hive_host_tag: Optional[str] = None,
        hive_port_tag: Optional[str] = None,
        hive_auto_tag: bool = True,
    ) -> Optional[List[HiveHost]]:
        """
        Import data from metasploit workspace to hive project
        Args:
            hive_project_name: Hive project name string, example: 'test_project'
            metasploit_workspace_name: Metasploit workspace name string, example: 'test_workspace'
            hive_host_tag: Set Hive tag for host, example: 'host_tag'
            hive_port_tag: Set Hive tag for port, example: 'port_tag'
            hive_auto_tag: Automatically add tag for Hive hosts

        Returns: None if error or List of Hive hosts, example:
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
                if hive_project_id is None:
                    return None

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
            print(f"Assertion error: {error}")
        return hive_hosts
