# Description
"""
Unit tests for Hive Metasploit connector
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from unittest import TestCase
from typing import Optional, List
from uuid import UUID
from libmsf import Msf, MsfData
from hive_library import HiveLibrary
from libmsf.rest import MsfRestApi
from hive_library.rest import HiveRestApi
from hive_metasploit import HiveMetasploit, MetasploitRecords
from test_variables import MsfVariablesForTest, HiveVariablesForTest
from time import sleep
from subprocess import getoutput
from os import path

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a2"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"


# Variables
msf_variables: MsfVariablesForTest = MsfVariablesForTest()
hive_variables: HiveVariablesForTest = HiveVariablesForTest()
msf_records: MetasploitRecords = MetasploitRecords()
msf_api: MsfRestApi = MsfRestApi(
    api_key=msf_variables.api_key,
    api_url=msf_variables.api_url,
    proxy=msf_variables.proxy,
)
hive_api: HiveRestApi = HiveRestApi(
    username=hive_variables.username,
    password=hive_variables.password,
    server=hive_variables.server,
    proxy=hive_variables.proxy,
    debug=True,
)
hive_metasploit: HiveMetasploit = HiveMetasploit(
    msf_api_key=msf_variables.api_key,
    msf_api_url=msf_variables.api_url,
    hive_username=hive_variables.username,
    hive_password=hive_variables.password,
    hive_server=hive_variables.server,
    proxy=hive_variables.proxy,
)


# Class for tests
class HiveMetasploitTest(TestCase):

    # Import data from Metasploit to Hive
    def test01_import(self):
        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

        # Create MSF workspace
        msf_variables.workspace.id = msf_api.create_workspace(
            workspace=msf_variables.workspace
        )
        self.assertIsNotNone(msf_variables.workspace.id)
        self.assertIsInstance(msf_variables.workspace.id, int)
        self.assertLess(0, msf_variables.workspace.id)

        # Create MSF host
        msf_variables.host.id = msf_api.create_host(msf_variables.host)
        self.assertIsInstance(msf_variables.host.id, int)
        self.assertLess(0, msf_variables.host.id)

        # Create MSF service
        msf_variables.service.id = msf_api.create_service(msf_variables.service)
        self.assertIsInstance(msf_variables.service.id, int)
        self.assertLess(0, msf_variables.service.id)

        # Create MSF vulnerability
        msf_variables.vuln.id = msf_api.create_vuln(msf_variables.vuln)
        self.assertIsInstance(msf_variables.vuln.id, int)
        self.assertLess(0, msf_variables.vuln.id)

        # Create MSF loot
        msf_variables.loot.id = msf_api.create_loot(msf_variables.loot)
        self.assertIsInstance(msf_variables.loot.id, int)
        self.assertLess(0, msf_variables.loot.id)

        # Create MSF note
        msf_variables.note.id = msf_api.create_note(msf_variables.note)
        self.assertIsInstance(msf_variables.note.id, int)
        self.assertLess(0, msf_variables.note.id)

        # Create MSF credential
        msf_variables.cred.workspace_id = msf_variables.workspace.id
        msf_variables.cred.id = msf_api.create_cred(msf_variables.cred)
        self.assertIsInstance(msf_variables.cred.id, int)
        self.assertLess(0, msf_variables.cred.id)

        # Create MSF login
        msf_variables.login.workspace_id = msf_variables.workspace.id
        msf_variables.login.core_id = msf_variables.cred.id
        msf_variables.login.id = msf_api.create_login(msf_variables.login)
        self.assertIsInstance(msf_variables.login.id, int)
        self.assertLess(0, msf_variables.login.id)

        # Import data from Metasploit to Hive
        hive_objects = hive_metasploit.import_from_metasploit_to_hive(
            hive_project_name=hive_variables.project.name,
            metasploit_workspace_name=msf_variables.workspace.name,
        )
        self.assertEqual(len(hive_objects.hosts), 1)
        self.assertTrue(hive_objects.hosts[0].import_result)

        # Check Hive project is exist
        hive_projects: Optional[List[HiveLibrary.Host]] = hive_api.get_projects_list()
        self.assertIsInstance(hive_projects, List)
        for project in hive_projects:
            if project.name == hive_variables.project.name:
                hive_variables.project.id = project.id
        self.assertIsInstance(hive_variables.project.id, UUID)

        # Check Hive host is exist
        hive_hosts: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(
            project_id=hive_variables.project.id
        )
        self.assertEqual(len(hive_hosts), 1)
        hive_host = hive_hosts[0]
        self.assertIsInstance(hive_host.id, int)
        self.assertLess(0, hive_host.id)
        self.assertEqual(hive_host.ip, msf_variables.host.address)
        vuln_tag_exist: bool = False
        cred_tag_exist: bool = False
        for tag in hive_host.tags:
            if tag.name == f"Vulnerable: {msf_variables.vuln.name}":
                vuln_tag_exist = True
            if tag.name == f"Credential: {msf_variables.cred.username}":
                cred_tag_exist = True
        self.assertTrue(vuln_tag_exist)
        self.assertTrue(cred_tag_exist)
        self.assertEqual(len(hive_host.names), 1)
        self.assertEqual(hive_host.names[0].hostname, msf_variables.host.name)
        self.assertEqual(len(hive_host.ports), 1)

        # Check Hive port is exist
        hive_port = hive_host.ports[0]
        self.assertEqual(hive_port.port, msf_variables.service.port)
        self.assertEqual(hive_port.protocol, msf_variables.service.proto)
        self.assertEqual(hive_port.state, msf_variables.service.state)
        self.assertEqual(hive_port.service.name, msf_variables.service.name)
        self.assertEqual(hive_port.service.product, msf_variables.service.info)

        # Check Hive host records
        hive_host = hive_api.get_host(
            project_id=hive_variables.project.id, host_id=hive_host.id
        )
        host_record_exist: bool = False
        loot_record_exist: bool = False
        note_record_exist: bool = False
        for record in hive_host.records:
            if record.name == msf_records.host:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Host.__dict__[i]
                            for i in msf_records.Host.__dict__
                        ],
                    )
                host_record_exist = True
            if record.name == msf_records.loot:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Loot.__dict__[i]
                            for i in msf_records.Loot.__dict__
                        ],
                    )
                loot_record_exist = True
            if record.name == msf_records.note:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Note.__dict__[i]
                            for i in msf_records.Note.__dict__
                        ],
                    )
                note_record_exist = True
        self.assertTrue(host_record_exist)
        self.assertTrue(loot_record_exist)
        self.assertTrue(note_record_exist)

        # Check Hive port records
        hive_port = hive_api.get_port(
            project_id=hive_variables.project.id, port_id=hive_port.id
        )
        cred_record_exist: bool = False
        vuln_record_exist: bool = False
        for record in hive_port.records:
            if record.name == msf_records.cred:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Cred.__dict__[i]
                            for i in msf_records.Cred.__dict__
                        ],
                    )
                cred_record_exist = True
            if record.name == msf_records.vuln:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Vuln.__dict__[i]
                            for i in msf_records.Vuln.__dict__
                        ],
                    )
                vuln_record_exist = True
        self.assertTrue(cred_record_exist)
        self.assertTrue(vuln_record_exist)

        # Check hive credentials
        self.assertIsInstance(hive_objects.credentials, List)
        self.assertEqual(len(hive_objects.credentials), 1)
        hive_credential = hive_objects.credentials[0]
        self.assertEqual(hive_credential.assets[0].asset, hive_host.ip)
        self.assertEqual(hive_credential.type, hive_variables.credential.type)
        self.assertEqual(hive_credential.login, hive_variables.credential.login)
        self.assertEqual(hive_credential.value, hive_variables.credential.value)
        self.assertEqual(
            hive_credential.tags[0].name, hive_variables.credential.tags[0].name
        )

        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

    # Export data from Hive to Metasploit
    def test02_export(self):
        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

        # Create Hive project
        hive_variables.project = hive_api.create_project(project=hive_variables.project)
        self.assertIsInstance(hive_variables.project.id, UUID)

        # Create Hive host
        task_id: Optional[UUID] = hive_api.create_host(
            project_id=hive_variables.project.id, host=hive_variables.host
        )
        self.assertIsInstance(task_id, UUID)
        import_task_is_completed: bool = False
        for _ in range(30):
            if hive_api.task_is_completed(
                project_id=hive_variables.project.id, task_id=task_id
            ):
                import_task_is_completed = True
                break
            else:
                sleep(1)
        self.assertTrue(import_task_is_completed)

        # Export data from Hive to Metasploit
        msf_data: MsfData = hive_metasploit.export_from_hive_to_metasploit(
            hive_project_name=hive_variables.project.name,
            metasploit_workspace_name=msf_variables.workspace.name,
        )
        self.assertEqual(msf_data.workspace, msf_variables.workspace.name)
        self.assertLess(0, len(msf_data.workspaces))
        self.assertLess(0, len(msf_data.hosts))
        self.assertLess(0, len(msf_data.services))
        self.assertLess(0, len(msf_data.vulns))
        self.assertLess(0, len(msf_data.loots))
        self.assertLess(0, len(msf_data.notes))
        self.assertLess(0, len(msf_data.creds))
        self.assertLess(0, len(msf_data.logins))

        # Check workspace
        workspace: Msf.Workspace = msf_data.workspaces[-1]
        self.assertNotEqual(workspace.id, -1)
        self.assertIsNotNone(workspace.id)
        msf_variables.workspace.id = workspace.id
        self.assertEqual(workspace.name, msf_variables.workspace.name)

        # Check host
        host: Msf.Host = msf_data.hosts[0]
        self.assertNotEqual(host.id, -1)
        self.assertIsNotNone(host.id)
        msf_variables.host = msf_api.get_hosts(msf_variables.workspace.name)[0]
        self.assertEqual(host.id, msf_variables.host.id)
        self.assertEqual(host.workspace, msf_variables.workspace.name)
        self.assertEqual(host.address, str(msf_variables.host.address))
        self.assertEqual(host.mac, msf_variables.host.mac)
        self.assertEqual(host.name, msf_variables.host.name)
        self.assertEqual(host.state, msf_variables.host.state)
        self.assertEqual(host.os_name, msf_variables.host.os_name)
        self.assertEqual(host.os_flavor, msf_variables.host.os_flavor)
        self.assertEqual(host.os_sp, msf_variables.host.os_sp)
        self.assertEqual(host.os_lang, msf_variables.host.os_lang)
        self.assertEqual(host.arch, msf_variables.host.arch)
        self.assertEqual(host.purpose, msf_variables.host.purpose)
        self.assertEqual(host.info, msf_variables.host.info)
        self.assertEqual(host.comments, msf_variables.host.comments)
        self.assertEqual(host.scope, msf_variables.host.scope)
        self.assertEqual(host.virtual_host, msf_variables.host.virtual_host)

        # Check service
        service: Msf.Service = msf_data.services[0]
        self.assertNotEqual(service.id, -1)
        self.assertIsNotNone(service.id)
        msf_variables.service = msf_api.get_services(msf_variables.workspace.name)[0]
        self.assertEqual(service.id, msf_variables.service.id)
        self.assertEqual(service.workspace, msf_variables.workspace.name)
        self.assertEqual(service.host, str(msf_variables.host.address))
        self.assertEqual(service.port, msf_variables.service.port)
        self.assertEqual(service.proto, msf_variables.service.proto)
        self.assertEqual(service.state, msf_variables.service.state)
        self.assertEqual(service.name, msf_variables.service.name)
        self.assertEqual(service.info, msf_variables.service.info)

        # Check vulnerability
        vuln: Msf.Vuln = msf_data.vulns[0]
        self.assertNotEqual(vuln.id, -1)
        self.assertIsNotNone(vuln.id)
        msf_variables.vuln = msf_api.get_vulns(msf_variables.workspace.name)[0]
        self.assertEqual(vuln.id, msf_variables.vuln.id)
        self.assertEqual(vuln.workspace, msf_variables.workspace.name)
        self.assertEqual(vuln.host, str(msf_variables.host.address))
        self.assertEqual(vuln.port, msf_variables.service.port)
        self.assertEqual(vuln.name, msf_variables.vuln.name)
        self.assertEqual(vuln.info, msf_variables.vuln.info)
        self.assertIn(vuln.refs[0], msf_variables.vuln.refs)
        self.assertIn(vuln.refs[1], msf_variables.vuln.refs)

        # Check loot
        loot: Msf.Loot = msf_data.loots[0]
        self.assertNotEqual(loot.id, -1)
        self.assertIsNotNone(loot.id)
        msf_variables.loot = msf_api.get_loots(msf_variables.workspace.name)[0]
        self.assertEqual(loot.id, msf_variables.loot.id)
        self.assertEqual(loot.workspace, msf_variables.workspace.name)
        self.assertEqual(loot.host, str(msf_variables.host.address))
        self.assertEqual(loot.data, msf_variables.loot.data)
        self.assertEqual(loot.content_type, msf_variables.loot.content_type)
        self.assertEqual(loot.name, msf_variables.loot.name)
        self.assertEqual(loot.info, msf_variables.loot.info)
        self.assertEqual(loot.ltype, msf_variables.loot.ltype)

        # Check note
        note: Msf.Note = msf_data.notes[0]
        self.assertNotEqual(note.id, -1)
        self.assertIsNotNone(note.id)
        msf_variables.note = msf_api.get_notes(msf_variables.workspace.name)[0]
        self.assertEqual(note.id, msf_variables.note.id)
        self.assertEqual(note.workspace, msf_variables.workspace.name)
        self.assertEqual(note.host, str(msf_variables.host.address))
        self.assertEqual(note.ntype, msf_variables.note.ntype)
        self.assertEqual(note.data, msf_variables.note.data)

        # Check credential
        cred: Msf.Cred = msf_data.creds[0]
        self.assertNotEqual(cred.id, -1)
        self.assertIsNotNone(cred.id)
        msf_variables.cred = msf_api.get_creds(msf_variables.workspace.name)[0]
        self.assertEqual(cred.id, msf_variables.cred.id)
        self.assertEqual(cred.workspace_id, msf_variables.workspace.id)
        self.assertEqual(cred.address, str(msf_variables.host.address))
        self.assertEqual(cred.port, msf_variables.service.port)
        self.assertEqual(cred.protocol, msf_variables.service.proto)
        self.assertEqual(cred.service_name, msf_variables.service.name)
        self.assertEqual(cred.username, msf_variables.cred.public.username)
        self.assertEqual(cred.private_data, msf_variables.cred.private.data)
        self.assertIn(cred.private_type.capitalize(), msf_variables.cred.private.type)
        self.assertIn(cred.origin_type.capitalize(), msf_variables.cred.origin.type)
        self.assertEqual(
            cred.module_fullname, msf_variables.cred.origin.module_full_name
        )

        # Check login
        login: Msf.Login = msf_data.logins[-1]
        self.assertNotEqual(login.id, -1)
        self.assertIsNotNone(login.id)
        logins: Optional[List[Msf.Login]] = msf_api.get_logins()
        for login in logins:
            if login.service_id == msf_variables.service.id:
                msf_variables.login = login
                break
        self.assertEqual(login.id, msf_variables.login.id)
        self.assertEqual(login.core_id, msf_variables.cred.id)
        self.assertEqual(login.status, "Successful")
        msf_api.delete_logins(ids=[login.id])

        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

    # Cli import data from Metasploit to Hive
    def test03_cli_import(self):
        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

        # Create MSF workspace
        msf_variables.workspace.id = msf_api.create_workspace(
            workspace=msf_variables.workspace
        )
        self.assertIsNotNone(msf_variables.workspace.id)
        self.assertIsInstance(msf_variables.workspace.id, int)
        self.assertLess(0, msf_variables.workspace.id)

        # Create MSF host
        msf_variables.host.workspace = msf_variables.workspace.name
        msf_variables.host.id = msf_api.create_host(msf_variables.host)
        self.assertIsInstance(msf_variables.host.id, int)
        self.assertLess(0, msf_variables.host.id)

        # Create MSF service
        msf_variables.service.host = msf_variables.host.address
        msf_variables.service.workspace = msf_variables.workspace.name
        msf_variables.service.id = msf_api.create_service(msf_variables.service)
        self.assertIsInstance(msf_variables.service.id, int)
        self.assertLess(0, msf_variables.service.id)

        # Create MSF vulnerability
        msf_variables.vuln.host = msf_variables.host.address
        msf_variables.vuln.port = msf_variables.service.port
        msf_variables.vuln.workspace = msf_variables.workspace.name
        msf_variables.vuln.id = msf_api.create_vuln(msf_variables.vuln)
        self.assertIsInstance(msf_variables.vuln.id, int)
        self.assertLess(0, msf_variables.vuln.id)

        # Create MSF loot
        msf_variables.loot.host = msf_variables.host.address
        msf_variables.loot.workspace = msf_variables.workspace.name
        msf_variables.loot.id = msf_api.create_loot(msf_variables.loot)
        self.assertIsInstance(msf_variables.loot.id, int)
        self.assertLess(0, msf_variables.loot.id)

        # Create MSF note
        msf_variables.note.host = msf_variables.host.address
        msf_variables.note.workspace = msf_variables.workspace.name
        msf_variables.note.id = msf_api.create_note(msf_variables.note)
        self.assertIsInstance(msf_variables.note.id, int)
        self.assertLess(0, msf_variables.note.id)

        # Create MSF credential
        msf_variables.cred.address = msf_variables.host.address
        msf_variables.cred.port = msf_variables.service.port
        if isinstance(msf_variables.cred.origin, Msf.Origin):
            msf_variables.cred.module_fullname = msf_variables.cred.origin.module_full_name
        else:
            msf_variables.cred.module_fullname = msf_variables.cred.module_fullname
        if isinstance(msf_variables.cred.origin, Msf.Origin):
            msf_variables.cred.username = msf_variables.cred.public.username
        else:
            msf_variables.cred.username = msf_variables.cred.username
        if isinstance(msf_variables.cred.origin, Msf.Origin):
            msf_variables.cred.private_data = msf_variables.cred.private.data
        else:
            msf_variables.cred.private_data = msf_variables.cred.private_data
        msf_variables.cred.private_type = "password"
        msf_variables.cred.service_name = msf_variables.service.name
        msf_variables.cred.protocol = msf_variables.service.proto
        msf_variables.cred.origin_type = "service"
        msf_variables.cred.workspace_id = msf_variables.workspace.id
        msf_variables.cred.id = msf_api.create_cred(msf_variables.cred)
        self.assertIsInstance(msf_variables.cred.id, int)
        self.assertLess(0, msf_variables.cred.id)

        # Create MSF login
        msf_variables.login.address = msf_variables.host.address
        msf_variables.login.port = msf_variables.service.port
        msf_variables.login.service_name = msf_variables.service.name
        msf_variables.login.protocol = msf_variables.service.proto
        msf_variables.login.workspace_id = msf_variables.workspace.id
        msf_variables.login.core_id = msf_variables.cred.id
        msf_variables.login.id = msf_api.create_login(msf_variables.login)
        self.assertIsInstance(msf_variables.login.id, int)
        self.assertLess(0, msf_variables.login.id)

        # Cli import data from Metasploit to Hive
        dir: str = path.dirname(path.dirname(path.realpath(__file__)))
        python: str = "~/.pyenv/versions/3.6.13/bin/python3.6"
        cli: str = f"{python} {path.join(dir, 'hive_metasploit_cli.py')} "
        cli += f"-hn {hive_variables.project.name} "
        cli += f"-mw {msf_variables.workspace.name} "
        cli += f"--proxy {msf_variables.proxy} "
        cli += "-I"
        out: str = getoutput(cli)
        print(out)
        self.assertIn(hive_variables.project.name, out)
        self.assertIn(msf_variables.workspace.name, out)
        self.assertIn(str(msf_variables.host.address), out)
        self.assertIn(str(msf_variables.cred.username), out)
        self.assertIn(str(msf_variables.cred.private_data), out)
        self.assertIn(str(msf_variables.cred.private_type), out)

        # Check Hive project is exist
        hive_projects: Optional[List[HiveLibrary.Host]] = hive_api.get_projects_list()
        self.assertIsInstance(hive_projects, List)
        for project in hive_projects:
            if project.name == hive_variables.project.name:
                hive_variables.project.id = project.id
        self.assertIsInstance(hive_variables.project.id, UUID)

        # Check Hive host is exist
        hive_hosts: Optional[List[HiveLibrary.Host]] = hive_api.get_hosts(
            project_id=hive_variables.project.id
        )
        self.assertEqual(len(hive_hosts), 1)
        hive_host = hive_hosts[0]
        self.assertIsInstance(hive_host.id, int)
        self.assertLess(0, hive_host.id)
        self.assertEqual(hive_host.ip, msf_variables.host.address)
        vuln_tag_exist: bool = False
        cred_tag_exist: bool = False
        for tag in hive_host.tags:
            if tag.name == f"Vulnerable: {msf_variables.vuln.name}":
                vuln_tag_exist = True
            if tag.name == f"Credential: {msf_variables.cred.username}":
                cred_tag_exist = True
        self.assertTrue(vuln_tag_exist)
        self.assertTrue(cred_tag_exist)
        self.assertEqual(len(hive_host.names), 1)
        self.assertEqual(hive_host.names[0].hostname, msf_variables.host.name)
        self.assertEqual(len(hive_host.ports), 1)

        # Check Hive port is exist
        hive_port = hive_host.ports[0]
        self.assertEqual(hive_port.port, msf_variables.service.port)
        self.assertEqual(hive_port.protocol, msf_variables.service.proto)
        self.assertEqual(hive_port.state, msf_variables.service.state)
        self.assertEqual(hive_port.service.name, msf_variables.service.name)
        self.assertEqual(hive_port.service.product, msf_variables.service.info)

        # Check Hive host records
        hive_host = hive_api.get_host(
            project_id=hive_variables.project.id, host_id=hive_host.id
        )
        host_record_exist: bool = False
        loot_record_exist: bool = False
        note_record_exist: bool = False
        for record in hive_host.records:
            if record.name == msf_records.host:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Host.__dict__[i]
                            for i in msf_records.Host.__dict__
                        ],
                    )
                host_record_exist = True
            if record.name == msf_records.loot:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Loot.__dict__[i]
                            for i in msf_records.Loot.__dict__
                        ],
                    )
                loot_record_exist = True
            if record.name == msf_records.note:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Note.__dict__[i]
                            for i in msf_records.Note.__dict__
                        ],
                    )
                note_record_exist = True
        self.assertTrue(host_record_exist)
        self.assertTrue(loot_record_exist)
        self.assertTrue(note_record_exist)

        # Check Hive port records
        hive_port = hive_api.get_port(
            project_id=hive_variables.project.id, port_id=hive_port.id
        )
        cred_record_exist: bool = False
        vuln_record_exist: bool = False
        for record in hive_port.records:
            if record.name == msf_records.cred:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        ["Username", "Module", "Password", "Credentials private type"],
                    )
                cred_record_exist = True
            if record.name == msf_records.vuln:
                for value in record.value:
                    self.assertIn(
                        value.name,
                        [
                            msf_records.Vuln.__dict__[i]
                            for i in msf_records.Vuln.__dict__
                        ],
                    )
                vuln_record_exist = True
        self.assertTrue(cred_record_exist)
        self.assertTrue(vuln_record_exist)

        # Check hive credentials
        hive_credentials: Optional[List[HiveLibrary.Credential]] = hive_api.get_credentials(
            project_id=hive_variables.project.id
        )
        self.assertIsInstance(hive_credentials, List)
        self.assertEqual(len(hive_credentials), 1)
        hive_credential = hive_credentials[0]
        self.assertEqual(hive_credential.assets[0].asset, hive_host.ip)
        self.assertEqual(hive_credential.type, hive_variables.credential.type)
        self.assertEqual(hive_credential.login, hive_variables.credential.login)
        self.assertEqual(hive_credential.value, hive_variables.credential.value)
        self.assertEqual(
            hive_credential.tags[0].name, hive_variables.credential.tags[0].name
        )

        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

    # Cli export data from Hive to Metasploit
    def test04_cli_export(self):
        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)

        # Create Hive project
        hive_variables.project = hive_api.create_project(project=hive_variables.project)
        self.assertIsInstance(hive_variables.project.id, UUID)

        # Create Hive host
        task_id: Optional[UUID] = hive_api.create_host(
            project_id=hive_variables.project.id, host=hive_variables.host
        )
        self.assertIsInstance(task_id, UUID)
        import_task_is_completed: bool = False
        for _ in range(30):
            if hive_api.task_is_completed(
                project_id=hive_variables.project.id, task_id=task_id
            ):
                import_task_is_completed = True
                break
            else:
                sleep(1)
        self.assertTrue(import_task_is_completed)

        # Cli import data from Metasploit to Hive
        dir: str = path.dirname(path.dirname(path.realpath(__file__)))
        python: str = "~/.pyenv/versions/3.6.13/bin/python3.6"
        cli: str = f"{python} {path.join(dir, 'hive_metasploit_cli.py')} "
        cli += f"-hn {hive_variables.project.name} "
        cli += f"-mw {msf_variables.workspace.name} "
        cli += f"--proxy {msf_variables.proxy} "
        cli += "-E"
        out: str = getoutput(cli)
        print(out)
        self.assertIn(hive_variables.project.name, out)
        self.assertIn(msf_variables.workspace.name, out)
        self.assertIn(str(msf_variables.host.address), out)
        self.assertIn(str(msf_variables.service.port), out)
        self.assertIn(str(msf_variables.service.proto), out)
        self.assertIn(str(msf_variables.vuln.name), out)
        self.assertIn(str(msf_variables.vuln.refs[0]), out)
        self.assertIn(str(path.dirname(msf_variables.loot.path)), out)
        self.assertIn(str(msf_variables.loot.ltype), out)
        self.assertIn(str(msf_variables.note.data), out)
        self.assertIn(str(msf_variables.cred.username), out)
        self.assertIn(str(msf_variables.cred.private_data), out)
        msf_data: MsfData = msf_api.get_all_data(workspace=msf_variables.workspace.name)

        # Check workspace
        workspace = Msf.Workspace()
        for created_workspace in msf_data.workspaces:
            if created_workspace.name == msf_data.workspace:
                workspace = created_workspace
                break
        self.assertNotEqual(workspace.id, -1)
        self.assertIsNotNone(workspace.id)
        msf_variables.workspace.id = workspace.id
        self.assertEqual(workspace.name, msf_variables.workspace.name)

        # Check host
        host: Msf.Host = msf_data.hosts[0]
        self.assertNotEqual(host.id, -1)
        self.assertIsNotNone(host.id)
        msf_variables.host = msf_api.get_hosts(msf_variables.workspace.name)[0]
        self.assertEqual(host.id, msf_variables.host.id)
        self.assertEqual(host.workspace_id, msf_variables.workspace.id)
        self.assertEqual(host.address, msf_variables.host.address)
        self.assertEqual(host.mac, msf_variables.host.mac)
        self.assertEqual(host.name, msf_variables.host.name)
        self.assertEqual(host.state, msf_variables.host.state)
        self.assertEqual(host.os_name, msf_variables.host.os_name)
        self.assertEqual(host.os_flavor, msf_variables.host.os_flavor)
        self.assertEqual(host.os_sp, msf_variables.host.os_sp)
        self.assertEqual(host.os_lang, msf_variables.host.os_lang)
        self.assertEqual(host.arch, msf_variables.host.arch)
        self.assertEqual(host.purpose, msf_variables.host.purpose)
        self.assertEqual(host.info, msf_variables.host.info)
        self.assertEqual(host.comments, msf_variables.host.comments)
        self.assertEqual(host.scope, msf_variables.host.scope)
        self.assertEqual(host.virtual_host, msf_variables.host.virtual_host)

        # Check service
        service: Msf.Service = msf_data.services[0]
        self.assertNotEqual(service.id, -1)
        self.assertIsNotNone(service.id)
        msf_variables.service = msf_api.get_services(msf_variables.workspace.name)[0]
        self.assertEqual(service.id, msf_variables.service.id)
        self.assertEqual(service.host.address, msf_variables.host.address)
        self.assertEqual(service.port, msf_variables.service.port)
        self.assertEqual(service.proto, msf_variables.service.proto)
        self.assertEqual(service.state, msf_variables.service.state)
        self.assertEqual(service.name, msf_variables.service.name)
        self.assertEqual(service.info, msf_variables.service.info)

        # Check vulnerability
        vuln: Msf.Vuln = msf_data.vulns[0]
        self.assertNotEqual(vuln.id, -1)
        self.assertIsNotNone(vuln.id)
        msf_variables.vuln = msf_api.get_vulns(msf_variables.workspace.name)[0]
        self.assertEqual(vuln.id, msf_variables.vuln.id)
        self.assertEqual(vuln.host.address, msf_variables.host.address)
        self.assertEqual(vuln.service_id, msf_variables.service.id)
        self.assertEqual(vuln.name, msf_variables.vuln.name)
        self.assertEqual(vuln.info, msf_variables.vuln.info)
        self.assertIn(vuln.refs[0], msf_variables.vuln.refs)
        self.assertIn(vuln.refs[1], msf_variables.vuln.refs)

        # Check loot
        loot: Msf.Loot = msf_data.loots[0]
        self.assertNotEqual(loot.id, -1)
        self.assertIsNotNone(loot.id)
        msf_variables.loot = msf_api.get_loots(msf_variables.workspace.name)[0]
        self.assertEqual(loot.id, msf_variables.loot.id)
        self.assertEqual(loot.host.address, msf_variables.host.address)
        self.assertEqual(loot.data, msf_variables.loot.data)
        self.assertEqual(loot.content_type, msf_variables.loot.content_type)
        self.assertEqual(loot.name, msf_variables.loot.name)
        self.assertEqual(loot.info, msf_variables.loot.info)
        self.assertEqual(loot.ltype, msf_variables.loot.ltype)

        # Check note
        note: Msf.Note = msf_data.notes[0]
        self.assertNotEqual(note.id, -1)
        self.assertIsNotNone(note.id)
        msf_variables.note = msf_api.get_notes(msf_variables.workspace.name)[0]
        self.assertEqual(note.id, msf_variables.note.id)
        self.assertEqual(note.host.address, msf_variables.host.address)
        self.assertEqual(note.ntype, msf_variables.note.ntype)
        self.assertEqual(note.data, msf_variables.note.data)

        # Check credential
        cred: Msf.Cred = msf_data.creds[0]
        self.assertNotEqual(cred.id, -1)
        self.assertIsNotNone(cred.id)
        msf_variables.cred = msf_api.get_creds(msf_variables.workspace.name)[0]
        self.assertEqual(cred.id, msf_variables.cred.id)
        self.assertEqual(cred.workspace_id, msf_variables.workspace.id)
        self.assertEqual(cred.origin.service_id, msf_variables.service.id)
        self.assertEqual(cred.public.username, msf_variables.cred.public.username)
        self.assertEqual(cred.private.data, msf_variables.cred.private.data)
        self.assertIn(cred.private.type, msf_variables.cred.private.type)
        self.assertEqual(
            cred.origin.module_full_name, msf_variables.cred.origin.module_full_name
        )

        # Check login
        login: Msf.Login = msf_data.logins[-1]
        self.assertNotEqual(login.id, -1)
        self.assertIsNotNone(login.id)
        logins: Optional[List[Msf.Login]] = msf_api.get_logins()
        for login in logins:
            if login.service_id == msf_variables.service.id:
                msf_variables.login = login
                break
        self.assertEqual(login.id, msf_variables.login.id)
        self.assertEqual(login.core_id, msf_variables.cred.id)
        self.assertEqual(login.status, "Successful")
        msf_api.delete_logins(ids=[login.id])

        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)
