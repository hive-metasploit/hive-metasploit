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

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a1"
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
        imported_hosts = hive_metasploit.import_from_hive_to_metasploit(
            hive_project_name=hive_variables.project.name,
            metasploit_workspace_name=msf_variables.workspace.name,
        )
        self.assertEqual(len(imported_hosts), 1)
        self.assertTrue(imported_hosts[0].import_result)

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
        for _ in range(10):
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

        # Delete MSF workspace and Hive project
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        hive_api.delete_project_by_name(project_name=hive_variables.project.name)
