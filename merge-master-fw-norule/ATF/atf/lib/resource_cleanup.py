# One Convergence, Inc. CONFIDENTIAL
# Copyright (c) 2012-2014, One Convergence, Inc., USA
# All Rights Reserved.
#
# All information contained herein is, and remains the property of
# One Convergence, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to One Convergence,
# Inc. and its suppliers.
#
# Dissemination of this information or reproduction of this material is
# strictly forbidden unless prior written permission is obtained from
# One Convergence, Inc., USA


"""
    This module contains functions to cleaning resources
    created by test case. It will be used for resource cleanup
    once tested cases is completed.
"""
# added comment to generate diff file
import atf.config.common_config as common_config
from atf.lib.neutron_cleanup import NeutronCleanup
from atf.lib.gbp_cleanup import GbpResourceCleanup
from atf.lib.lib_common import commonLibrary
import atf.lib.nvp_atf_logging as log
from atf.lib.lib_heat import HeatLibrary

# sys.path.append("../../")

# pylint: disable=W0142

# pylint: disable=W0702

LOG_OBJ = log.get_atf_logger()


class ResourceCleanup(object):
    """Class contains methods for cleaning resources created by
        test cases.
    """
    def __init__(self, lib_obj):
        """Constructor

        Arguments:-
            lib_obj: OpenstackLibrary class object.
        """
        self.os_pub_ip = lib_obj.host_ip
        self.gbp_cleanup_driver = GbpResourceCleanup(self.os_pub_ip)
        self.neutron_cleanup = NeutronCleanup(lib_obj)
        self.lib_obj = lib_obj
        self.common_obj = commonLibrary()
        self.error_msg = ""

    def isprojectexist(self, user_name, project_name):
        """Return True if project exist. Otherwise Returns False."""
        try:
            project_exist = False
            user_exist = False
            # get project & user list.
            if common_config.keystone_api_version == 'v3':
                project_list = self.lib_obj.list_keystone_v3_projects()
                if type(project_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list project."
                    LOG_OBJ.error(err_msg)
                    return err_msg
                user_list = self.lib_obj.list_keystone_v3_users()
                if type(user_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list users."
                    LOG_OBJ.error(err_msg)
                    return err_msg
            else:
                project_list = self.lib_obj.list_tenants()
                if type(project_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list project."
                    LOG_OBJ.error(err_msg)
                    return err_msg
                user_list = self.lib_obj.list_users()
                if type(user_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list users."
                    LOG_OBJ.error(err_msg)
                    return err_msg

            for project in project_list:
                if project["name"] == project_name:
                    project_exist = True
                    break
            for user in user_list:
                if user["name"] == user_name:
                    user_exist = True

            if project_exist and user_exist:
                return True
            return False
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while checking project's existence."

    def __pre_cleanup(self, project_name, token, project_id):
        try:
            old_context = self.lib_obj.set_tenant_info(
                            project_name, token, token, project_id)
            if not old_context:
                LOG_OBJ.error("Failed to switch context.")
                return

            routers = self.lib_obj.list_router()
            if routers is None:
                LOG_OBJ.error("Failed to list routers.")
                return

            floatingips = self.lib_obj.list_floating_ip()
            if floatingips is None:
                LOG_OBJ.error("Failed to list floating ips.")
                return

            for fip in floatingips:
                if fip["tenant_id"] == project_id:
                    self.lib_obj.disassociate_floating_ip(fip["id"])

            for router in routers:
                ports = self.lib_obj.list_router_ports(router["id"])
                if ports is None:
                    LOG_OBJ.error("Failed to list router ports.")
                    return
                for port in ports:
                    if port["name"] == common_config.port_name and\
                            port["tenant_id"] == project_id:
                        self.lib_obj.remove_router_interface(
                            router["id"], port_id=port["id"])
                        # self.lib_obj.delete_port(port["id"])
                        return True
            else:
                return True
            return
        except Exception as err:
            LOG_OBJ.exception(err)
            return
        finally:
            if old_context:
                self.lib_obj.set_tenant_info(*old_context)

    def get_tenant_info(self, tenant_info):
        """Helper function.

        Arguments:
            tenant_info: dictionary of tenant details.
                e.g.
                    {
                        "project_name": "test-project",
                        "user_name": "test-user",
                        "password": "test-passwd",
                        "domain_name": "default",
                        "sharable": True/False
                    }
        Returns:
            1. On success returns tenant tuple. (token, tenant_id)
            2. On Failure return string containing err msg. (str)
        """
        try:
            project_name = tenant_info.get("project_name")
            user_name = tenant_info.get("user_name")
            password = tenant_info.get("password")
            domain_name = tenant_info.get("domain_name")

            if common_config.keystone_api_version == 'v3':
                scope = "project"
                # get keystone v3 token.
                token = self.lib_obj.\
                    get_keystone_v3_token(project_name, domain_name,
                                          user_name, password, scope)

                # get project id.
                project_id = self.lib_obj.get_keystone_v3_project_id(
                                                            project_name)
                if type(project_id) is not unicode:
                    err_msg = "Resource Cleanup: Failed to access project id"\
                        " for project: %s" % project_name
                    LOG_OBJ.error(err_msg)
                    return err_msg
            else:
                # get keystone v2 token
                token = self.lib_obj.get_token(project_name, user_name,
                                               password)
                # get project id.
                project_id = self.lib_obj.get_tenant_id(project_name)
                if type(project_id) is not unicode:
                    err_msg = "Resource Cleanup: Failed to access project id"\
                        " for project: %s" % project_name
                    LOG_OBJ.error(err_msg)
                    return err_msg

            LOG_OBJ.debug("Token: %s, project id"
                          ": %s" % (token, project_id))

            return (token, project_id)
        except Exception as err:
            err_msg = "Exception occurred while accessing project "\
                "tokens for cleanup."
            LOG_OBJ.exception(err)
            return err_msg

    def delete_local_project_resources(self, local_project_list):
        """Delete all resources (gbp, neutron, nova, keystone)
        in all local projects.

        Argu:
            local_project_list: list of local project details.
            [
                {
                    'project_name': "",
                    "user_name": "",
                    "password": "",
                    "domain_name": "",
                    "sharable": True/False  # True if test using shared
                                            # node & spec.
                }, {}, {}, ...
            ]
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            err_msg = ""
            admin_project_token = self.lib_obj.cloud_admin_info[
                                                "token_project"]
            # start cleaning gbp resources in local tenant.
            for project_info in local_project_list:
                project_name = project_info.get("project_name")
                user_name = project_info.get("user_name")
                if not project_name or not user_name:
                    err_msg += "Incorrect project details. "
                    LOG_OBJ.error(err_msg)
                    continue

                # check if project exist.
                if not self.isprojectexist(user_name, project_name):
                    err_msg = "ResourceCleanup: Looks like project with "\
                        "name %s or user with name %s is not created."\
                        % (project_name, user_name)
                    LOG_OBJ.error(err_msg)
                    continue

                # get token for local tenant info.
                tenant_info = self.get_tenant_info(project_info)
                if type(tenant_info) is not tuple:
                    err_msg += tenant_info
                    continue

                local_project_info = {"name": project_info["project_name"],
                                      "tid": tenant_info[1],
                                      "token": tenant_info[0],
                                      "cloud_admin_token": admin_project_token
                                      }

                if not self.__pre_cleanup(project_info["project_name"],
                                          tenant_info[0], tenant_info[1]):
                    LOG_OBJ.error("failed to perform pre cleanup activities.")
                    err_msg += "failed to perform pre cleanup activities."

                msg = "Cleaning gbp resources of local project:"\
                    " %s" % local_project_info["name"]
                msg = self.common_obj.get_decorated_message(msg, "&", 80)
                print msg
                LOG_OBJ.debug("%s" % msg)

                return_status = self.gbp_cleanup_driver.\
                    delete_all_gbp_resources(local_project_info)
                if return_status is not True:
                    LOG_OBJ.error(return_status)
                    err_msg += return_status
                    LOG_OBJ.error("Some problem occurred while cleaning "
                                  "gbp resources in %s project.Proceeding"
                                  " further with clean up."
                                  % local_project_info["name"])

                # validate stack cleanup after cleaning GBP
                # resources in local tenant
                status = self.validate_stack_cleanup(local_project_info)
                if status is not True:
                    err_msg += status
                    LOG_OBJ.error("Stack is not cleaned up after cleaning  "
                                  "gbp resources.Proceeding further "
                                  "with clean up.")
                else:
                    print "Stack cleanup happened properly after cleaning"\
                        " GBP resources in project %s"\
                        % local_project_info["tid"]
                    LOG_OBJ.debug("Stack cleanup happened properly after "
                                  "cleaning GBP resources in project %s"
                                  % local_project_info["tid"])

                # Delete local tenant and resources (neutron, nova &
                # keystone)in it.
                message = "Started cleaning resources (neutron, nova, keyst"\
                    "one) in local project: %s" % project_info["project_name"]
                decorated_message = self.common_obj.\
                    get_decorated_message(message, '&', 80)
                print decorated_message
                LOG_OBJ.debug(decorated_message)

                # tenant_info = {"project_name": project_info["project_name"],
                #              "domain_name": project_info["domain_name"],
                #               "user_name": project_info["user_name"]
                #              }
                status = self.clean_neutron_resources(project_info)
                if type(status) == str or type(status) == unicode:
                    err_msg += status
                    LOG_OBJ.error("Some problem occurred while cleaning "
                                  "neutron, nova & keystone resources of %s"
                                  " local project. Proceeding with cleanup.")
            if err_msg:
                return str(err_msg)
            return True
        except Exception, err:
            LOG_OBJ.exception(err)
            return "Exception occurred while cleaning local project resources."

    def delete_remote_project_resources(self, remote_project_list):
        """Deletes resources (neutron, nova, keystone) in remote projects.

        Argu:
            remote_project_list: list of remote project details.
            [
                {
                    'project_name': "",
                    "user_name": "",
                    "password": "",
                    "domain_name": ""
                }, {}, {}, ...
            ]

        Returns: On Success returns True.
            On failure returns string containing error message.
        """
        try:
            err_msg = ""
            # clean resources in remote tenant.
            for project_info in remote_project_list:
                project_name = project_info.get("project_name")
                user_name = project_info.get("user_name")
                if not project_name or not user_name:
                    err_msg += "Incorrect project details. "
                    LOG_OBJ.error(err_msg)
                    continue

                message = "Started cleaning resources in remote project:"\
                    " %s" % project_info["project_name"]
                decorated_message = self.common_obj.\
                    get_decorated_message(message, '&', 70)
                print decorated_message
                LOG_OBJ.debug(decorated_message)

                # check if project exist.
                if not self.isprojectexist(user_name, project_name):
                    err_msg = "ResourceCleanup: Looks like project with "\
                        "name %s or user with name %s is not created."\
                        % (project_name, user_name)
                    LOG_OBJ.error(err_msg)
                    continue

                remote_project_info = {
                            "project_name": project_name,
                            "domain_name": project_info.get(
                                                    "domain_name",
                                                    common_config.
                                                    cloud_admin_domain),
                            }
                status = self.clean_neutron_resources(remote_project_info)
                if status is not True:
                    err_msg += status
                    LOG_OBJ.error("Resources in remote project '%s' didn't "
                                  "cleaned up properly. Proceeding further"
                                  "with clean up." % remote_project_info[
                                                            "project_name"])
            if err_msg:
                return err_msg
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while cleaning resources in "\
                "remote projects."

    def clean_resources(self, project_details_dict):
        """Master function. This function will clean all resources
        (gbp, neutron, nova, keystone) in local & remote projects.

        Argu:
            project_details_dict: (dict)
            e.g.
            project_details_dict = {
                "local_project_details": [
                                            {
                                                'project_name': "",
                                                "user_name": "",
                                                "password": "",
                                                "domain_name": "",
                                                "sharable": True/False
                                                # if using shared node & spec.
                                            }, {}, {}, ...
                                        ],
                "remote_project_details": [
                                            {
                                                'project_name': "",
                                                "user_name": "",
                                                "password": "",
                                                "domain_name": ""
                                            }, {}, {}, ...
                                        ]
                }
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            decorated_message = self.common_obj.\
                get_decorated_message("Started Post Test Resources Cleanup",
                                      '@', 70)
            print decorated_message
            LOG_OBJ.debug(decorated_message)

            self.error_msg = ""
            print "project_details_dict: %s" % project_details_dict
            LOG_OBJ.debug("project_details_dict: %s" % project_details_dict)

            # clean resources in local tenant.
            if not project_details_dict.get("local_project_details") and\
                    not project_details_dict.get("remote_project_details"):
                err_msg = "Local & remote project details missing couldn't"\
                    " proceed with resource cleanup."
                print err_msg
                LOG_OBJ.error(err_msg)
                return err_msg

            # reset cloud admin token.
            self.lib_obj.set_cloud_admin_info(only_token=True)

            if project_details_dict.get("local_project_details"):
                status = self.delete_local_project_resources(
                                project_details_dict["local_project_details"])
                if type(status) == str:
                    self.error_msg += status
                    LOG_OBJ.error("Some problem occurred while cleaning res"
                                  "ources in local projects. Proceeding"
                                  " with cleanup.")

            # clean resources in remote tenant.
            if project_details_dict.get("remote_project_details"):
                status = self.delete_remote_project_resources(
                                project_details_dict["remote_project_details"])
                if type(status) == str:
                    self.error_msg += status

            if self.error_msg != "":
                return self.error_msg
            else:
                return True
        except Exception as err:
            err_msg = "Exception while cleaning resources after "\
                "test execution."
            LOG_OBJ.exception(err)
            self.error_msg += err_msg
            return self.error_msg

    def validate_stack_cleanup(self, tenant_info):
        """This function will validate stack cleanup, once GBP resources
        are cleaned up from local tenant,.
        Arguments:
            (1) tenant_info (dict)
                e.g.
                    {
                        'name': None,
                        'tid': None,
                        'token': None
                    }
            (2) heat_driver (heat library object.)
        Returns: On success returns True.
            On failure returns string containing error message.
        """
        try:
            err_msg = ""
            # lib heat object
            heat_driver = HeatLibrary(self.os_pub_ip,
                                      tenant_info["tid"],
                                      tenant_info["token"])
            # list stacks in local tenant.
            stacks_info = heat_driver.stack_list()
            if type(stacks_info) is not list:
                err_msg += "Failed to list stacks in tenant %s"\
                    % tenant_info["tid"]
                print err_msg
                LOG_OBJ.error(err_msg)
                return err_msg

            if len(stacks_info) != 0:
                err_msg += "Stack exist in tenant %s, even after "\
                    "cleaning GBP resources." % tenant_info["tid"]
                print err_msg
                LOG_OBJ.error(err_msg)
                LOG_OBJ.error("Uncleaned stack list: %s"
                              % stacks_info)
                return err_msg
            return True
        except Exception as err:
            err_msg += "Exception while validating stack "\
                "cleanup after GBP resource cleanup."
            LOG_OBJ.exception(err)
            return err_msg

    def clean_neutron_resources(self, tenant_info):
        """It will clean all resources in tenant. And after that it will
        clean tenant it self.
        Arguments: tenant_info (dictionary)
            e.g.
                tenant_info = {
                        "project_name": "test1",
                        "domain_name": "test_domain", # in case of keystone v3
                        "user_name": user1
                       }
        Returns: On success returns true.
            On Failure returns string containing error message.
        """
        try:
            cleanup_project_list = []
            cleanup_project_list.append(tenant_info)
            status = self.neutron_cleanup.\
                start_resource_cleanup(cleanup_project_list)
            if type(status) == str:
                err_msg = status
                return err_msg
            return True
        except Exception as err:
            err_msg += "Exception occurred while deleting tenant resources."
            LOG_OBJ.exception(err)
            return err_msg

    def master_local_project_resource_cleanup(self, project_type="local"):
        """Method will verify projects & users created by automation
        framework are actually cleaned up or not. if not it will
        cleanup them along with resources they have.

        Optional Arguments:
            project_type: if "local" cleans local projects if any.
                        if "remote" cleans remote projects if any.

        Return: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            tenant_details_dict = {"local_project_details": [],
                                   "remote_project_details": []
                                   }

            base_project_name = common_config.\
                keystonev3_project_details[0]["project_name"]
            base_user_name = common_config.\
                keystonev3_project_details[0]["user_name"]
            base_passwd = common_config.\
                keystonev3_project_details[0]["password"]
            if project_type.lower() == "remote":
                base_project_name = common_config.remote_project_info[
                                                        0]["project_name"]
                base_user_name = common_config.remote_project_info[0][
                                                            "user_name"]
                base_passwd = common_config.\
                    remote_project_info[0]["password"]

            # get project & user list.
            if common_config.keystone_api_version == 'v3':
                project_list = self.lib_obj.list_keystone_v3_projects()
                if type(project_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list project."
                    LOG_OBJ.error(err_msg)
                    return err_msg
                user_list = self.lib_obj.list_keystone_v3_users()
                if type(user_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list users."
                    LOG_OBJ.error(err_msg)
                    return err_msg
            else:
                project_list = self.lib_obj.list_tenants()
                if type(project_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list project."
                    LOG_OBJ.error(err_msg)
                    return err_msg
                user_list = self.lib_obj.list_users()
                if type(user_list) is not list:
                    err_msg = "ResourceCleanup: Failed to list users."
                    LOG_OBJ.error(err_msg)
                    return err_msg

            LOG_OBJ.info("Project List: %s" % project_list)
            LOG_OBJ.info("User list: %s" % user_list)

            stale_prj_usr = []
            for project in project_list:
                if base_project_name in project['name']:
                    project_name = project['name']
                    if project_type.lower() == "local" and\
                            common_config.remote_project_info[0][
                            "project_name"] in project_name:
                        continue

                    user_name = base_user_name +\
                        project_name[len(base_project_name):]
                    stale_prj_usr.append((project_name, user_name))

            LOG_OBJ.debug("Stale Projects: %s" % stale_prj_usr)
            for project in stale_prj_usr:
                project_name = project[0]
                user_name = project[1]
                self.error_msg = ""
                tenant_info = {}
                tenant_info["project_name"] = project_name
                tenant_info["user_name"] = user_name
                tenant_info["password"] = base_passwd
                tenant_info["domain_name"] = common_config.\
                    keystonev3_domain_name
                if project_type.lower() == "remote":
                    tenant_info["domain_name"] = \
                        common_config.cloud_admin_domain
                tenant_info["sharable"] = False
                tenant_details_dict["local_project_details"].\
                    append(tenant_info)

                status = self.clean_resources(tenant_details_dict)
                if type(status) is str:
                    print "Some problem occurred while cleaning resources"\
                        " in project %s with user %s" % (project_name,
                                                         user_name)
                    LOG_OBJ.error("Some problem occurred while "
                                  "cleaning resources in project %s"
                                  " with user %s" % (project_name,
                                                     user_name))
            return True
        except Exception as err:
            err_msg = "Exception occurred while cleaning stale project "\
                "entries post running automation."
            LOG_OBJ.exception(err)
            print "%s" % err_msg
            return err_msg

    def master_remote_tenant_resource_cleanup(self):
        """This function will check if remote-tenant (created in N-S scenarios)
        are deleted or not. if not it will delete those stale tenants &
        resources they have.

        Arguments:

        """
        try:
            self.master_local_project_resource_cleanup(project_type="remote")
            return True
        except Exception as err:
            err_msg = "Exception occurred while deleting stale remote "\
                "tenant & it's resources."
            print err_msg
            LOG_OBJ.exception(err)
            return err_msg
