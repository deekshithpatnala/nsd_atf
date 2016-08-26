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
    Module contains methods for deleting neutron resources (network, subnet,
    floatingip, ports, routers). Though name of module is neutron_cleanup, it
    have methods for deleting nova resources (vms) & keystone resources
    (project & users). Used for cleaning resource created by test cases,
    after test case completion.
"""


# added comment to generate diff file

import time
import sys
from atf.config import common_config
import traceback
import atf.lib.nvp_atf_logging as log


sys.path.append("../../")

LOG_OBJ = log.get_atf_logger()
# pylint: disable=W0702
# pylint: disable=R0914
null = None


class NeutronCleanup():
    """
    Class contains methods for cleaning neutron,
    nova & keystone resources created during test case
    execution.
    """
    def __init__(self, lib_obj):
        """
        Arguments:
            lib_obj: OpnstackLibraray class object.
        """
        self.LIBOS = lib_obj

    def start_resource_cleanup(self, cleanup_project_info_list):
        """
        For cleaning (deleting) resources (vm, ports, floatingip, routers,
        networks, subnets, tenant, tenant users)
        Arguments:
            cleanup_project_info_list   (list project details dictionaries)
            e.g.
            [
                {
                    "project_name": "test1",
                    "domain_name": "testdom1" # for keystone v3
                    "user_name": "user1"
                },
                {}, {}, ...
            ]
        Returns: On success returns True.
            On failure returns string containing error message.
        """
        try:
            err_msg = ""
            domain_id = None
            old_project_info = None
            for project in cleanup_project_info_list:
                if common_config.keystone_api_version == "v3":
                    project_id = self.LIBOS.\
                        get_keystone_v3_project_id(project["project_name"])
                    if not isinstance(project_id, unicode):
                        err_msg += " Failed to get project id of project"\
                            " %s" % project["project_name"]
                        LOG_OBJ.error(err_msg)
                        return err_msg
                    # get domain id
                    domain_id = self.LIBOS.\
                        get_keystone_v3_domain_id(project["domain_name"])
                    if not isinstance(domain_id, unicode):
                        err_msg += " Failed to get domain id of domain"\
                            " %s" % project["domain_name"]
                        LOG_OBJ.error(err_msg)
                        return err_msg
                else:
                    project_id = self.LIBOS.get_tenant_id(
                                            project["project_name"])
                    if not isinstance(project_id, unicode):
                        err_msg += " Failed to get project id of project"\
                            " %s" % project["project_name"]
                        LOG_OBJ.error(err_msg)
                        return err_msg

                old_project_info = self.LIBOS.set_tenant_info(
                                common_config.cloud_admin_project,
                                self.LIBOS.cloud_admin_info["token_domain"],
                                self.LIBOS.cloud_admin_info["token_project"],
                                self.LIBOS.cloud_admin_info["project_id"]
                                )
                if type(old_project_info) != tuple:
                    err_msg += "Changing project context in libos object "\
                        "failed."
                    LOG_OBJ.error(err_msg)
                    return err_msg

                destroy_project_info = {"tid": project_id,
                                        "domain_id": domain_id,
                                        "user_name": project["user_name"],
                                        "tenant_name": project["project_name"]
                                        }
                status = self.destroy_all(destroy_project_info)
                if not isinstance(status, bool):
                    err_msg += str(status)
                    # return err_msg

            if err_msg != "":
                return err_msg
            return True
        except:
            err_msg += "Exception occurred while cleaning resources."
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg
        finally:
            if old_project_info:
                self.LIBOS.set_tenant_info(*old_project_info)

    def destroy_all(self, tenant_info):
        """
        Argument:
            tenant_info (dictionary)
                {
                    "tid": tenant id
                    "domain_id": domain_id
                    "user_name": "user_name",
                    "tenant_name": "project_name"
                }
        Returns: On success returns True.
            On failure returns string containing error message.
        """
        try:
            err_msg = ""
            tenant_id = tenant_info["tid"]
            # delete nova instances
            status = self.delete_instances(tenant_id)
            if not isinstance(status, bool):
                err_msg += status
            time.sleep(10)
            # delete floating ips.
            status = self.delete_floatingip(tenant_id)
            if not isinstance(status, bool):
                err_msg += status
            # delete routers.
            status = self.delete_routers(tenant_id)
            if not isinstance(status, bool):
                err_msg += status
            # delete ports
            status = self.delete_ports(tenant_id)
            if not isinstance(status, bool):
                err_msg += status
            # delete subnets
            status = self.delete_subnets(tenant_id)
            if not isinstance(status, bool):
                err_msg += status
            # delete networks
            status = self.delete_networks(tenant_id)
            if not isinstance(status, bool):
                err_msg += status
            # delete tenant
            status = self.delete_tenant(tenant_info)
            if not isinstance(status, bool):
                err_msg += status

            if err_msg != "":
                return err_msg
            print "\nSuccesfully deleted all resources of tenant %s\n"\
                % tenant_info["tid"]
            LOG_OBJ.debug("\nSuccesfully deleted all resources "
                          "of tenant %s\n" % tenant_info["tid"])
            return True
        except:
            err_msg += "Some exception while cleaning resources "\
                "in tenant %s" % tenant_info["tid"]
            LOG_OBJ.error("Got an exception : %s " % traceback.format_exc())
            return err_msg

    def delete_instances(self, tenant_id):
        """
        This function will delete all instances from given tenant.
        Arguments:
                tenant_id
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting instances of tenant %s" % tenant_id
            LOG_OBJ.debug("Deleting instances of tenant %s" % tenant_id)

            # get nova list
            server_list = self.LIBOS.list_servers(all_tenants=True)
            if not isinstance(server_list, list):
                err_msg = "Some problem while getting server "\
                    "list in tenant: %s" % tenant_id
                return err_msg

            # delete servers
            for server in server_list:
                if str(tenant_id) == str(server['tenant_id']):
                    LOG_OBJ.debug("Deleting server %s" % server['id'])
                    status = self.LIBOS.delete_server(server["id"])
                    if not isinstance(status, bool):
                        err_msg = "Some problem while deleting %s server of "\
                            "tenant %s" % (server["id"], tenant_id)
                        return err_msg
                    time.sleep(10)
            print "Successfully deleted all instances in tenant:"\
                " %s" % tenant_id
            LOG_OBJ.debug("Successfully deleted all instances in "
                          "tenant: %s" % tenant_id)
            return True
        except:
            err_msg = "Exception occurred while deleting instances "\
                "of tenant: %s" % tenant_id
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg

    def delete_routers(self, tenant_id):
        """
        This function will delete all routers from given tenant.
        Arguments:
            tenant_id: ID of tenant.
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting routers in the tenant: %s" % tenant_id
            LOG_OBJ.debug("Deleting routers in the tenant: %s" % tenant_id)

            # get router list
            router_list = self.LIBOS.list_router()
            if not isinstance(router_list, list):
                err_msg = "problem while listing routers in "\
                    "tenant: %s" % router_list
                LOG_OBJ.error(err_msg)
                return err_msg

            for router in router_list:
                if str(tenant_id) == str(router['tenant_id']):
                    router_id = router['id']

                    if type(router['external_gateway_info']) is dict:
                        # clear external router gateway
                        print "Clearing external gateway of router"\
                            " %s" % router_id
                        LOG_OBJ.debug("Clearing external gateway of "
                                      "router %s" % router_id)
                        status = self.LIBOS.clear_router_gateway(router_id)
                        if not isinstance(status, bool):
                            err_msg = "Some problem while clearing external "\
                                "gateway of %s router" % router_id
                            LOG_OBJ.error(err_msg)
                            return err_msg

                    # get router port list
                    port_list = self.LIBOS.list_router_ports(router_id)
                    if not isinstance(port_list, list):
                        err_msg = "Some problem while listing router ports "\
                            "related to router %s of tenant %s" % (router_id,
                                                                   tenant_id)
                        LOG_OBJ.error(err_msg)
                        return err_msg

                    for port in port_list:
                        for fixed_ip in port['fixed_ips']:
                            # get subnet id
                            subnet_id = fixed_ip['subnet_id']
                            # remove associated router interface
                            print "Detaching %s subnet from %s router of "\
                                "%s tenant" % (subnet_id, router_id, tenant_id)
                            LOG_OBJ.debug("Detaching %s subnet from "
                                          "%s router of %s tenant"
                                          % (subnet_id, router_id, tenant_id))
                            status = self.LIBOS.\
                                remove_router_interface(router_id,
                                                        subnet_id)
                            if not isinstance(status, bool):
                                err_msg = "Some problem while detaching %s "\
                                    "subnet from %s router."\
                                    % (subnet_id, router_id)
                                return err_msg
                        # Revisit (Kiran): Temproty fix.
                        status = self.LIBOS.delete_port(port["id"])
                        if not status:
                            err_msg = "Some problem occurred while deleting " \
                                "router port: %s" % port["id"]
                            LOG_OBJ.error(err_msg)
                            return err_msg

                    # delete router
                    print "Deleting %s router of tenant %s"\
                        % (router_id, tenant_id)
                    LOG_OBJ.debug("Deleting %s router of tenant %s"
                                  % (router_id, tenant_id))
                    status = self.LIBOS.delete_router(router_id)
                    if not isinstance(status, bool):
                        err_msg = "Some problem while deleting %s router of "\
                            "%s tenant" % (router_id, tenant_id)
                        return err_msg

            print "Successfully deleted all routers in %s tenant." % tenant_id
            LOG_OBJ.debug("Successfully deleted all routers in %s "
                          "tenant." % tenant_id)
            return True
        except:
            err_msg = "Exception occurred while deleting routers in "\
                "%s tenant" % tenant_id
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg

    def delete_ports(self, tenant_id):
        """
        This function will delete all ports from given tenant.
        Arguments:
            tenant_id: ID of tenant
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting all ports present in tenant %s" % tenant_id
            LOG_OBJ.debug("Deleting all ports present in tenant "
                          "%s" % tenant_id)

            # get port list
            port_list = self.LIBOS.list_port()
            if not isinstance(port_list, list):
                err_msg = "Some problem while listing ports in "\
                    "%s tenant" % tenant_id
                return err_msg

            for port in port_list:
                if str(tenant_id) == str(port['tenant_id']):
                    port_id = port['id']
                    # get port details and check for dhcp port
                    port_info = self.LIBOS.show_port(port_id)
                    if not isinstance(port_info, dict):
                        err_msg = "Some problem while getting details of "\
                            "port %s of tenant %s" % (port_id, tenant_id)
                        return err_msg

                    if port_info['device_owner'] not in\
                            ['network:dhcp']:
                        # delete port
                        print "Deleting %s port of tenant %s"\
                            % (port_id, tenant_id)
                        LOG_OBJ.debug("Deleting %s port of tenant %s"
                                      % (port_id, tenant_id))
                        status = self.LIBOS.delete_port(port_id)
                        if not isinstance(status, bool):
                            err_msg = "Some problem while deleting port %s "\
                                "of %s tenant" % (port_id, tenant_id)
                            return err_msg

            print "Successfully deleted all the ports in "\
                "%s tenant." % tenant_id
            LOG_OBJ.debug("Successfully deleted all the ports "
                          "in %s tenant." % tenant_id)
            return True
        except:
            err_msg = "Exception while deleting ports in %s tenant" % tenant_id
            LOG_OBJ.error("%s" % traceback.format_exc())
            return

    def delete_subnets(self, tenant_id):
        """
        This function will delete all subnets from given tenant.
        Arguments:
            tenant_id: ID of tenant
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting all subnets presents in tenant %s" % tenant_id
            LOG_OBJ.debug("Deleting all subnets presents in tenant %s"
                          % tenant_id)

            # get subnet list
            subnet_list = self.LIBOS.list_subnet()
            if not isinstance(subnet_list, list):
                err_msg = "Some problem while listing subnets "\
                    "in %s tenant" % tenant_id
                return err_msg

            for subnet in subnet_list:
                if str(tenant_id) == str(subnet['tenant_id']):
                    subnet_id = subnet['id']
                    # delete subnet
                    print "Deleting Subnet %s of %s tenant" % (subnet_id,
                                                               tenant_id)
                    LOG_OBJ.debug("Deleting Subnet %s of %s tenant"
                                  % (subnet_id, tenant_id))
                    status = self.LIBOS.delete_subnet(subnet_id)
                    if not isinstance(status, bool):
                        err_msg = "Some problem while deleting %s subnet "\
                            "of %s tenant." % (subnet_id, tenant_id)
                        return err_msg

            print "Successfully deleted all subnets in %s tenant" % tenant_id
            LOG_OBJ.debug("Successfully deleted all subnets in %s "
                          "tenant" % tenant_id)
            return True
        except:
            err_msg = "Exception occurred while deleting subnets "\
                "of %s tenant" % tenant_id
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg

    def delete_networks(self, tenant_id):
        """
        This function will delete all networks from given tenant.
        Arguments:
            tenant_id: ID of tenant.
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting all networks present in tenant %s" % tenant_id
            LOG_OBJ.debug("Deleting all networks present in tenant %s"
                          % tenant_id)

            # get net list
            network_list = self.LIBOS.list_net()
            if not isinstance(network_list, list):
                err_msg = "Some problem while listing networks"\
                    " in %s tenant." % tenant_id
                return err_msg

            for net in network_list:
                if str(tenant_id) == str(net['tenant_id']):
                    network_id = net["id"]
                    print "Deleting network %s of %s tenant"\
                        % (network_id, tenant_id)
                    LOG_OBJ.debug("Deleting network %s of %s tenant"
                                  % (network_id, tenant_id))
                    status = self.LIBOS.delete_net(network_id)
                    if not isinstance(status, bool):
                        err_msg = "Some problem while deleting %s network "\
                            "of %s tenant." % (network_id, tenant_id)
                        return err_msg

            print "Successfully deleted all the networks in "\
                "%s tenant" % tenant_id
            LOG_OBJ.debug("Successfully deleted all the networks "
                          "in %s tenant" % tenant_id)
            return True
        except:
            err_msg = "Exception occurred while deleting networks "\
                "in %s tenant" % tenant_id
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg

    def delete_floatingip(self, tenant_id):
        """
        This function will delete all floating ips from given tenant.
        Arguments:
            tenant_id: ID of tenant
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting floating ips in %s" % tenant_id
            LOG_OBJ.debug("Deleting floating ips in %s" % tenant_id)

            # get floating ip list
            floatingip_list = self.LIBOS.list_floating_ip()
            if not isinstance(floatingip_list, list):
                err_msg = "Some problem while listing floating ips"\
                    " of %s tenant" % tenant_id
                return err_msg

            for floatingip in floatingip_list:
                if str(tenant_id) == str(floatingip['tenant_id']):
                    floatingip_id = floatingip['id']

                    # dissociate floating ip
                    print "Dissociating floatingip: %s" % floatingip_id
                    LOG_OBJ.debug("Dissociating floatingip: %s"
                                  % floatingip_id)

                    status = self.LIBOS.disassociate_floating_ip(floatingip_id)
                    if not isinstance(status, bool):
                        err_msg = "Some problem while dissociating "\
                            "floatingip with id %s of %s tenant"\
                            % (floatingip_id, tenant_id)
                        return err_msg
                    # delete floating ip
                    print "Deleting floating ip: %s" % floatingip_id
                    LOG_OBJ.debug("Deleting floating ip: %s" % floatingip_id)
                    status = self.LIBOS.delete_floating_ip(floatingip_id)
                    if not isinstance(status, bool):
                        err_msg = "Some problem while deleting floatingip"\
                            " with id %d of 5s tenant."\
                            % (floatingip_id, tenant_id)
                        return err_msg

            print "Successfully deleted all the floating ips "\
                "in %s tenant" % tenant_id
            LOG_OBJ.debug("Successfully deleted all the floating ips "
                          "in %s tenant" % tenant_id)
            return True
        except:
            err_msg = "Exception occurred while deleting floating "\
                "ips in %s tenant" % tenant_id
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg

    def delete_user(self, tenant_info):
        """
        This function will delete given tenant user.
        Arguments:
            1. tenant_info (dictionary)
                {
                    "tid": <tenant id>,
                    domain_id": domain id,
                    "user_name": user name
                }

        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            if common_config.keystone_api_version == "v3":
                # get user roles assigned to project.
                role_assignment_list = self.LIBOS.\
                    list_assigned_keystone_v3_roles(project=tenant_info["tid"])
                if type(role_assignment_list) != list:
                    err_msg = "Failed to list user roles associated with"\
                        " project %s" % tenant_info["tid"]
                    LOG_OBJ.error(err_msg)
                    return err_msg

                if len(role_assignment_list) == 0:
                    print "No user associated with project %s"\
                        % tenant_info["tid"]
                    LOG_OBJ.debug("No user associated with project"
                                  " %s" % tenant_info["tid"])
                    return True

                # filter users based on project id.
                user_set = set()
                for role in role_assignment_list:
                    user_set.add(role["user"]["id"])

                for user_id in list(user_set):
                    # check if user is cloud admin user.
                    user_details = self.LIBOS.show_keystone_v3_user(user_id)
                    if user_details["name"] in [common_config.cloud_admin_user,
                                                "admin", "neutron"]:
                        LOG_OBJ.debug("Ignoring cloud admin user "
                                      "deletion associated with project"
                                      " %s" % tenant_info["tid"])
                        continue
                    # delete users.
                    print "Deleting user: %s" % user_id
                    LOG_OBJ.debug("Deleting user: %s" % user_id)
                    status = self.LIBOS.delete_keystone_v3_user(user_id)
                    if not isinstance(status, bool):
                        err_msg = "Failed to delete user %s" % user_id
                        LOG_OBJ.error(err_msg)
                        return err_msg
                return True
            else:
                if tenant_info['user_name'] in \
                        [common_config.cloud_admin_user, "admin", "neutron"]:
                    LOG_OBJ.debug("Ignoring deletion of cloud admin associated"
                                  "with project %s" % tenant_info["tid"])
                    return True

                status = self.LIBOS.delete_user(tenant_info['tid'],
                                                tenant_info['user_name'])
                if not isinstance(status, bool):
                    err_msg = "Failed to delete user:"\
                        " %s" % tenant_info["user_name"]
                    LOG_OBJ.error(err_msg)
                    return err_msg
                return True
        except:
            err_msg = "Exception occurred while deleting "\
                "tenant users."
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg

    def delete_tenant(self, tenant_info):
        """
        This function will delete given tenant.
        Arguments:
            tenant_info: tenant info
            {
                    "tid": <tenant id>,
                    "domain_id": domain id
                    "user_name": user name
            }
        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            print "Deleting tenant: %s" % tenant_info["tid"]
            LOG_OBJ.debug("Deleting tenant: %s" % tenant_info["tid"])

            # delete users associated with project.
            status = self.delete_user(tenant_info)
            if type(status) != bool:
                err_msg = "Failed to delete users associated "\
                    "with project %s" % tenant_info["tid"]
                print err_msg
                LOG_OBJ.error(err_msg)
                return err_msg

            print "Deleted users associated with pr"\
                "oject %s" % tenant_info["tid"]
            LOG_OBJ.debug("Deleted users associated with pr"
                          "oject %s" % tenant_info["tid"])

            # delete project.
            if common_config.keystone_api_version == "v3":
                status = self.LIBOS.\
                    delete_keystone_v3_project(tenant_info["tid"],
                                               tenant_info["domain_id"])
                if not isinstance(status, bool):
                    err_msg = "failed to delete project %s"\
                         % tenant_info["tid"]
                    LOG_OBJ.error(err_msg)
                    return err_msg
            else:
                status = self.LIBOS.delete_tenant(tenant_info['tid'])
                if not isinstance(status, bool):
                    err_msg = "Failed to delete project: %s"\
                        % tenant_info['tid']
                    LOG_OBJ.error(err_msg)
                    return err_msg

            print "Successfully deleted tenant: %s" % tenant_info["tid"]
            LOG_OBJ.debug("Successfully deleted tenant:"
                          " %s" % tenant_info["tid"])
            return True
        except:
            err_msg = "Exception occurred while deleting "\
                "tenant: %s" % tenant_info["tid"]
            LOG_OBJ.error("%s" % traceback.format_exc())
            return err_msg
