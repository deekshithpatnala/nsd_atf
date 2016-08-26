#
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
#
# pylint: disable=W0703
"""
This is a resource creator module.
This basically creates the GBP resources.
"""
# import sys
# sys.path.append("../../")

from contextlib import contextmanager
import copy
from decorator import decorator
import threading
import json
import re
# import time

import atf.config.common_config as config
import atf.config.gbp_config as gbp_config
import atf.config.template_config as template_config
from atf.lib.lib_common import commonLibrary
from atf.lib.gbp_constructs import gbp_construct
from atf.lib.lib_haproxy import LbaasLib
from atf.lib.lib_heat import HeatLibrary
# from atf.lib.lib_mysql import AccessDb
from atf.lib.lib_os import OpenStackLibrary
import atf.lib.nvp_atf_logging as log
from atf.lib.remote_vpn_configure import RemoteVpnClientConfigure


LOG = log.get_atf_logger()


def create_external_gateway(lib_os_obj, **kwargs):
    """
    It attaches the router to the external network.
    Note: If no router id is passed then it creates a router and then attaches
        the  router to the external network..

    params: lib_os_obj: Openstack Library Object.

    Optional params: router_name, router_id
    Return: router_id (unicode) on success.
            Error string on failure.
    """
    try:
        # Create router if no router_id passed.
        router_id = kwargs.get("router_id")
        if not router_id:
            routet_name = kwargs.get('router_name', "remote_router")
            router_id = lib_os_obj.create_router(routet_name)
            if not isinstance(router_id, unicode):
                err_msg = "Problem while creating router."
                LOG.error(err_msg)
                return err_msg

        # Attach the router with the external gateway.
        status = lib_os_obj.set_router_gateway(
            config.extnet_name,
            router_id)
        if not isinstance(status, bool):
            LOG.error("Problem while setting the gateway.")
            return "Problem while setting the gateway."

        return router_id
    except Exception as err:
        LOG.exception(err)
        return "Problem while creating router and setting gateway."


def create_floatingip_for_port(lib_os_obj, ext_net_name, port_id):
    """
    It creates a floating in ext_net_name and then attaches the floating ip
    to the port port_id.
    params:
        lib_os_obj: Openstack library object.
        ext_net_name: Name of the external network in which floating ip to be
                      created. Ex: cust-net
        port_id: ID of the port.
    return:
        On succees: floating ip(unicode).
        On failure: error message.
    """
    try:
        # Create a floating ip.
        floatingip_details = lib_os_obj.create_floating_ip(
            ext_net_name,
            return_details=True)
        if not isinstance(floatingip_details, dict):
            err_msg = "Problem while creating floating ip."
            LOG.error(err_msg)
            return err_msg
        # Associate the floating ip with the port.
        status = lib_os_obj.associate_floating_ip(
            floatingip_details['id'],
            port_id)
        if not isinstance(status, bool):
            err_msg = "Problem while associating the floating ip :%s to "\
                "the port %s" % (floatingip_details['floating_ip_address'],
                                 port_id)
            LOG.error(err_msg)
            return str("Problem while associating the floating ip.")

        return unicode(floatingip_details['floating_ip_address'])
    except Exception as err:
        LOG.exception(err)
        return "Problem while creating floating ip for port: %s" % str(port_id)


def create_floatingip_for_server(lib_os_obj, net_id, server_id):
    """
    It first determines the port of server (in the network having id
    net_id) to which the floating ip has to be attached.
    Then it creates a floating ip for the port and returns the port_ip
    and floating_ip in a tuple.

    params:
        lib_os_obj: Openstack Library Object.
        net_id: Network ID,
        server_id: Vm's ID

    Return: tuple: (fixed_ip, floating ip) on success.
            error message on failure.
    """
    try:
        # Get port details.
        port_details = lib_os_obj.get_specific_port_by_server_id(
            net_id, server_id)
        if not isinstance(port_details, dict):
            err_msg = "Problem while getting port details of server %s"\
                % server_id
            LOG.error(err_msg)
            return str(err_msg)
        port_ip = port_details["fixed_ips"][0]["ip_address"]
        # Create a floating ip.
        fip = create_floatingip_for_port(lib_os_obj, config.extnet_name,
                                         port_details['id'])
        if not isinstance(fip, unicode):
            return fip

        return (port_ip, fip)
    except Exception as err:
        LOG.exception(err)
        return "Problem while creating floating ip."


def create_floatingip_for_targets(lib_os_obj, policy_targets):
    """
    It creates the floating ip for the policy-targets whose info is there
    in policy_targets
    params:
        lib_os_obj: Openstack Library Object.
        policy_targets: A list of policy-targets
    Return: A list of floating ips corresponding to each port in target.
    """
    try:
        floating_ips = []
        for target in policy_targets:
            # Create a floating ip.
            floating_ip = create_floatingip_for_port(
                lib_os_obj, config.extnet_name, target['port_id'])
            if not isinstance(floating_ip, unicode):
                return floating_ip
            # Store the floating ip.
            # NOTE: This will also reflect in the original, if no copy of
            # the policy_targets passed to this fun.
            target['floating_ip'] = floating_ip

            floating_ips.append(floating_ip)

        return floating_ips
    except Exception as err:
        LOG.exception(err)
        return "Problem while creating floating ip for targets."


def create_net_subnet(lib_os_obj, subnet_cidr, **kwargs):
    """
    It creates the network and subnet under this network.
    If router id is passed then it attaches the subnet to the router.

    params:
        lib_os_obj: Openstack Library object.
        subnet_cidr: Subnet cidr (ex: 10.10.0.0/24)
    Optional params:
            net_name, subnet_name, router_id
    Return: (net_id, subnet_id)
    """
    try:
        net_name = kwargs.get("net_name", "test_nw")
        net_id = lib_os_obj.create_net(net_name)
        if not isinstance(net_id, unicode):
            err_msg = "Problem while creating the network."
            LOG.error(err_msg)
            return err_msg
        # Create subnet
        subnet_name = kwargs.get('subnet_name', 'subnet')
        subnet_id = lib_os_obj.create_subnet(net_name,
                                             subnet_name,
                                             subnet_cidr)
        if not isinstance(subnet_id, unicode):
            err_msg = "Problem while creating the subnet with"\
                " cidr: %s." % str(subnet_cidr)
            LOG.error(err_msg)
            return err_msg
        LOG.debug("net_id: %s, subnet_id: %s", net_id, subnet_id)
        # Attach the subnet to the router, if necessary.
        if kwargs.get('router_id'):
            status = lib_os_obj.add_router_interface(
                kwargs['router_id'],
                subnet_id
            )
            if not isinstance(status, bool):
                err_msg = "Problem while attaching subnet: %s to the "\
                    "router: %s" % (subnet_id, kwargs['router_id'])
                LOG.error(err_msg)
                return str("Problem while attaching subnet to router.")
            LOG.info("Successfully attached the subnet"
                     " to the router")

        return (net_id, subnet_id)
    except Exception as err:
        LOG.exception(err)
        return "Problem in creating net/subnet"


def launch_vms_using_targets(lib_os_obj, image_name, targets, **kwargs):
    """It launches the vms using the ports in the policy targets.

    Note: The vms will be launched PARALLELLY.
    params:
        lib_os_obj: Openstack Library object.
        image_name: Name of the image using which the vm to be launched.
        targets: The list of targets in the target group. Each target is
                 a dictionary containing the target info like port_id,
                 network_id, ptg_name(optional), etc.
                 Ex: targets = [{port_id, network_id, ..}, {}]
    Optional params:
        flavor_name: Name of the flavor.

    Return: List containing the server ids.
    """
    try:
        server_ids = []
        old_project_info = None
        for target_index, target in enumerate(targets):
            ptg_name = target.get('ptg_name', "ptg")
            server_name = ptg_name + "_vm_" + str(target_index + 1)
            network_id = target['network_id']
            port_id = target['port_id']
            # Launch VM
            server_info = lib_os_obj.create_server(
                image_name, kwargs.get('flavor_name', "m1.small"), "",
                server_name, port_ids=port_id,
                poll_on_status=False, net_ids=network_id, return_details=True)
            if not isinstance(server_info, dict):
                err_msg = "\nProblem while launching VM using "\
                    "the port_id:%s on the newtork: %s" % \
                    (str(port_id), str(network_id))
                LOG.error(err_msg)
                return "Problem while launching VM"
            # An optioanl attempt. This will reflect in the original
            # targets provided no copy of targets passed to this fun.
            target['server_id'] = server_info['id']
            # target['host_name'] = server_info['OS-EXT-SRV-ATTR:host']

            msg = "\n\nVM: %s is launched using port: %s. Target id: %s"\
                % (str(server_info['id']), str(port_id), str(target['id']))
            print msg
            LOG.info(msg)
            server_ids.append(server_info['id'])

        LOG.debug("All Server ids: %s", server_ids)
        # Poll on the servers.
        for server_id in server_ids:
            output = lib_os_obj.poll_on_server_boot_up(server_id)
            if not isinstance(output, unicode):
                return output

        print "\nAll vms launched successfully ..."
        LOG.info("\nAll vms launched successfully ...")

        admin_project_id = lib_os_obj.\
            cloud_admin_info['project_id']
        # NOTE: Get the token of admin with project scope.
        admin_token = lib_os_obj.cloud_admin_info['token_project']
        # Set the tenant's token as admin's token (cloud admin)
        # and once the work is done restore back the old token.
        old_project_info = lib_os_obj.set_tenant_info(
            config.cloud_admin_project, admin_token,
            admin_token, admin_project_id)

        # Get host names of target vms
        for target in targets:
            vm_info = lib_os_obj.show_server(target['server_id'])
            if not isinstance(vm_info, dict):
                err_msg = "Problem while getting vm details."
                LOG.error(err_msg)
                return err_msg
            target['host_name'] = vm_info['OS-EXT-SRV-ATTR:host']

        return server_ids
    except Exception as err:
        LOG.exception(err)
        return "ERROR: Problem occured while launching vms using policy"\
            " target ports."
    finally:
        # NOTE: Don't use return statement here.
        # Unset the context, if changed at all.
        if old_project_info:
            lib_os_obj.set_tenant_info(*old_project_info)


def get_stack_by_node_id(heat_lib_obj, node_id):
    """
    It returns the stack details corresponding to the service chain node.
    params:
        heat_lib_obj: Heat Library Object.
        node_id: Service Chain NOde ID.
    Return: On success: Dict, containing stack details.
    """
    try:
        # List the stacks
        stacks = heat_lib_obj.stack_list()
        if not isinstance(stacks, list):
            LOG.error("ERROR: Problem while listing the stack.")
            return "ERROR: Problem while listing the stack."
        LOG.debug("\n\nStacks: %s", stacks)
        if len(stacks) == 0:
            LOG.error("ERROR: There is NO stack created!")
            return "ERROR: There is NO stack created!"

        # Get the stack name corresponding to the node
        for stack in stacks:
            node_it_part = str(node_id)[:8]
            if node_it_part in stack['stack_name']:
                msg = "\nStack name corresponds to the node: %s is %s" % (
                    node_id, stack['stack_name'])
                LOG.info(msg)
                stack_name = str(stack['stack_name'])
                stack_id = stack['id']
                # Poll on the stack to become CREATE_COMPLETE/UPDATE_COMPLETE
                status = heat_lib_obj.poll_on_stack_status(stack_id)
                if not isinstance(status, bool):
                    return status
                # Show the stack and get the details.
                stack_details = heat_lib_obj.stack_show(stack_id)
                LOG.debug("Stack details: %s", stack_details)
                if not isinstance(stack_details, dict):
                    err_msg = "Problem while showing stack: %s" % stack_name
                    LOG.error(err_msg)
                    return err_msg
                return stack_details

        LOG.error("ERROR: There is NO stack created "
                  "corresponding to the node: %s", node_id)
        return "ERROR: There is NO stack created corresponding to the"\
            " service chain node."

    except Exception as err:
        LOG.exception(err)
        return "Problem while getting stack name for service chain node."


def add_pool_members(lbaas_obj, vip_id, pool_id, port_range, vms_info):
    """
    It adds the members (corresponding to the vm ip in vms_info)
    into the pool. If the port_range contains multiple ports then for
    one vm we have multiple members added to the pool.
    Note:
        (1) For simplicity, We assume the weight is applied to a vm.
            And hence the weight of member(s) is same as the weight of the
            corresponding vm.
            Ex: The weights of 3 vms are   2, 1, 1.
        (2) We will directly add the weight in the vms_info.
            [This will also reflect in the original provider target.]
    params:
        lbaas_obj: Haproxy Library (Lbaas) object.
        vip_id: ID of the vip
        pool_id: Id of the pool to which the vip is added.
        port_range: Range of ports on which there are servers running in
                    the vm.
        vms_info: The list of dict. Each dict contains info of a vm
                  which will be added as member to pool.

    Return: List of weigts of vm [actually weights of members], on success
    """
    try:
        weights = gbp_config.member_weight
        for port in port_range.split(":"):
            for vm_info, weight in zip(vms_info, weights):
                # Add member to pool.
                member = lbaas_obj.create_member(
                    protocol_port=port,
                    address=vm_info['vm_ip'],
                    pool_id=pool_id,
                    weight=weight)
                if not isinstance(member, dict):
                    err_msg = "Problem while adding vm:%s as"\
                        " member to pool:%s" % (vm_info['vm_ip'], pool_id)
                    LOG.error(err_msg)
                    return "Problem while adding vm as member to pool."
                msg = "Member: %s with port:%s added to pool: %s" % (
                    vm_info['vm_ip'], port, pool_id)
                print msg
                LOG.info(msg)
                # Store the weigth in the vm itself. This will reflect
                # in the caller of this function also. Taking advantages of
                # mutable nature.
                vm_info['weight'] = weight

        # Check the status of the pool and vip after adding
        # the members to pool.
        def check_status(resource_name, resource_id):
            """ It checks the status of a resource"""
            status = lbaas_obj.poll_on_resource_status(
                name=resource_name,
                id=resource_id,
                status="ACTIVE",
                monitor_duration=120,
                negative_status="ERROR"
            )
            if not isinstance(status, str):
                LOG.error("Problem while polling on %s", resource_name)
                return "Problem while polling on %s" % resource_name
            if status.lower() != "active":
                err_msg = "%s with id:%s is NOt ACTIVE. Current state: %s"\
                    % (str(resource_name), str(id), str(status))
                LOG.error(err_msg)
                return err_msg
            msg = "The %s is Active after members are added to pool" % \
                resource_name
            print msg
            LOG.info(msg)
            return True

        # Check the status of Pool
        status = check_status("pool", pool_id)
        if not isinstance(status, bool):
            return status
        # Check the status of the vip.
        status = check_status("vip", vip_id)
        if not isinstance(status, bool):
            return status

        return weights
    except Exception as err:
        LOG.exception(err)
        return "Problem while adding member to pool."


def get_port_details(lib_os_obj, port_id):
    '''It returns the port detials (in dict). If the port is associated
    with floating ip then it also gets that and puts in the details.
    If the port is associated with a vm then it also gets the hostname of vm.

    :param lib_os_obj: Openstack library object
    :param port_id: Neutron Port ID.

    return: {port_id, fixed_ip, subnet_id, cidr, floating_ip(if any),
            vm_id and host_name (if any), etc}
    '''
    try:
        port = lib_os_obj.show_port(port_id)
        if not isinstance(port, dict):
            err_msg = "Problem while getting port details."
            LOG.error(err_msg)
            return err_msg

        port_info = {}
        port_info['port_id'] = port['id']

        fixed_ips = port["fixed_ips"][0]
        port_info['fixed_ip'] = fixed_ips["ip_address"]
        port_info['subnet_id'] = fixed_ips["subnet_id"]

        # Get the subnet cidr
        subnet_details = \
            lib_os_obj.get_subnet_details(subnet_id=port_info['subnet_id'])
        if not isinstance(subnet_details, dict):
            err_msg = "Problem while getting details"\
                " of subnet:%s" % port_info['subnet_id']
            LOG.error(err_msg)
            return str(err_msg)

        port_info['cidr'] = subnet_details['cidr']
        # Get floating ip, if any.
        floating_ip = lib_os_obj.get_floating_ip_by_port_id(port_id)
        if isinstance(floating_ip, unicode):
            port_info['floating_ip'] = floating_ip

# Get VM host name, if nova is the owner of this port
#         if port.get('device_id'):
#             vm_info = lib_os_obj.show_server(port['device_id'])
#             if not isinstance(vm_info, dict):
#                 err_msg = "Problem while getting vm details."
#                 LOG.error(err_msg)
#                 return err_msg
#             port_info['host_name'] = vm_info['OS-EXT-SRV-ATTR:host']

        # Get the host name if any host id is bound to this port.
        if port.get('binding:host_id'):
            port_info['host_name'] = port['binding:host_id']
            port_info['vm_id'] = port['device_id']

        return port_info
    except Exception as err:
        LOG.exception(err)
        return "Problem while getting port details!"


# TODO: (Kiran/Dilip) Add support to get stitching port details of,
# service vms with asav images. Currently only getting stitching
# port of service vm belonging to vyos & paloalto images is only supported.
def get_stitching_port_id(gbp_res_obj, lib_os_obj,
                          svm_id, provider_ptg_id):
    """Returns stitching port details.

    :param object gbp_res_obj: gbp_construct class object.
    :param object lib_os_obj: OpenstackLibrary class object.
    :param string svm_id: service vm uuid.
    :param string provider_ptg_id: provider port group id.

    :Returns: On Success: (True, stitching port id)
        On Failure: (False, string with err msg)
    """
    try:
        # get stitching subnet id by provider ptg id.
        stitching_subnet_id = None
        group_list = gbp_res_obj.list_policy_target_group()
        if group_list is None:
            err_msg = "Failed to list policy target groups."
            return (False, err_msg)
        for ptg in group_list:
            if ptg["proxied_group_id"] == provider_ptg_id:
                stitching_ptg_id = ptg['id']
                LOG.debug("Stitching ptg corresponding to provider:'%s' is:%s",
                          provider_ptg_id, stitching_ptg_id)
                if ptg['subnets']:
                    stitching_subnet_id = ptg['subnets'][0]
                    break

        # get stitching port details.
        stitching_port_id = None
        if stitching_subnet_id:
            interfaces_list = lib_os_obj.list_server_interfaces(svm_id)
            if interfaces_list is None:
                err_msg = "Nova interface list failed."
                return (False, err_msg)
            for iface in interfaces_list:
                if iface["fixed_ips"][0]["subnet_id"] == stitching_subnet_id:
                    stitching_port_id = iface["port_id"]
                    return (True, stitching_port_id)

        return (False, "Failed to get stitching port id.")
    except Exception as err:
        LOG.exception(err)
        return (False, "Some problem occured while getting "
                "stitching port details.")


# TODO: (Kiran/Dilip) Add support to get svm info if service image
# used is asav. Method supports only vyos & haproxy services.
def get_svm_basic_info(gbp_res_obj, lib_os_obj, provider_subnet_id,
                       service_type, provider_ptg_id):
    """It returns provider & stitching port id for service vm and service vm id

    :param object gbp_res_obj: gbp_construct class object.
    :param object lib_os_obj: OpenstackLibrary class object.
    :param string provider_subnet_id: subnet id of provider target group.
    :param string service_type: service type (FW/LB/VPN).
    :param string provider_ptg_id: provider ptg id.

    :Returns: On success tuple of containing active & standby svm details..
                e.g.
                    ({
                        "provider_port_id": None,
                        "service_vm_id": None,
                        "stitching_port_id": None
                    }, #active svm details
                    {
                        "provider_port_id": None,
                        "service_vm_id": None,
                        "stitching_port_id": None
                    } #standby service vm
                    )
        On failure returns string containing error message.
    """
    try:
        svm_details = {"provider_port_id": None,
                       "service_vm_id": None,
                       "stitching_port_id": None
                       }
        # Get provider port ip.
        subnet_info = \
            lib_os_obj.get_subnet_details(subnet_id=provider_subnet_id)
        if not isinstance(subnet_info, dict):
            err_msg = "Failed access details of provider "\
                "subnet: %s" % provider_subnet_id
            LOG.error(err_msg)
            return err_msg

        # TODO: (dilip), don't guess the vip, to identify the LB vm, in NFP
        # setups, we can see that the port that has non-empty
        # allowed_address_pairs field is the LB vm's fixed ip. But care should
        # be taken in neutron * as service set ups. Or better way is to
        # distinguish lb vm, the dns name of it has service chain instance id.
        # Or pass actual vip ip to this fun and distinguish.
        gateway_ip = subnet_info["gateway_ip"]

        if service_type.lower() == "lb":
            vip_ip = gateway_ip[:gateway_ip.rindex('.')] + ".254"

        port_list = lib_os_obj.list_port()
        if not isinstance(port_list, list):
            err_msg = "Some problem occurred while listing ports."
            LOG.error(err_msg)
            return err_msg

        for port in port_list:
            # get active fw service vm detials
            if service_type.lower() in ["fw", 'vpn'] and port['fixed_ips'] \
               and port['fixed_ips'][0]['subnet_id'] == provider_subnet_id \
               and port['fixed_ips'][0]['ip_address'] == \
               subnet_info["gateway_ip"]:
                svm_details['provider_port_id'] = port["id"]
                svm_details['service_vm_id'] = port["device_id"]
            # get lb active svm details.
            if service_type.lower() == "lb" and port["allowed_address_pairs"]\
               and port['fixed_ips'] and\
               port['fixed_ips'][0]['subnet_id'] == provider_subnet_id \
               and port["allowed_address_pairs"][0]["ip_address"] == vip_ip:
                svm_details["provider_port_id"] = port["id"]
                svm_details["service_vm_id"] = port["device_id"]

        if not any(svm_details.values()):
            err_msg = "Some problem while getting provider port details."
            LOG.error(err_msg)
            return err_msg

        # get stitching port id.
        if service_type.lower() in ["fw", "vpn"]:
            status, stitching_port_id = get_stitching_port_id(
                gbp_res_obj, lib_os_obj, svm_details["service_vm_id"],
                provider_ptg_id)
            if not status:
                return stitching_port_id
            svm_details["stitching_port_id"] = stitching_port_id
        # TODO: (Kiran/Dilip) get standby service vm details.
        # NOTE:- Standby services vms are not returned.
        # As currently servies HA is not supported in NFP.
        return (svm_details, None)
    except Exception as err:
        LOG.exception(err)
        return "Problem while getting provider port details"\
            " for service: %s" % service_type


def get_subnet_id_by_ptg_id(gbp_res_obj, lib_os_obj, ptg_id):
    """Returns provider subnet id

    :param object gbp_res_obj: Object of class gbp_construct
    :param object lib_os_obj: Object of class OpenstackLibrary
    :param string ptg_id: uuid of PTG.

    :Returns: On success (True, subnet_id)
        On Failure (False, error message)
    """
    try:
        ptg_info = gbp_res_obj.show_policy_target_group(ptg_id)
        if not ptg_info:
            err_msg = "Couldn't get details of ptg: %s" % ptg_id
            LOG.error(err_msg)
            return (False, err_msg)
        subnet_list = lib_os_obj.list_subnet()
        if not isinstance(subnet_list, list):
            LOG.error("Failed to list subnet.")
            return (False, "Failed to list subnet.")

        for subnet in subnet_list:
            if subnet['id'] in ptg_info["subnets"] and\
               subnet['tenant_id'] == lib_os_obj.project_info['project_id']:
                return (True, subnet['id'])
        return (False, "Failed to get subnet details for ptg: %s", ptg_id)
    except Exception as err:
        LOG.exception(err)
        return (False, "Problem while getting subnet id of ptg: %s." % ptg_id)


class Template(object):
    """A helper to get the customised template for lb, fw and vpn"""
    @staticmethod
    def _get_custom_fw_template_(**kwargs):
        """Prepares template for fw"""
        template_in_dict_form = copy.deepcopy(
            template_config.fw_template_base)
        resources = template_in_dict_form["resources"]
        fw_policy_rules = resources["Firewall_Policy"][
            "properties"]["firewall_rules"]
        fw_policy_rules.pop()
        
        #import pdb; pdb.set_trace()
        protocol = kwargs.get("protocol", "any")
        ports = kwargs.get("port", "").split(":")  # Also handles ICMP.
        if not protocol :
            return template_in_dict_form
        
        if len(ports) > 1:
            ports = range(int(ports[0]), int(ports[1]) + 1)

        for rule_index, port in enumerate(ports):
            rule_name = "Rule_%s" % (rule_index + 1)
            fw_policy_rules.append({"get_resource": rule_name})
            properties = {"action": "allow",
                          "enabled": True,
                          "protocol": protocol,
                          "name": rule_name}
            if protocol.lower() != "icmp" and ports:
                properties.update({"destination_port": str(port)})

            resources[rule_name] = {"type": "OS::Neutron::FirewallRule",
                                    "properties": properties}

        return template_in_dict_form

    @staticmethod
    def _get_custom_lb_template_(**kwargs):
        """Prepares template for lb"""

        if not kwargs.get("protocol"):
            LOG.warning("Pool protocol is NOT specified. Using default: HTTP")
        if not kwargs.get("port"):
            LOG.warning("Port for VIP is NOT specified. Using default: 80")
        if not kwargs.get('version'):
            LOG.warning("LB version is not specified. Using default V1")

        protocol = kwargs.get("protocol", "HTTP").upper()
        vip_port = int(kwargs.get("port", gbp_config.lb_member_port))
        mem_port = 443 if vip_port == 443 else gbp_config.lb_member_port

        version = kwargs.get("version", "V1").upper()
        if str(version) == "V2":
            template_in_dict_form = copy.deepcopy(
                template_config.lb_template_config_v2)
            params = template_in_dict_form["parameters"]
            params["lb_port"]["default"] = vip_port
            params["app_port"]["default"] = mem_port
            resources = template_in_dict_form["resources"]
            resources["pool"]["properties"]["protocol"] = protocol
            resources["listener"]["properties"]["protocol"] = protocol
            return template_in_dict_form

        # For LB version: 1
        template_in_dict_form = copy.deepcopy(
            template_config.lb_template_config)
        resources = template_in_dict_form["resources"]
        pool = resources["LoadBalancerPool"]['properties']
        pool["protocol"] = protocol
        pool["vip"]["protocol_port"] = vip_port
        # Update the port for the member. Use 80 if port is other than 443.
        resources["LoadBalancer"]["properties"]["protocol_port"] = mem_port

        return template_in_dict_form

    @staticmethod
    def _get_custom_vpn_template_(**kwargs):
        """Prepares template for vpn"""
        template_in_dict_form = copy.deepcopy(
            template_config.vpn_remote_template_config)

        if kwargs.get('vpn_type', "").lower() == "s2s":
            s2s = copy.deepcopy(template_config.vpn_s2s_connection)
            props = s2s["site_to_site_connection1"]['properties']

            vpn_srv_info = kwargs.get('vpn_server_info', None)
            if not vpn_srv_info:
                LOG.error("There is NO VPN server info.")
                return (False, "There is NO VPN server info.")
            if not kwargs.get('remote_client_info'):
                LOG.error("There is NO Client Info.")
                return (False, "There is NO Client Info.")

            props["psk"] = gbp_config.vpn_s2s_secret_key
            props["peer_address"] = vpn_srv_info['floating_ip']
            props["peer_id"] = vpn_srv_info['listen_iface']
            props["peer_cidrs"] = [kwargs['remote_client_info']['cidr']]

            resources = template_in_dict_form['resources']
            ike_policy = resources["IKEPolicy"]["properties"]
            ike_policy["encryption_algorithm"] = \
                gbp_config.vpn_handshake_encrypt_algos[0]
            ipsec_policy = resources["IPsecPolicy"]["properties"]
            ipsec_policy["encryption_algorithm"] = \
                gbp_config.vpn_handshake_encrypt_algos[0]

            # Append the site-to-site connection in the template.
            resources.update({s2s.keys()[0]: s2s.values()[0]})
        return template_in_dict_form

    @staticmethod
    def get_template_in_json_form(service_type, **kwargs):
        """
        It identifies the template based on the service_type,
        converts the template into json form and returns it.
        params:
            service_type: Type of service. Ex: vpn/fw/lb.
        Optional params:
                    (a) vpn_server_info, remote_client_info
                        The above two are required when service is a VPN.
                    (b) protocol, port. [For fw/lb]
                    (c) vpn_type: s2s/remote [for vpn only]
                    (d) version: 1/2 [for lb only]

        Return: Tuple containing the status and String.
                On Success: (True, Template in json (string))
                On Failure: (False, Error String)
        """
        try:
            if service_type.lower() == "fw":
                template_in_dict_form = \
                    Template._get_custom_fw_template_(**kwargs)
            elif service_type.lower() == "lb":
                template_in_dict_form = \
                    Template._get_custom_lb_template_(**kwargs)
            elif service_type.lower() == "vpn":
                template_in_dict_form = \
                    Template._get_custom_vpn_template_(**kwargs)
            else:
                err_msg = "ERROR: There is NO template for"\
                    " this service:%s" % service_type
                LOG.error(err_msg)
                return (False, err_msg)

            if not isinstance(template_in_dict_form, dict):
                return template_in_dict_form

            template_in_json = json.dumps(template_in_dict_form)
            LOG.debug("template_in_json: %s", template_in_json)
            return (True, template_in_json)

        except Exception as err:
            LOG.exception(err)
            return (False, "ERROR: Problem while getting the template "
                    "for service_type: %s." % service_type)


class GBPResourceHelper(object):
    """A wrapper on the GBP constructs"""
    def __init__(self, gbp_res_obj=None, project_id=None, lib_os_obj=None):
        self.gbp_res_obj = gbp_res_obj
        self.lib_os_obj = lib_os_obj
        self.project_id = project_id

        self.ext_pol_info = {}

    def get_external_policy(self, project_id, ext_segments):
        '''It returns the external policy (dict), if any, created under
        the current project. It stores the ext pol info in m/o.

        :param project_id: ID of the project.
        :param ext_segments: A list of external segments (ids)

        :return Dict on success.
        '''
        try:
            if not hasattr(self, 'ext_pol_info'):
                self.ext_pol_info = {}
            LOG.debug("External Segments received: %s", ext_segments)

            # Check, if already ext policy created for this project.
            if self.ext_pol_info.get(project_id):
                # Check whether same external segment is there or not.
                for info in self.ext_pol_info[project_id]:
                    if not len(set(info['seg']) - set(ext_segments)):
                        # Reuse the ext policy.
                        ext_policy = info['pol']
                        LOG.debug("Reusing the external policy: %s",
                                  ext_policy['id'])
                        return ext_policy

#             ext_pols = self.gbp_res_obj.list_external_policy()
#             if not isinstance(ext_pols, list):
#                 LOG.info("Probelm while getting ext policy.")
#                 return "Probelm while getting ext policy."
#             for ext_pol in ext_pols:
#                 if ext_pol['tenant_id'] == project_id:
#                     LOG.debug("Ext policy for project id:%s is %s" %
#                                   (project_id, ext_pol))
#                     return ext_pol
#             else:
#                 msg = ("There is no external policy created in project: %s" %
#                        project_id)
#                 LOG.debug(msg)
#                 return msg
        except Exception as err:
            LOG.exception(err)
            # return "Problem while getting external policy."

    def create_srvc_chain_node_helper(self, service_type, **kwargs):
        """
        This creates the service chain node based on the service_type.
        param:
            service_type: Type of service. Ex: Firewall(fw), VPN(vpn) or
                    Load balancer (lb) service.
        Optional params:
                (a) node_name: Name of the service chain node.
                (b) vpn_server_info (for s2s only), remote_client_info,
                    vpn_type. [for vpn service]
                    vpn_server_info = {'floating_ip': <floating ip>,
                                       'listen_iface': <fixed ip>}
                    remote_client_info = {cidr:""}
                    vpn_type: s2s/remote.
                (d) protocol, port. [for fw and lb service]
                    For fw, this is temporarily used to create allow action
                    on top of the redirect classifier,
                (e) shared: Whether this is sharable or NOT
                (f) vpnfw_service_image: asav, vyos, paloalto.
                       # for chains containing vpn or fw images.
                (g) service_ha = True, if this service is to be inserted in HA
                (h) version: V1/V2 [optional, required only for LB node]
        """
        try:
            # NOTE: This is a temporary fix. No protocol other than tcp, udp
            # and icmp is supported. So create the classifier with tcp/udp/icmp
            #import pdb; pdb.set_trace()
            if not kwargs.get('protocol'):
                kwargs['protocol'] = ""
            elif kwargs.get('protocol', "").lower() in ['tcp', 'http', 'https',
                                                      'smtp', 'ftp']:
                kwargs['protocol'] = "tcp"
            if kwargs.get('protocol', "").lower() in ["dns"]:
                kwargs['protocol'] = "udp"

            # Get the template for this service_type
            status_string = \
                Template.get_template_in_json_form(service_type, **kwargs)
            if not status_string[0]:
                return status_string[1]
            kwargs['config'] = status_string[1]

            # kwargs['service_type'] = service_type
            name = kwargs.get('node_name', "_node_" + service_type)

            # Get the service profile ID
            if service_type.lower() == 'lb':
                key = service_type.lower()
                if kwargs.get("version"):
                    key += "_" + kwargs.get("version").lower()
                if kwargs.get('service_ha'):
                    key += "_ha"
                sp_name = config.service_profile_names[key]
            else:
                service_image = kwargs.get("vpnfw_service_image", "vyos")
                key = service_image.lower() + "_" + service_type.lower()
                # Service HA is there then use the ha profile.
                if kwargs.get('service_ha'):
                    key += "_ha"
                sp_name = config.service_profile_names[key]

            service_profile = self.gbp_res_obj.get_service_profile(sp_name)
            if not isinstance(service_profile, dict):
                err_msg = "Problem while getting details of"\
                    " service profile: %s" % sp_name
                LOG.error(err_msg)
                return err_msg
            kwargs['service_profile_id'] = service_profile['id']
            # Create the chain node.
            chain_node = self.gbp_res_obj.create_service_chain_node(
                name, **kwargs)
            if not isinstance(chain_node, dict):
                err_msg = "Problem while creating service-chain-node for %s"\
                    % service_type
                LOG.error(err_msg)
                return err_msg

            LOG.info("Service-chain-node %s is created successfully."
                     " ID: %s", name, chain_node['id'])
            return chain_node
        except Exception as err:
            LOG.exception(err)
            return "Problem during creation of Servie Chain Node."

    def create_srvc_chain_spec_helper(self, node_ids, **kwargs):
        """It creates the service chain spec from the nodes list.
        params:
            node_ids: Service Chain Nodes passed as list.
        Optional params:
            spec_name: Name of the service chain spec.,
            shared: Whether this is sharable or NOT
        Return:
            Dict containing the service chain spec info, on success.
        """
        try:
            if not isinstance(node_ids, list):
                return "node(s) must be passed as list."

            kwargs['nodes'] = node_ids
            name = kwargs.get('spec_name', "_spec")

            # Create the service chain spec.
            spec = self.gbp_res_obj.create_service_chain_spec(name, **kwargs)
            if not isinstance(spec, dict):
                err_msg = "Problem while creating the service chain"\
                    " spec: %s" % name
                LOG.error(err_msg)
                return err_msg
            LOG.info("Service chain spec :%s is created"
                     "successfully. ID: %s", name, spec['id'])
            return spec
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating the service chain spec."

    def create_policy_action_helper(self, action_type, action_value=None,
                                    **kwargs):
        """
        It creates the policy action.
        params:
            action_type: Type of action. Ex: redirect, allow, etc.
        Optional params:
            act_name: Name of the policy action.
            action_value: Basically service chain spec ID.
                        [required when action type is redirect]
        Return:
            Dict containing the policy action info, on success.
        """
        try:
            name = kwargs.get('act_name', 'action_' + action_type)
            kwargs['action_type'] = action_type

            if action_type.lower() == "redirect":
                if not action_value:
                    err_msg = "There is NO service chain spec id for the"\
                        " redirect action!"
                    LOG.error(err_msg)
                    return err_msg
                kwargs['action_value'] = action_value

            # Create the action
            action = self.gbp_res_obj.create_policy_action(name, **kwargs)

            if not isinstance(action, dict):
                err_msg = "Problem while creating policy_action for :%s"\
                    % action_type
                LOG.error(err_msg)
                return err_msg
            LOG.info("Policy Action: %s is created successfully. ID:%s",
                     name, action['id'])

            return action
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating policy action."

    def create_policy_classifier_helper(self, classifier, **kwargs):
        """
        It creates the policy classifier.
        params:
            classifier: {direction:"", protocol:"", ports:""}
            NOTE: 'ports' in clasifier is optional.
        Optional params:
            classifier_name: name of the classifier.

        Note: For single port, pass as a string. Ex: "80"
                and for ports pass as  "min:max". Ex: "80:85"

        Return: classifier dict on success,
                String on failure.
        """
        try:
            kwargs['direction'] = classifier['direction'].lower()
            if classifier.get('protocol'):  # Optional for special scenarios.
                kwargs['protocol'] = classifier['protocol'].lower()
            if classifier.get('ports'):
                kwargs['port_range'] = classifier['ports']

            if kwargs.get('protocol', "") == "icmp" and\
                    kwargs.get('port_range'):
                kwargs.pop('port_range')

            name = kwargs.get('classifier_name', "classifier_" +
                              kwargs.get('protocol', ""))
            # NOTE: This is a temporary fix. No protocol other than tcp, udp
            # and icmp is supported. So create the classifier with tcp/udp/icmp
            if kwargs.get('protocol', "") in ['http', 'https', 'smtp', 'ftp']:
                kwargs['protocol'] = "tcp"
            elif kwargs.get('protocol', "") in ["dns"]:
                kwargs['protocol'] = "udp"

            # Create Classifier
            classifier = self.gbp_res_obj.create_policy_classifier(name,
                                                                   **kwargs)
            if not isinstance(classifier, dict):
                err_msg = "Problem while creating policy classifier."
                LOG.error(err_msg)
                return err_msg
            LOG.info("Policy classifier:%s is created successfully. ID:%s",
                     name, classifier['id'])

            return classifier
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating classifier"

    def create_policy_rule_helper(self, action_ids, classifier_id, **kwargs):
        """
        It creates the Policy Rule.
        params:
            action_ids: A list of policy action ids.
            classifier_id: A Policy classifier id.
        Optional params:
            rule_name: Name of the policy rule.
        Return:
            Dict containing the policy rule, on success.
        """
        try:
            if not isinstance(action_ids, list):
                return "Action ID(s) must be passed as a list"

            name = kwargs.get('rule_name', "rule")
            kwargs['policy_actions'] = action_ids
            kwargs['policy_classifier_id'] = classifier_id
            # Create rule
            rule = self.gbp_res_obj.create_policy_rule(name, **kwargs)
            if not isinstance(rule, dict):
                LOG.error("Problem while creating policy rule: %s", name)
                return "Problem while creating policy rule."
            LOG.info("Policy rule: %s is created successfully. ID: %s",
                     name, rule['id'])
            return rule
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating policy rule."

    def create_policy_rule_set_helper(self, rule_ids, **kwargs):
        """
        It creates the Policy Rule Set.
        params:
            rule_ids: A list of policy rule ids
        Optional params:
            rule_set_name: Name of the policy rule set.
        Return:
            Dict containing the policy rule set info, on success.
        """
        try:
            if not isinstance(rule_ids, list):
                return "Rule Ids must be in list."

            name = kwargs.get('rule_set_name', "rule_set")
            kwargs['policy_rules'] = rule_ids
            # Create rule set
            rule_set = self.gbp_res_obj.create_policy_rule_set(name, **kwargs)
            if not isinstance(rule_set, dict):
                err_msg = "Problem while creating policy rule set: %s" % name
                LOG.error("Problem while creating policy rule set.")
                return err_msg
            LOG.info("Policy rule set: %s is created successfully. ID: %s",
                     name, rule_set['id'])
            return rule_set
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating policy rule set."

    def create_nw_srvc_policy_helper(self, **kwargs):
        """
        This creates the network service policy.
        Optional params:
            traffic_type: Type of traffic (n-s/e-w)
            nw_srvc_pol_name: Name of the network service policy.
            param_type: Type: Type of Parameter (default: ip_single),
            param_name: Name of parameter (default: vip_ip),
            param_value: Value of parameter (default: self_subnet)
        Return:
            Dict containing the network service policy info, on success.
        """
        try:
            name = kwargs.get('nw_srvc_pol_name', "nsp")
            param_type = kwargs.get('param_type', 'ip_single')
            param_name = kwargs.get('param_name', 'vip_ip')
            param_value = kwargs.get('param_value', 'self_subnet')

            kwargs['network_service_params'] = [{"type": param_type,
                                                 "name": param_name,
                                                 "value": param_value}]
            # Create network service policy.
            nsp = self.gbp_res_obj.create_network_service_policy(name,
                                                                 **kwargs)
            if not isinstance(nsp, dict):
                LOG.error("Problem while creating"
                          " Network Service Policy: %s", name)
                return "Problem while creating Network Service Policy."
            LOG.info("Network Service Policy :%s is created. ID: %s",
                     name, nsp['id'])
            return nsp

        except Exception as err:
            LOG.exception(err)
            return "Problem while creating Network service policy."

    def create_policy_tgt_group_helper(self, rule_set_ids,
                                       group_type="provider", **kwargs):
        """
        It creates the Policy target Group.
        params: rule_set_ids: A list of policy rule set ids.
              group_type: A policy target group type.
                    value: provider/consumer. [Default is provider]
                    (OR any sring containing either consumer or provider)
        Optional params:
            pg_name: Name of the policy target group.
            nsp_id: network service policy id.
            l2_policy_id: l2 policy id
        Return:
            Dict containing the policy target group info, on success.
        """
        try:
            rule_sets = {}
            if not isinstance(rule_set_ids, list):
                return "Rule set ids must be a list of rule sets."
            for rule_set_id in rule_set_ids:
                rule_sets[rule_set_id] = rule_set_id

            name = kwargs.get("pg_name", group_type)
            if "consumer" in group_type.lower():
                kwargs['consumed_policy_rule_sets'] = rule_sets
            else:
                kwargs['provided_policy_rule_sets'] = rule_sets

            kwargs['network_service_policy_id'] = kwargs.get('nsp_id', None)
            kwargs['l2_policy_id'] = kwargs.get('l2_policy_id', None)

            pt_group = self.gbp_res_obj.create_policy_target_group(name,
                                                                   **kwargs)
            if not isinstance(pt_group, dict):
                err_msg = "Problem while creating Policy Target Group: %s"\
                    % group_type
                LOG.error(err_msg)
                return err_msg
            LOG.info("Policy Target Group: %s is created "
                     "successfully. ID: %s", name, pt_group['id'])
            return pt_group
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating Policy Target Group."

    def create_policy_target_helper(self, no_of_targets, ptg_id, **kwargs):
        """
        It creates the policy target(s) in a policy target group.
        params:
            no_of_targets: No. of policy targets to create.
            ptg_id: This will be the consumer/provoder group ID
        Optional params:
            policy_target_group_name

        Return: On success: A list of target(s) info.
                     Ex: [{target1 info}, {}, ...]
                On failure: String containing error message.
        """
        try:
            targets = []
            for target_no in range(1, no_of_targets + 1):
                target_name = "target_" + str(target_no)
                name = kwargs.get('policy_target_group_name',
                                  str(ptg_id)[:5]) +\
                    "_" + target_name
                kwargs['policy_target_group_id'] = ptg_id
                # Create the target
                target = self.gbp_res_obj.create_policy_target(name, **kwargs)
                if not isinstance(target, dict):
                    err_msg = "Problem while creating the target for target "\
                        "group: %s." % str(ptg_id)
                    LOG.error(err_msg)
                    return err_msg
                LOG.info("Target: %s is created in ptg: %s successfully.",
                         target['id'], ptg_id)
                # Get the port_ip and mac from the port_id of the target.
                port_details = self.lib_os_obj.show_port(target['port_id'])
                if not isinstance(port_details, dict):
                    err_msg = "Unable to get the details of Port: %s" % \
                        str(target['port_id'])
                    LOG.error(err_msg)
                    return err_msg
                LOG.debug("Port details: %s for target: %s",
                          port_details, target['id'])

                target["vm_ip"] = port_details["fixed_ips"][0]["ip_address"]
                # target["port_mac"] = port_details["mac_address"]
                target["subnet_id"] = port_details["fixed_ips"][0]["subnet_id"]
                target["network_id"] = port_details["network_id"]
                target['ptg_name'] = name
                targets.append(target)
                # targets.append(target['vm_ip'])

            LOG.info("All targets: %s", targets)

            return targets
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating policy target."

    def create_ext_policy_helper(self, ext_segment_names, rule_set_ids,
                                 group_type="consumer", **kwargs):
        """
        It creates the external policy.
        params:
            ext_segment_names: A list of external segment names.
                    Note: This is not required if ext_segment_ids is given.
            rule_set_ids: A list of policy rule set.
        Optional params:
            ext_pol_name: Name of the external policy.
            group_type: Type of group. Is this a consumer or provider.
            ext_segment_ids: A list of IDs of the external segment.
            project_id: ID of the project.

        Return: Dict, containing the ext policy details, on success.
        """
        try:
            project_id = kwargs.get('project_id', self.project_id)
#             if not hasattr(self, 'old_rule_set_ids'):
#                 self.old_rule_set_ids = []
#
#             self.old_rule_set_ids += rule_set_ids
#             rule_set_ids = self.old_rule_set_ids

            rule_sets = {}
            if not isinstance(rule_set_ids, list):
                LOG.error("Rule set ids must be a list of rule sets.")
                return "Rule set ids must be a list of rule sets."
            for rule_set_id in rule_set_ids:
                rule_sets[rule_set_id] = rule_set_id

            key = 'consumed_policy_rule_sets'
            if "provider" in group_type.lower():
                key = 'provided_policy_rule_sets'
            kwargs[key] = rule_sets

            ext_segment_ids = kwargs.get('ext_segment_ids', [])
            if not ext_segment_ids:
                if not isinstance(ext_segment_names, list):
                    ext_segment_names = [ext_segment_names]
                # Get external segment details by name.
                for ext_segment_name in ext_segment_names:
                    ext_segment_details = \
                        self.gbp_res_obj.get_external_segment(ext_segment_name)
                    if not isinstance(ext_segment_details, dict):
                        return ext_segment_details
                    ext_segment_ids.append(ext_segment_details['id'])

            # Check, if already ext policy created for this project.
            ext_policy = \
                self.get_external_policy(project_id, ext_segment_ids)
            if isinstance(ext_policy, dict):
                # Reuse the ext policy and update the new prs ids.
                # Include old prs, if any.
                for prs_id in ext_policy[key]:
                    kwargs[key].update({prs_id: prs_id})

                ext_policy = self.gbp_res_obj.update_external_policy(
                    ext_policy['id'], **kwargs)
                if not isinstance(ext_policy, dict):
                    err_msg = "Problem while updating the ext policy."
                    LOG.error(err_msg)
                    return err_msg
                return ext_policy

            print "Creating external policy ..."
            LOG.info("Creating external policy ...")

            kwargs['external_segments'] = ext_segment_ids
            name = kwargs.get('ext_pol_name', "%s_ext_policy" % group_type)

            ext_policy = self.gbp_res_obj.create_external_policy(name,
                                                                 **kwargs)
            if not isinstance(ext_policy, dict):
                LOG.error("Problem while creating the external policy:%s",
                          name)
                return "Problem while creating the external policy."

            LOG.info("External Policy:%s is created. ID:%s",
                     name, ext_policy['id'])
            # Store the ext pol info corresponding to the project.
            info = {'seg': ext_segment_ids, 'pol': ext_policy}
            if not self.ext_pol_info.get(project_id):
                self.ext_pol_info[project_id] = []
            self.ext_pol_info[project_id].append(info)

            return ext_policy
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating external policy."


class GbpResourceCreator(GBPResourceHelper):

    """This creates the resources for GBP.
    The resources are service-chain-node, service-chain-spec,
    policy-action, policy-classifier, policy-rule, policy-rule-set,
    policy-target-group, policy-target, etc ...
    """

    def __init__(self, lib_os_obj):
        """
        lib_os_obj: Openstack Library object.
        """
        GBPResourceHelper.__init__(self)
        self.tokens = {
            'tenant': lib_os_obj.project_info['token_project'],
            'admin': lib_os_obj.cloud_admin_info['token_project']
        }
        # self.db_obj = AccessDb()
        self.lib_os_obj = lib_os_obj
        self.project_name = lib_os_obj.project_info['project_name']
        self.project_id = lib_os_obj.project_info['project_id']
        self.gbp_res_obj = gbp_construct(self.tokens['tenant'],
                                         lib_os_obj.host_ip)
        self.heat_lib_obj = HeatLibrary(
            lib_os_obj.host_ip, self.project_id, self.tokens['tenant'])
        self.lbaas_obj = LbaasLib(self.tokens['tenant'],
                                  lib_os_obj.host_ip)
        # Keep track of service chain count.
        self.service_chain_count = 0

    @decorator
    def increase_chain_count(fun, *args, **kwargs):  # @NoSelf
        """A decorator to increase the chain count."""
        try:
            # Check if service chain is there
            if args[1].get('service_chain_nodes'):
                args[0].service_chain_count += 1

            return fun(*args, **kwargs)
        except Exception as err:
            LOG.error(err)

    # @decorator
    # def __set_context__(fun, self, lib_os_obj, **kwargs):  # @NoSelf
    def __set_context__(self, lib_os_obj, **kwargs):
        '''It sets the context to the new tenant.
        :param lib_os_obj: Openstack library object.
        '''
        if not lib_os_obj:
            return None

        old_lib_os_obj = self.lib_os_obj
        new_project_name = lib_os_obj.project_info['project_name']

        # Check if it is old project.
        if new_project_name != self.project_name:
            self.lib_os_obj = lib_os_obj
            self.tokens['tenant'] = lib_os_obj.project_info['token_project']
            self.project_name = new_project_name
            self.project_id = lib_os_obj.project_info['project_id']

            self.gbp_res_obj.token = self.tokens['tenant']
            self.heat_lib_obj.tenant_id = self.project_id
            self.heat_lib_obj.tenant_token = self.tokens['tenant']

            self.lbaas_obj.token = self.tokens['tenant']

        return old_lib_os_obj
        # return fun(self, lib_os_obj, **kwargs)

    @contextmanager
    def my_project_context(self, lib_os_obj, **kwargs):
        """It changes the context to a new context and then reverts back once
         the work is done.
         NOTE: Example (How to use this).
             Say, this will be called from method xx().

               def xx(self):
                   # Now do work outside the context
                   ...

                   # Now perform your task specific to the new context.
                   with self.my_project_context(lib_os_obj):
                       ...
                       self.get_inserted_services(..)
                       self.add_ptg_members(...)
                       self.lib_os_obj.list_net(...)
                       ...

                   # Now do work outside the context
                   ...
         """
        try:
            old_context = self.lib_os_obj
            # Set the context
            self.__set_context__(lib_os_obj, **kwargs)
            yield
        finally:
            # Unset the context
            self.__set_context__(old_context, **kwargs)

    @staticmethod
    def is_service_in_chain(service_type, service_chain_nodes):
        """
        This checks whether the service[vpn/fw/lb] is part of the
        chain or not.
        params:
            service_type: Type of the service (vpn/fw/lb).
            service_chain_nodes: A list of service chain nodes (dict).
                               service_type is one of the key in each dict.
        Return:
            True on success.
        """
        try:
            for node in service_chain_nodes:
                if service_type.lower() in node['service_type'].lower():
                    return True
            return False

#             _lm = lambda service_type: service_type.lower() in \
#                 [service['service_type'] for service in service_chain_nodes]
#             return _lm(service_type)

        except Exception as err:
            LOG.exception(err)
            return False

    @staticmethod
    def get_inserted_services(gbp_resources, service_type=""):
        """It gets the services list that are inserted in between the
        consumer/ext and provider. If a service tyupe is passed then it
        returns that service in the list."""
        try:
            for rule in gbp_resources['policy_rule_set']['policy_rules']:
                if rule['action'].get('service_chain'):
                    services = rule['action']['service_chain']['services']
                    if not service_type:
                        return services
                    return [service for service in services if service[
                        'service_type'].lower() == service_type.lower()]

            return "There is NO services inserted!"
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting service chain details."

    @staticmethod
    def add_allow_rules(gbp_resource_info):
        """It adds an allow rule with a clasifier having any protocol
        and port to the input dict, INPLACE.

        params:
            gbp_resource_info: The gbp resource input dictionary that is
            passed to create_gbp_resources().
        Return: Bool.
            True on success, False on failure.
        """
        try:
            policy_rules = gbp_resource_info.get('policy_rules', [])
            if not policy_rules:
                gbp_resource_info.update({'policy_rules': policy_rules})

            policy_rules.append({'policy_classifier': {'direction': "bi"},
                                 'policy_action_type': "allow"})
            return True
        except Exception as err:
            LOG.exception(err)
            return False

    @staticmethod
    def get_ha_vip(stack_detail):
        """It gets the ha_vip_fip (vip fip of the service vm).
        This info can be found in the stack setails of the service node.

        :param stack_detail: The stack show o/p dict of a specific service.
        :return A tuple containing the status and the vip fip, vip fixed ip.
        """
        try:
            svc_desc = stack_detail['parameters'].get('ServiceDescription')
            if not svc_desc:
                err_msg = "There is no HA VIP for the service."
                LOG.error(err_msg)
                return (False, err_msg)
            ha_vip_fip = re.search('user_access_ip=(.+?);', svc_desc).group(1)
            ha_vip_fix = re.search('fixed_ip=(.+?);', svc_desc).group(1)

            LOG.info("HA VIP FIP: %s Fix IP: %s", ha_vip_fip, ha_vip_fix)
            return (True, ha_vip_fip, ha_vip_fix)
        except Exception as err:
            LOG.exception(err)
            return (False, "Problem while getting the HA VIP")

    @staticmethod
    def prepare_for_remote_config(srvc_details, chain_index=0,
                                  vpnfw_image_vendor="vyos", vpn_type="s2s"):
        """It decides which fixed ip and floating ip of the cloud vpn service
         (both for HA and non-HA )to use for configuring the remote site
         server/client. It changes the input dict with required info INPLACE.

         :param srvc_details: Services details as given by  get_svm_info
         :param vpnfw_image_vendor: The name of the vpn/fw image vendor.
         """
        # For HA, use the ha_vip_fip as the fip for both listen_iface
        # (peer_id) and fip(peer_address). If asav in the cloud then use the
        # ha_vip_fip in peer_address and ha_vip_fip's fixed ip as
        # listen iface. This is b'coz we are using the remote vyos vpn.

        # Get the svc chain's stitching interfaces of the service vm.
        vpn_srvc_ifaces = \
            srvc_details['consumer_provider_interfaces'][chain_index][0]

        if srvc_details.get('ha_vip_fip'):
            vpn_srvc_ifaces['floating_ip'] = srvc_details['ha_vip_fip']

        if vpn_type.lower() != "s2s":
            return
        # Change the listen iface (peer id) accordingly.
        if vpnfw_image_vendor.lower() in ["vyos", "paloalto"]:
            vpn_srvc_ifaces['listen_iface'] = vpn_srvc_ifaces['floating_ip']

        elif vpnfw_image_vendor.lower() == "asav":
            vpn_srvc_ifaces['listen_iface'] = srvc_details['ha_vip_fix'] if \
                srvc_details.get('ha_vip_fix') else vpn_srvc_ifaces['fixed_ip']

    def get_network_info(self, ids, id_type="ptg"):
        """
        It gets the network info for the given ids. The nw info is a dict
        that contains the nw name and id.
        param:
            ids: A list of ids (ptg ids/nw ids of ptgs).
        Optional:
            id_type: Type of id. Values:ptg/net. Port Group id or network id.

        Return: On success, a list of dict.
            The order of dicts is same as the order of the ids in the
            input list (ids).
        """
        try:
            networks_info = []
            for _id in ids:
                net_id = _id
                if id_type == "ptg":
                    # Get one of the subnet id of the ptg
                    ptg_details = self.gbp_res_obj.show_policy_target_group(
                        _id)
                    if not isinstance(ptg_details, dict):
                        err_msg = "Problem while getting details of ptg: %s"\
                            % _id
                        LOG.error(err_msg)
                        return err_msg
                    # Get the n/w id from one of the subnets.
                    subnet_id = ptg_details['subnets'][0]
                    subnet_details = self.lib_os_obj.get_subnet_details(
                        subnet_id=subnet_id)
                    if not isinstance(subnet_details, dict):
                        err_msg = "Problem while getting details"\
                            " of subnet:%s" % subnet_id
                        LOG.error(err_msg)
                        return err_msg
                    net_id = subnet_details['network_id']

                # Get the network details.
                net_details = self.lib_os_obj.get_net_details(net_id=net_id)
                if not isinstance(net_details, dict):
                    err_msg = "Problem while getting details of net: %s"\
                        % net_id
                    LOG.error(err_msg)
                    return err_msg

                LOG.info("Name of the network for id: %s of type: %s "
                         "is:%s", _id, id_type, net_id)
                networks_info.append({'name': net_details['name'],
                                      'id': net_id})

            return networks_info
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting network name."

    def get_svm_info(self, service_type, provider_ptg_ids, **kwargs):
        """It gets all the consumer(stitching), provider interface info of a
        service vm. If HA is there then it also gets the corresponding
        details of the stand-by service vm.

        The service vm info retrieval depends on the provider ptg id. For each
        provider ptg id in the provider_ptg_ids, it will get the corresponding
        service vm details and put them in a list.

        Each service vm info is a tuple containing the stitching and provider
        interfaces info (dict) is placed in the list. In this list, the order
        of the svm info corresponding to a provider ptg id is based on the
        order in which the provider ptg ids are passed to this method.

        NOTE:
        =====
        For backward compartability, the standby service vm info, if any, is
        also placed in outer dictionary in the same format as that of the
        Active service vm.

        :params:
            :param project_id: ID of the project.
            :param service_type: Type of service (vpn/fw/lb).
            :param provider_ptg_ids: A list of Providers PTG ids.
                   NOTE: For the latest release, there is only one provider
                        for a set of consumers per one service chain.
                        The set of consumers is also represented by only one
                        stitching port.
        :Optional:
            :param vpnfw_service_image: vyos / asav / paloalto. default vyos.
                    This is used for service type (fw/vpn)
            :param service_ha: A boolean flag which tells whether
                   the service vm is in HA or not. Default is False.
        :return: Dict on success.
                String on failure.

            Ex: {
                    consumer_provider_interfaces: [
                            ( # For provider PTG 1
                                {consumer interface details},
                                {provider interface details}
                            ),
                            ( # For Provider PTG 2 ), ...
                    ],
                    standby_consumer_provider_interfaces: [({}, {}), ()],
                }
            NOTE: consumer_provider_interfaces:
                      It is a list of tuples. Each tuple is for each ptg id.
                      The tuple is the consumer(stitching) and provider
                      interfcases details corresponding to a provider in the
                      provider_ptg_ids. The order of items in the list is same
                      as the order of ids in the provider_ptg_ids.

                  standby_consumer_provider_interfaces:
                      This corresponds the standby service vm, if HA is there.
                      It has the same format as that of the active vm
                      (consumer_provider_interfaces).
        """
        try:
            old_project_info = None
            service_type = service_type.lower()

            fw_image_vendor = kwargs.get("vpnfw_service_image", "vyos").lower()
            service_ha = kwargs.get('service_ha', False)

            """
            # NOTE: The admin/services tenant can only see all the vms,
            # provided all_tenants flag is set.
            # Get admin tenant's ID.
            admin_project_id = self.lib_os_obj.cloud_admin_info['project_id']
            # NOTE: Get the v3 token of admin with project scope.
            admin_token = self.lib_os_obj.cloud_admin_info['token_project']
            # Set the tenant's token as admin's token (cloud admin)
            # and once the work is done restore back the old token.
            old_project_info = self.lib_os_obj.set_tenant_info(
                config.cloud_admin_project, admin_token,
                admin_token, admin_project_id)

            # restore back the old token.
            # self.lib_os_obj.set_tenant_info(*old_project_info)
            """

            # Get the ip details.
            svm_ip_info = {}
            svm_ip_info['consumer_provider_interfaces'] = []
            if service_ha:
                svm_ip_info['standby_consumer_provider_interfaces'] = []

            # _svc_type = "FIREWALL"
            # if service_type == "vpn":
            #    _svc_type = "VPN"
            # elif service_type == "lb":
            #    _svc_type = "LOADBALANCER"

            def get_vm_info(svm_basic_info):
                """It gets the vm info in details in a tuple.
                The 1st item in tuple is the consumer interface info and 2nd
                item is that of provider. Each info includes the interface ip,
                floating ip, if any, subnet cidr, vm host name etc."""

                svm_port_ids = [None, svm_basic_info['provider_port_id']]
                # NOTE: LB doesn't have stitching/consumer side interface.
                if service_type.lower() != "lb":
                    svm_port_ids[0] = svm_basic_info['stitching_port_id']

                cons_prov_ifaces = [None, None]  # [Stitching, Provider]
                # Get the port details: fixed_ip, fip (if any), cidr, etc
                for index, port_id in enumerate(svm_port_ids):
                    if port_id is None:
                        cons_prov_ifaces[index] = None
                        continue
                    # Get the Port details.
                    port_details = get_port_details(self.lib_os_obj, port_id)
                    if not isinstance(port_details, dict):
                        return port_details

                    # NOTE: For ASAV case, we capture traffic on the plugged in
                    # provider port (an interface of SVM). In this case traffic
                    # doesn't come on the mapped_real_port - (a port on
                    # provider nw). Also for VPN case we need the cidr of the
                    # provider side (mappeed..) not this plugged_in_port's cidr
                    if service_type.lower() != "lb" and index and \
                            fw_image_vendor == "asav":
                        # We need to get the host name, based on the port.
                        # We avoid using nova, otherswise we can get from vm id
                        plg_port_details = get_port_details(
                            self.lib_os_obj,
                            svm_basic_info['plugged_in_provider_port_id'])
                        if not isinstance(plg_port_details, dict):
                            return port_details
                        plg_port_details['cidr'] = port_details['cidr']
                        plg_port_details['provider_port_id'] = port_id
                        port_details = plg_port_details

                    # Store corresponding port detials
                    cons_prov_ifaces[index] = port_details

                return tuple(cons_prov_ifaces)

            # Prepare the consumer(stitching) and provider interface in pairs
            # for each provider. The result will be a list of tuples.
            for provider_ptg_id in provider_ptg_ids:
                # get provider_subnet.
                status, provider_subnet_id = get_subnet_id_by_ptg_id(
                    self.gbp_res_obj, self.lib_os_obj, provider_ptg_id)
                if not status:
                    return provider_subnet_id

                # Poll for the Active status of the svms
                # Poll on the status of the server to become Active/ERROR
                # NOTE: The admin/services tenant can only see all the vms,
                # provided all_tenants flag is set.
                # Get admin tenant's ID.
                admin_project_id = self.lib_os_obj.\
                    cloud_admin_info['project_id']
                # NOTE: Get the v3 token of admin with project scope.
                admin_token = self.lib_os_obj.cloud_admin_info['token_project']
                # Set the tenant's token as admin's token (cloud admin)
                # and once the work is done restore back the old token.
                old_project_info = self.lib_os_obj.set_tenant_info(
                    config.cloud_admin_project, admin_token,
                    admin_token, admin_project_id)
                # Surendar - changing context of token
                old_token = self.gbp_res_obj.token
                self.gbp_res_obj.token = admin_token

                svms_basic_info = get_svm_basic_info(
                    self.gbp_res_obj, self.lib_os_obj, provider_subnet_id,
                    service_type, provider_ptg_id)
                if not isinstance(svms_basic_info, tuple):
                    return svms_basic_info

                LOG.debug("SVM basic info: %s", str(svms_basic_info))

                for index, svm_basic_info in enumerate(svms_basic_info):
                    if svm_basic_info is None:
                        continue
                    status = self.lib_os_obj.poll_for_active_status(
                        svm_basic_info["service_vm_id"])
                    if status is None:
                        err_msg = ("Problem while polling on %s svm: %s" %
                                   (svm_basic_info["service_vm_id"],
                                    service_type))
                        LOG.error(err_msg)
                        return err_msg
                    if status.lower() != "active":
                        err_msg = ("The status of %s svm: %s is NOT active."
                                   "Current status: %s" %
                                   (svm_basic_info["service_vm_id"],
                                    service_type, str(status)))
                        LOG.error(err_msg)
                        return err_msg

                # Get the services detailed info.
                # svms_basic_info: ({active}, {standby})
                for index, svm_basic_info in enumerate(svms_basic_info):
                    if svm_basic_info is None:
                        continue
                    _vm_info = get_vm_info(svm_basic_info)
                    if not isinstance(_vm_info, tuple):
                        return _vm_info

                    # Store the stitching and provider interface pairs of a svm
                    if not index:  # Active SVM
                        svm_ip_info['consumer_provider_interfaces'
                                    ].append(_vm_info)
                    else:  # Stand by svm.
                        svm_ip_info['standby_consumer_provider_interfaces'
                                    ].append(_vm_info)

            LOG.debug("Service VM(s) info: %s", svm_ip_info)
            return svm_ip_info
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting service vm info."
        finally:
            # NOTE: Don't use return statement here.
            # Unset the context, if changed at all.
            if old_project_info:
                self.lib_os_obj.set_tenant_info(*old_project_info)
                # Surendar - changing context of token
                self.gbp_res_obj.token = old_token

    def create_ext_gw_for_target_group(self, l2_policy_id):
        """
        It creates the external gateway for the port-target-group
        whose l2_policy_id is given.
        param:
            l2_policy_id: ID of the l2 policy.

        (a) It first gets the corresponding l3policy id
        (b) Gets the router id corresponding to l3 policy
        (c) Attaches the router to the external network.

        Return: router_id on success.
        """
        try:
            # Get the l2 policy details.
            l2_policy = self.gbp_res_obj.show_l2policy(l2_policy_id)
            if not isinstance(l2_policy, dict):
                err_msg = "Problem while getting details of l2 policy: %s."\
                    % l2_policy_id
                LOG.error(err_msg)
                return str(err_msg)
            l3_policy_id = l2_policy['l3_policy_id']
            msg = "L3 policy corresponding to L2 policy: %s is %s" % (
                l2_policy_id, l3_policy_id)
            print msg
            LOG.info(msg)
            # Get the router id corresponding to l3 policy.
            l3_policy = self.gbp_res_obj.show_l3policy(l3_policy_id)
            if not isinstance(l3_policy, dict):
                err_msg = "Problem while getting details of l3 policy: %s."\
                    % l3_policy_id
                LOG.error(err_msg)
                return str(err_msg)
            router_id = l3_policy['routers'][0]
            msg = "Router ID for l3 policy: %s is %s" % (l3_policy_id,
                                                         router_id)
            print msg
            LOG.info(msg)
            # Attach the router to external gateway.
            result = create_external_gateway(self.lib_os_obj,
                                             router_id=router_id)
            if not isinstance(result, unicode):
                return result

            return router_id
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating external gateway for target group"

    def get_vip_details(self, stack_id, create_floating_ip=False, **kwargs):
        """
        It gets the vip details like vip ip, vip floating ip and pool id.

        params:
            stack_id: Stack corresponding to Loadbalancer service vm.
            create_floating_ip: Tells whether to create floating ip for vip.
        Optional param:
            version: Version of the LB (V1/V2), default is v1
            subnet_id: Id of the provider group subnet id.
            Return: On success: Dict. containing vip Details.
               On failure: String containing error message.
        """
        try:
            lb_version = kwargs.get("version", "V1").lower()
            vip_details = {}
            # Get the Pool ID from the stack resources.
            # TODO: (dilip) Directly call resource show [stack id, res name]
            resources = self.heat_lib_obj.stack_resource_list("", stack_id)
            if not isinstance(resources, list):
                err_msg = "Problem while getting resource of stack: %s" % \
                    stack_id
                LOG.error(err_msg)
                return err_msg
            LOG.debug("\nStack resources: %s", resources)
            if len(resources) == 0:
                err_msg = "There is no resource created for the stack: %s" % \
                    stack_id
                LOG.error(err_msg)
                return err_msg
            # For LB the resource name for pool is LoadBalancerPool/pool
            for resource in resources:
                if resource['resource_name'] in ["LoadBalancerPool", "pool"]:
                    pool_id = resource['physical_resource_id']
                    LOG.info("\n\nThe Pool ID corresponding to the stack: %s"
                             " is %s", stack_id, pool_id)
                    vip_details['pool_id'] = pool_id
                    # In V2, pool doesn't have status field.
                    if lb_version != "v1":
                        break
                    # Check the status of Pool
                    pool_status = self.lbaas_obj.poll_on_resource_status(
                        "pool", pool_id, "ACTIVE"
                    )
                    if not isinstance(pool_status, str):
                        err_msg = "Problem while polling on pool. %s" % \
                            str(pool_id)
                        LOG.error(err_msg)
                        return err_msg
                    if pool_status.lower() != "active":
                        err_msg = "Pool:%s is NOt ACTIVE.Current state: %s"\
                            % (str(pool_id), str(pool_status))
                        LOG.error(err_msg)
                        return err_msg
                    # return vip_details
                    break
            else:
                err_msg = "There is NO Pool resource created for"\
                    " the stack: %s" % stack_id
                LOG.error(err_msg)
                return err_msg
            ports = self.lib_os_obj.list_port()
            if not isinstance(ports, list):
                LOG.err("Problem while getting port list")
                return "Problem while getting port list"
            # Get the VIP port
            for port in ports:
                subnet_id = port["fixed_ips"][0]["subnet_id"]
                if subnet_id == kwargs["subnet_id"]:
                    if "neutron:" in port["device_owner"]:
                        LOG.info("VIP port details: %s", port)
                        break
            else:
                LOG.err("Unable to get port of VIP")
                return "Unable to get port of VIP"
            """
            # Get the vip details.
            vip_info = self.lbaas_obj.get_vip_info_by_pool_id(pool_id)
            if not isinstance(vip_info, dict):
                err_msg = "Problem while getting vip details for pool: %s"\
                    % pool_id
                LOG.error(err_msg)
                return err_msg
            vip_details['fixed_ip'] = vip_info['address']
            vip_details['id'] = vip_info['id']
            """
            vip_details['fixed_ip'] = port["fixed_ips"][0]["ip_address"]
            vip_details["subnet_id"] = port["fixed_ips"][0]["subnet_id"]
            vip_details['port_id'] = port["id"]

            # Get the loadbalancers, listeners for v2
            """
            # TODO: (dilip), First enable heat apis for v2 then it will work.
            # or get separtately pool show and get the below resources.
            if lb_version == "v2":
                vip_details["loadbalancers"] = resource["loadbalancers"]
                vip_details["listeners"] = resource["listeners"]
            """
            # Check whether to create floating ip for vip or NOT.
            if create_floating_ip:
                # Create a floating ip for vip port.
                fip = create_floatingip_for_port(
                    self.lib_os_obj,
                    config.extnet_name,
                    vip_details['port_id'])
                if not isinstance(fip, unicode):
                    return fip
                vip_details['floating_ip'] = fip

            return vip_details
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting vip details related to a stack."

    def create_remote_resources(self, os_pub_ip, project_info,
                                create_vpn_server=False):
        """It creates remote resources such as client vm, vpn server(optional)
        in a new member tenant. The net and subnet info is taken from config.

        params:
            os_pub_ip: Openstack nodes' Public IP.
            project_info: Remote project info.
        Optioan params:
            create_vpn_server: Boolean type which tells whether to create vpn
                               server or not [in site-to-site].
        Note: If vpn server is there then we have to attach the server's subnet
            to the router else attach to the client's subnet.

        Return: Remote resources info dict, on success
                String, on failure.
        """
        try:
            # NOTE: We can use a context manager in this case. But we have
            # dependencies for this method in other files. And also it avoids
            # the user to take the burden of creating the tenant, etc..
            old_context = None

            lib_os_obj = OpenStackLibrary(os_pub_ip)
            remote_resource_info = {
                "project_info": {},
                "remote_client_info": {}
            }

            # Create remote project in default domain with admin role.
            if config.keystone_api_version == 'v3':
                remote_project_id = \
                    lib_os_obj.create_keystone_v3_project_user(
                        config.cloud_admin_domain,
                        config.domain_member_role_name, project_info)
                if not isinstance(remote_project_id, unicode):
                    err_msg = "Problem while creating remote project."
                    LOG.error(err_msg)
                    return err_msg
            else:
                remote_project_id = lib_os_obj.create_tenant(project_info)
                if not isinstance(remote_project_id, unicode):
                    err_msg = "Problem while creating remote project."
                    LOG.error(err_msg)
                    return err_msg

            # Change the context
            old_context = self.__set_context__(lib_os_obj)

            # NOTE: Intentionally done this, to support clean up.
            project_info['project_id'] = remote_project_id
            # Token is required for configuring the remote vpn server.
            project_info['token'] = lib_os_obj.project_info['token_project']
            project_info['domain_name'] = config.cloud_admin_domain
            remote_resource_info["project_info"] = project_info.copy()

            # Create a dummy PTG. To avoid the remote and local prefix ip
            # becoming same. This is to help s2s tunnel establishment. And also
            # for Remote VPN (client and cloud provider not to have same ip)

            # Work around-2: Cisco doesn't allow to create a PTG
            # without any policy rule set. NOTE: Create this dummy ptg
            # only for chain 1 and not for other chains. This will also
            # help for multiple chain insertion scenarios.
            if self.service_chain_count == 1 and not create_vpn_server:
                dummy_prs = self.create_policy_rule_set_helper(
                    [], rule_set_name="dummy_remoteside_prs")
                if not isinstance(dummy_prs, dict):
                    return dummy_prs
                dummy_ptg = self.create_policy_tgt_group_helper(
                    [dummy_prs['id']], pg_name="dummy-ptg")

            if create_vpn_server:
                remote_resource_info.update({"vpn_server_info": {}})
                gbp_resource_info = {
                    'shared': False, 'traffic_type': 'n-s', 'vpn_type': 's2s',
                    'service_chain_nodes': [{'service_type': 'vpn'}],
                    'policy_rules': [
                        # Dummy classifier
                        {'policy_classifier': {"direction": "bi"},
                         'policy_action_type': "redirect"}]}

                dummy_remote_resource = {  # Dummy remote resource info.
                    'remote_client_info': {'cidr': '8.7.6.0/24'},
                    'vpn_server_info': {'listen_iface': '8.7.6.2',
                                        'floating_ip': '192.168.6.100'}}

                # Create remote service resources (only VPN).
                gbp_resources = self._create_gbp_resources_helper_(
                    gbp_resource_info, remote_resources=dummy_remote_resource,
                    suffix_str="_chain" + (str(self.service_chain_count)),
                    explicit_l3_l2_policy=True)
                if not isinstance(gbp_resources, dict):
                    err_msg = "Problem while creating remote resource:"
                    if isinstance(gbp_resources, str):
                        err_msg += gbp_resources
                    LOG.error(err_msg)
                    return err_msg

                services = self.get_inserted_services(
                    gbp_resources, service_type="vpn")
                if not isinstance(services, list):
                    return services

                vpn_service = services[0]['service_details'][
                    'consumer_provider_interfaces']

                # NOTE: Here provider is the client so provider side interface
                # (index=1) is the client side interface and stitching(index=0)
                # is for establishing tunnel with the cloud service vm.
                vpn_server = remote_resource_info['vpn_server_info']
                vpn_server['node_id'] = services[0]['node']['id']
                vpn_server['client_side_iface'] = vpn_service[0][1]['fixed_ip']
                vpn_server['vm_id'] = vpn_service[0][1]['vm_id']
                # vpn_server['listen_iface'] = vpn_service[0][0]['fixed_ip']
                # Now the peer_id is also expected as floating ip since
                # we use vyos for remote vpn server.
                vpn_server['listen_iface'] = vpn_service[0][0]['floating_ip']
                vpn_server['floating_ip'] = vpn_service[0][0]['floating_ip']
                vpn_server['cidr'] = vpn_service[0][0]['cidr']

                # Fill the client side info. Here provider is the client.
                targets = gbp_resources['ptg_info']['provider'][
                    'policy_targets']
                remote_resource_info["remote_client_info"]['cidr'] = \
                    vpn_service[0][1]['cidr']
                remote_resource_info["remote_client_info"]['fixed_ip'] = \
                    targets[0]['vm_ip']

                # TODO:(Surendar). revisit : Adding provider subnet to router
                provider_subnet_id = vpn_service[0][1]['subnet_id']
                l2_policy_id = gbp_resources['ptg_info']['provider'][
                    'ptg_details']['l2_policy_id']
                # Get the l3 policy id.
                l2_policy = self.gbp_res_obj.show_l2policy(l2_policy_id)
                if not isinstance(l2_policy, dict):
                    err_msg = "Problem while getting l2 policy details: %s." \
                        % l2_policy_id
                    LOG.error(err_msg)
                    return str(err_msg)
                l3_policy_id = l2_policy['l3_policy_id']
                provider_nw_id = l2_policy['network_id']
                msg = "L3 policy corresponding to L2 policy: %s is %s" % (
                    l2_policy_id, l3_policy_id)
                print msg
                LOG.info(msg)
                # Get the router id corresponding to l3 policy.
                l3_policy = self.gbp_res_obj.show_l3policy(l3_policy_id)
                if not isinstance(l3_policy, dict):
                    err_msg = "Problem while getting details of l3 policy: "\
                              "%s." % l3_policy_id
                    LOG.error(err_msg)
                    return str(err_msg)
                router_id = l3_policy['routers'][0]
                LOG.info("Router ID for l3 policy: %s is %s",
                         l3_policy_id, router_id)
                # Updating dictionary: using these values to remove 
                # router interface in case of S2S VPN 
                gbp_resources['ptg_info']['provider'][
                    'ptg_details'].update({'router_id': router_id,
                                   'provider_subnet_id': provider_subnet_id})

                port_id = lib_os_obj.create_port(
                    "", port_name=config.port_name, net_id=provider_nw_id)
                if not isinstance(port_id, unicode):
                    return

                # Add provider subnet to the router
                status = lib_os_obj.add_router_interface(
                    router_id, port_id=port_id)
                if not isinstance(status, bool):
                    err_msg = "Problem while attaching subnet: %s to the "\
                              "router: %s" % (provider_subnet_id, router_id)
                    LOG.error(err_msg)
                    return str("Problem while attaching subnet to router.")
                LOG.info("Successfully attached the subnet to the router")

            else:  # Create only client. In this case create only PTG.
                prs_ids = self.enable_external_access()
                if not isinstance(prs_ids, list):
                    return prs_ids

                # Create a PTG which will be a Provider for
                # a new external policy. This is a work-around for cisco.
                pg_nm = "remote-client_chain_" + str(self.service_chain_count)
                client_ptg = self.create_policy_tgt_group_helper(
                    prs_ids, pg_name=pg_nm)
                if not isinstance(client_ptg, dict):
                    LOG.error("Problem while creating PTG in remote site")
                    return "Problem while creating PTG in remote site."

                ptgs_info = [{'no_of_vms': 1, 'ptg_id': client_ptg['id'],
                              'ptg_name': client_ptg['name']}]
                # Create the members in the policy target group(s).
                output = self.add_ptg_members(config.image_name, ptgs_info)
                if not isinstance(output, list):
                    return output
                targets = output[0][1]
                # Set the gateway.
                router_id = self.create_ext_gw_for_target_group(
                    client_ptg['l2_policy_id'])
                if not isinstance(router_id, unicode):
                    return router_id
                remote_resource_info['remote_client_info']['fixed_ip'] = \
                    targets[0]['vm_ip']

                # Get gateway ip. Required for ASAV case.
                subnet_id = client_ptg["subnets"][0]
                subnet_details = \
                    lib_os_obj.get_subnet_details(subnet_id=subnet_id)
                if not isinstance(subnet_details, dict):
                    err_msg = "Problem in getting subnet info %s" % subnet_id
                    LOG.error(err_msg)
                    return err_msg
                # Store the gateway ip.
                remote_gw_ip = subnet_details['gateway_ip']
                remote_resource_info['remote_client_info']['gateway_ip'] = \
                    remote_gw_ip

            # Create floating ip for pts
            floating_ips = create_floatingip_for_targets(
                lib_os_obj, targets)
            if not isinstance(floating_ips, list):
                return floating_ips

            remote_resource_info["remote_client_info"][
                'floating_ip'] = floating_ips[0]

            print "remote_resource_info: %s" % remote_resource_info
            LOG.debug("remote_resource_info: %s", remote_resource_info)

            return remote_resource_info

        except Exception as err:
            LOG.exception(err)
            return "Problem while creating remote resources."
        finally:
            self.__set_context__(old_context)

    # Revisit (Kiran/dilip): Temprory fix to access consumer vm using
    # floating ip. As policy rules are not getting reflected into
    # consumer vm provider security group.
    def add_sg_rules(self, prs_name):
        """Add Security group rules into provided security group.
        of consumer vm. So that ssh & icmp traffic to consumer
        vm will be enabled.
        """
        try:
            sg_name = "provided_" + prs_name
            sg_list = self.lib_os_obj.list_security_groups()
            if not sg_list:
                return "Failed to list Security Groups."
            sg_id = None
            for _sg in sg_list:
                if _sg['name'] == sg_name:
                    sg_id = _sg['id']
                    break
            # ingress & egress ssh
            self.lib_os_obj.create_security_group_rule(
                sg_id, protocol='tcp', from_port='22', to_port='22')
            self.lib_os_obj.create_security_group_rule(
                sg_id, protocol='tcp', direction="egress")

            # ingress & egress icmp
            self.lib_os_obj.create_security_group_rule(sg_id, protocol='icmp')
            self.lib_os_obj.create_security_group_rule(
                sg_id, protocol='icmp', direction="egress")
            return True
        except Exception as err:
            LOG.exception(err)
            return "Some problem while adding sg rules,"\
                "to enable external access."

    def enable_external_access(self, ptg_id=None, ptg_name="updated_group"):
        """This is a work around for cisco, which enables a vm to be accessed
        from external world using the floating ip.
        This will basicaly create a PRS that allows ping and any other
        required traffic for the vm. It creates an external policy and makes
        the PTG(if given) of the vm as provider.
        params:
            ptg_id: Port traget group ID which will be provider here.
        """
        try:
            # NOTE: The policy rule is intentionally made empty as the
            # create_gbp_resource_helper adds one allow for any traffic.
            gbp_resource_info = {'shared': False, 'traffic_type': 'n-s'}
            # Create gbp resources with out port target group.
            gbp_resources = self._create_gbp_resources_helper_(
                gbp_resource_info, create_ptg=False, suffix_str="_enable")
            if not isinstance(gbp_resources, dict):
                return gbp_resources

            prs_ids = [gbp_resources['policy_rule_set']['prs_id']]
            # Create external policy.
            ext_policy = self.create_ext_policy_helper(
                [config.ext_segment_name], prs_ids,
                ext_pol_name=self.project_name + "_enable_ext_policy",
                project_id=self.project_id)
            if not isinstance(ext_policy, dict):
                return ext_policy
            gbp_resources['ext_policy'] = ext_policy

            rule_sets = {}
            [rule_sets.update({prs_id: prs_id}) for prs_id in prs_ids]

            if ptg_id:
                # NOTE: We are making this ptg as provider.
                # update the group with the prs ids
                updated_ptg = self.gbp_res_obj.update_policy_target_group(
                    ptg_id, ptg_name, provided_policy_rule_sets=rule_sets)
                if not isinstance(updated_ptg, dict):
                    err_msg = "Problem while updating policy target group!"
                    LOG.error(err_msg)
                    return err_msg

            # Revisit (Kiran/dilip): Temprory fix to access consumer vm using
            # floating ip. As policy rules are not getting reflected into
            # consumer vm provider security group.
            prs_name = gbp_resources['policy_rule_set']['name']
            status = self.add_sg_rules(prs_name)
            if isinstance(status, str):
                return status

            return prs_ids
        except Exception as err:
            LOG.exception(err)
            return "Problem while enabling vm access from external."

    @increase_chain_count
    def create_gbp_resources(self, gbp_resource_info, **kwargs):
        """This will create all the resources for GBP.

        This requires the resources to be specified in a pre-defined
        format(dict), so that it will create them accordingly.
        :param:
            gbp_resource_info (dict). See below for its detail info.


        :optional create_ptg: Whether to create PTGs or NOT. Defulat is True.

        :optional remote_resources: The dict containing the remote resources.
                   This is what the create_remote_resources returns.
        :optional suffix_str: The suffix string for every resource name.
        :optional no_of_provider_members: The no. of members to be launched in
                the provider group.

        :return: Dictionary containing the gbp resource info, on success.
                 String containing the error message on failutre.
        ======
        NOTE-1:
        ======
        This method can be used ...
           (1) to insert a service chain in between consumer/ext and provider,
               [See the below i/p dict format]
           (2) to create ptgs without any chain,
               [the i/p dict should not contain the redirct action and
               service chain nodes. It contains explicit allow rules]
           (3) to simply create policy rule set with dependencies [no ptgs].
               [the i/p dict should not contain the redirct action and service
               chain nodes and make the optional param create_ptg=False]
           (4) to insert a service in HA mode.
               NOTE: It also supports combinations of HA and Non-HA vms
               in chains. For HA, user has to explictly specify service_ha=True
               in service_chain_nodes.

        =======
        Note-2:
        =======
        (1) In this scenario, we will create only one
            Policy-Rule-Set between a consumer and a provider and the policy
            rule set will have atmost one Redirect Action.

        (2) In addition to GBP resources, if the traffic_type is N-S then we
            will create a client, in a new tenant member, based on info
            contained in the config file.
            Note: The client will be used to send traffic to the cloud.

        (3) If there is a VPN service in chain and the traffic is N-S then
            in addition to the (2) we have to create a VPN server(acting
            as remote VPN server) in the above tenant.
            NOte: The scenario is to simulate site-to-site vpn connection.
                In this case the client will be in the local LAN (logical)
                of this remote VPN server. It will be acting as the remote
                client for the VPN server in the cloud.

        (4) When we have only Firewall service and the traffic_type is N-S
            then we have to associate floating ip to each provider's
            policy target, explicitly.

        (5) When we have LB in the chain then we have to add the members
            to the haproxy vm, explicitly. And special care has to be taken
            when classifier has range of ports. [In this case we have to add
            member for each member port. Assumption: In the validation of the
            scenarios, the member VM should have as many services running with
            those many ports in classifier.

        (6) When LB is in chain in N-S scenario then we have to explicitly
            associate floating ip to the vip.

        =====================================================================
        Example of i/p dict format (for service chain)
        =====================================================================
        gbp_resource_info = {
            'shared': True/False, # True: Tenant uses admin's spec and nodes.
            'traffic_type': 'n-s/e-w' # North-South/East-West.
            'vpn_type': s2s/remote # (Optional). Required when vpn is there.
            'vpnfw_service_image': 'asav'/'vyos' / 'paloalto',
            'service_chain_nodes': [ # Note: The order of nodes matters.
                {
                    'service_type': 'vpn/fw/lb',
                    'service_ha': True/False [optional. default is False]
                    'version': v1/v2 [optional, required only for lb node]
                },
                {}
            ],
            'policy_rules' :[ # Note: We support only ONE Redirect Action.
                {
                    policy_classifier: {
                        "direction":"bi",
                        "protocol": "tcp",
                        "ports": "80" # Same for single and range of ports.
                    },
                    policy_action_type: "redirect/allow",
                    # If redirect then nodes will be created as per above -
                    # service_chain_nodes info (in-order)

                }, # Rule1
                {} # Rule2
            ]
        # Note:
        # (1) The Policy-Rule-Set, Spec are implicit, so no need to specify
        #     them, we will create them.
        # (2) The Policy target groups are also implicit. And we will create
        #    1 port target in each group. For scenario in which LB is inserted
        #    we will create 3 members (vms) in the Provider.

        }# gbp_resource_info
        """
        try:
            allow_rule = True
            LOG.debug("gbp_resource_info received %s", gbp_resource_info)

            gbp_resource_info = copy.deepcopy(gbp_resource_info)
            traffic_type = gbp_resource_info['traffic_type'].lower()

            LOG.debug("gbp_resource_info:%s", gbp_resource_info)
            # lib_os_obj = self.lib_os_obj  # Store a copy of libos obj

            remote_resources = None
            # If traffic_type is NS then create remote resources.
            if traffic_type == "n-s":
                # Get the remote project info and update it.
                thread_name = ''
                if 'main' not in threading.currentThread().getName().lower():
                    thread_name += "_" + threading.currentThread().\
                        getName().lower()

                self.remote_project_info = config.remote_project_info[0].copy()
                self.remote_project_info['project_name'] += \
                    str(self.remote_project_info['project_no']) + thread_name
                self.remote_project_info['user_name'] += \
                    str(self.remote_project_info['project_no']) + thread_name
                config.remote_project_info[0]['project_no'] += 1

                vpn_server_required = True if gbp_resource_info.get(
                    'vpn_type', "").lower() == "s2s" else False

                remote_resources = self.create_remote_resources(
                    self.lib_os_obj.host_ip,
                    self.remote_project_info,
                    vpn_server_required)

                if not isinstance(remote_resources, dict):
                    return remote_resources
            # No need to add allow rules to prs in only lb case
            service_chain_nodes = gbp_resource_info.get('service_chain_nodes',
                                                        [])
            if not any(node.get('service_type', None) == 'FW'
                       for node in service_chain_nodes):
                allow_rule = False

            # Create all the GBP resources based on the user input.
            empty_classifier = False
            if "NORULE" in gbp_resource_info["tc_id"]:
                empty_classifier = True

            gbp_resources = self._create_gbp_resources_helper_(
                gbp_resource_info,
                allow_rule=allow_rule,
                remote_resources=remote_resources,
                suffix_str="_chain" + (str(self.service_chain_count)),
                **kwargs)

            if not isinstance(gbp_resources, dict):
                return gbp_resources

            # Configure the remote server and client if traffic is N-S
            # and vpn service is there.
            if traffic_type == "n-s" and gbp_resource_info.get('vpn_type'):
                services = self.get_inserted_services(gbp_resources, "vpn")
                if not isinstance(services, list):
                    return services
                chain_index = 0
                # Prepare for remote server/client configuration.
                self.prepare_for_remote_config(
                    services[0]['service_details'], chain_index,
                    gbp_resource_info['vpnfw_service_image'],
                    gbp_resource_info['vpn_type'])

                # Get the VPN service details.
                # NOTE: Here, the consumer side interface is the stitching one.
                vpn_service_ifaces = services[0]['service_details'][
                    'consumer_provider_interfaces']
                # Configure remote vpn server with the cloud side vpn info.
                status = self.configure_remote_resources(
                    remote_resources, vpn_service_ifaces[chain_index][0],
                    cloud_client_subnet_cidr=vpn_service_ifaces[chain_index
                                                                ][1]['cidr'],
                    vpn_type=gbp_resource_info['vpn_type'],
                    vpn_img_vendor=gbp_resource_info['vpnfw_service_image'])

                if not isinstance(status, bool):
                    return status
                msg = commonLibrary.get_decorated_message(
                    "Remote resources for vpn of type %s configured "
                    "successfully ..." % gbp_resource_info['vpn_type'])
                print msg
                LOG.info(msg)

            # NOTE: Enable the consumer vm if traffic is East-West.
            if traffic_type == 'e-w':
                consumer_ptg = gbp_resources['ptg_info'][
                    'consumer']['ptg_details']
                prs_ids = self.enable_external_access(
                    consumer_ptg['id'], consumer_ptg['name'])
                if not isinstance(prs_ids, list):
                    return prs_ids

            msg = commonLibrary.get_decorated_message(
                "\nAll gbp resources are created successfully: \n%s\n" %
                gbp_resources)
            print msg
            LOG.info(msg)

            return gbp_resources
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating gbp resources."

    # def create_gbp_resources_helper(self, lib_os_obj,
    #                                gbp_resource_info, **kwargs):

    # @__set_context__
    def _create_gbp_resources_helper_(self, gbp_resource_info, **kwargs):
        '''This will create all the resources for GBP.

        This requires the resources to be specified in a pre-defined
        format(dict), so that it will create them accordingly.

        :param gbp_resource_info dict:
                    Refer to the create_gbp_resources for its detail info.
                    If not given then default behaviour is to create 2 PTGs
                    with all kind of traffic allowed in between them.

        :optional remote_resources dict: The dict containing the remote
                resources. This is what the create_remote_resources returns.
        :optional create_ptg bool: Whether to create PTGs or NOT.
                  Defulat is True.
        :optional suffix_str str: The suffix string for every resource name.
        :optional allow_rule bool: Whether to add default allow rules for
                  all traffic to reach to pts of provider ptg. Default is True
        :optional explicit_l3_l2_policy bool: whether to create l3 and l2 
                  policies explicitly while creating ptg. Default is False.
        '''
        try:
            LOG.debug("gbp_resource_info received for tenant: %s"
                      " is %s", self.project_name, gbp_resource_info)

            service_chain_nodes = gbp_resource_info.get('service_chain_nodes',
                                                        [])
            # NOTE: use this
            # is_service_in_chain = lambda service_type: service_type.lower() \
            #    in [service['service_type'].lower() \
            #    for service in service_chain_nodes]

            # NOTE: Temp fix for Cisco. Reverse the chain order.
            # service_chain_nodes.reverse()

            gbp_resources = {
                'policy_rule_set': {'policy_rules': []},
                'ptg_info': {
                    "consumer": {
                        "ptg_details": "",
                        "policy_targets": []
                    },
                    "provider": {
                        "ptg_details": "",
                        "policy_targets": []
                    },
                },
                "consumer_nw_id": None,
                "provider_nw_id": None,
                # If there is a vpn service in chain then do following.
                # Launch 1 client vm and 1 remote vpn server in a new member
                # tenant.
                # "remote_resource_info": {
                #        "project_info": {},
                #        "vpn_server_info": {},
                #        "remote_client_info": {}
                #    },
            }  # gbp_resources.

            gbp_resource_info = copy.deepcopy(gbp_resource_info)
            traffic_type = gbp_resource_info['traffic_type'].lower()

            # Add allow rules for all protocols and ports, irrespective of the
            # traffic type & classifier if FW is in chain.
            if kwargs.get("allow_rule", True):
                self.add_allow_rules(gbp_resource_info)

                LOG.debug("gbp_resource_info after adding implicit allow "
                          "rules:%s", gbp_resource_info)

            if kwargs.get('remote_resources'):
                remote_resources = kwargs['remote_resources']
                gbp_resources['remote_resource_info'] = remote_resources
                # NOTE: Also store the vpn type if any.
                if gbp_resource_info.get('vpn_type'):
                    gbp_resources['remote_resource_info']['vpn_type'] = \
                        gbp_resource_info['vpn_type']

            rule_set_ids = []
            suffix_str = kwargs.get('suffix_str', "")
            lb_version = "V1"
            abs_rule_set_name = self.project_name + suffix_str + "_prs"
            rule_ids = []
            redirect_action = False
            for rule_no, pol_rule_info in enumerate(
                    gbp_resource_info['policy_rules']):
                policy_rule = {}
                policy_rule['name'] = abs_rule_set_name + "_rule_" + \
                    str(rule_no + 1)
                action_ids = []
                spec_id = None
                # Create Policy Classifier
                #empty_classifier = False
                #if kwargs.get('empty_classifier'):
                #    empty_classifier = kwargs['empty_classifier']

                #classifier = {}
                #import pdb; pdb.set_trace();
                classifier = self.create_policy_classifier_helper(
                    pol_rule_info['policy_classifier'].copy(),
                    classifier_name=policy_rule['name'] + "_classifier")

                if not isinstance(classifier, dict):
                    return classifier
                # NOTE: Store the original protocol name.
                if pol_rule_info['policy_classifier'].get('protocol'):
                    classifier['protocol_original_name'] = \
                        pol_rule_info['policy_classifier']['protocol']
                policy_rule['classifier'] = classifier

                policy_rule['action'] = {}
                act_name = policy_rule['name'] + "_action"
                policy_rule['action']['name'] = act_name

                # Create Service chain node(s) and spec.
                node_ids = []
                if pol_rule_info['policy_action_type'].lower() == "redirect":
                    redirect_action = True
                    # If shared = True then the admin will create the spec and
                    # nodes and the tenant will re-use them.
                    if gbp_resource_info['shared']:
                        # Set the admin token
                        self.gbp_res_obj.token = self.tokens['admin']
                        # self.project_name = config.cloud_admin_project

                    policy_rule['action']['service_chain'] = {}
                    services = policy_rule['action']['service_chain'][
                        'services'] = []
                    for chain_node in service_chain_nodes:
                        add_args = {}
                        add_args['node_name'] = act_name + "_node_" + \
                            chain_node['service_type'].lower()
                        # vpnfw service vm image (asav / vyos / paloalto).
                        add_args['vpnfw_service_image'] = gbp_resource_info.\
                            get("vpnfw_service_image", "vyos")
                        add_args['service_ha'] = \
                            chain_node.get('service_ha', False)

                        if traffic_type == "n-s":
                            if chain_node['service_type'].lower() == "vpn":
                                if gbp_resource_info.get('vpn_type',
                                                         "").lower() == "s2s":
                                    add_args['vpn_server_info'] = \
                                        remote_resources['vpn_server_info']
                                add_args['remote_client_info'] = \
                                    remote_resources['remote_client_info']
                                add_args['vpn_type'] = gbp_resource_info[
                                    'vpn_type']

                        if chain_node['service_type'].lower() == "lb":
                            add_args['protocol'] = classifier['protocol']
                            add_args['port'] = classifier['port_range']
                            add_args['version'] = chain_node['version']
                            lb_version = chain_node['version']

                        # NOTE: To add allow rule in service chain node
                        #if (chain_node['service_type'].lower() == "fw") and (not empty_classifier):
                        if (chain_node['service_type'].lower() == "fw"):
                            add_args['protocol'] = classifier['protocol']
                            if classifier.get('port_range'):
                                add_args['port'] = classifier['port_range']

                        add_args['shared'] = gbp_resource_info['shared']
                        node = self.create_srvc_chain_node_helper(
                            chain_node['service_type'],
                            **add_args)
                        if not isinstance(node, dict):
                            return node
                        service_info = {}
                        service_info['node'] = node
                        service_info['service_type'] = \
                            chain_node['service_type']
                        service_info['service_ha'] = add_args['service_ha']
                        services.append(service_info)
                        node_ids.append(node['id'])

                    # Create Service chain node spec
                    spec = self.create_srvc_chain_spec_helper(
                        node_ids, spec_name=act_name + "_spec",
                        shared=gbp_resource_info['shared'])
                    if not isinstance(spec, dict):
                        return spec
                    policy_rule['action']['service_chain'][
                        'spec_id'] = spec['id']
                    spec_id = spec['id']
                    # Reset the token to tenant's token.
                    if gbp_resource_info['shared']:
                        self.gbp_res_obj.token = self.tokens['tenant']
                        # self.project_name = project_name

                # Create action
                action = self.create_policy_action_helper(
                    pol_rule_info['policy_action_type'],
                    action_value=spec_id,
                    act_name=act_name)
                if not isinstance(action, dict):
                    return action

                policy_rule['action']['action_id'] = action['id']
                action_ids.append(action['id'])
                # kwargs['action_ids'] = action_ids

                # Create Policy Rule
                rule = self.create_policy_rule_helper(
                    action_ids, classifier['id'],
                    rule_name=policy_rule['name'])
                if not isinstance(rule, dict):
                    return rule
                policy_rule['rule_id'] = rule['id']
                rule_ids.append(rule['id'])

                gbp_resources['policy_rule_set'][
                    'policy_rules'].append(policy_rule)
            # Create Policy Rule Set
            rule_set = self.create_policy_rule_set_helper(
                rule_ids,
                rule_set_name=abs_rule_set_name)
            if not isinstance(rule_set, dict):
                return rule_set
            gbp_resources['policy_rule_set']['name'] = abs_rule_set_name
            gbp_resources['policy_rule_set']['prs_id'] = rule_set['id']
            rule_set_ids.append(rule_set['id'])

            ptgs_info = []
            nsp_id = None

            # Create network service policy when lb is there in chain.
            if redirect_action and self.is_service_in_chain(
                    "lb", service_chain_nodes):
                nsp = self.create_nw_srvc_policy_helper(
                    nw_srvc_pol_name=self.project_name + suffix_str +
                    "_nw_service_policy")
                if not isinstance(nsp, dict):
                    return nsp
                nsp_id = nsp['id']
            # ptg_pair_ids = [None, None]
            # Create provider Port group
#             print "Creating provider ..."
#             LOG.info("Creating provider ...")
#             provider_tg = self.create_policy_tgt_group_helper(
#                 rule_set_ids,
#                 pg_name=self.project_name + "_provider", nsp_id=nsp_id)
#             if not isinstance(provider_tg, dict):
#                 return provider_tg
#             gbp_resources['ptg_info']['provider'][
#                                        'ptg_details'] = provider_tg
#
# Determine no. of provider targets to create.
#             no_of_targets = 1
#             if is_service_in_chain("lb"):
#                 no_of_targets = 3
# Prepare the info for provider members (targets)
#             ptgs_info.append({
#                 'no_of_vms': no_of_targets,
#                 'ptg_id': provider_tg['id'],
#                 'ptg_name': provider_tg['name']
#             })

            # Check whether to proceed to create port groups. Default: create
            if not kwargs.get('create_ptg', True):
                msg = commonLibrary.get_decorated_message(
                    "\nAll gbp resources (except ptgs) are created "
                    "successfully: \n%s\n" % gbp_resources)
                print msg
                LOG.info(msg)
                return gbp_resources

            # Create Consumer Port group: If traffic_type is E-W,
            # else create an external Policy.
            if traffic_type == "e-w":
                print "Creating consumer ..."
                LOG.info("Creating consumer ...")
                consumer_tg = self.create_policy_tgt_group_helper(
                    rule_set_ids,
                    group_type="consumer",
                    pg_name=self.project_name + suffix_str + "_consumer")
                if not isinstance(consumer_tg, dict):
                    return consumer_tg
                gbp_resources['ptg_info']['consumer'][
                    'ptg_details'] = consumer_tg
                # Prepare the info for consumer members (targets)
                ptgs_info.append({
                    'no_of_vms': 1,
                    'ptg_id': consumer_tg['id'],
                    'ptg_name': consumer_tg['name']
                })

                router_id = self.create_ext_gw_for_target_group(
                    consumer_tg['l2_policy_id'])
                if not isinstance(router_id, unicode):
                    return router_id

                # ptg_pair_ids[0] = consumer_tg['id']
            else:  # Traffic is N-S: create external policy.
                # NOTE: Per tenant there is ONLY one ext policy allowed.
                # Create external policy.
                ext_policy = self.create_ext_policy_helper(
                    config.ext_segment_name,
                    rule_set_ids,
                    ext_pol_name=self.project_name + "_ext_policy",
                    project_id=self.project_id)
                if not isinstance(ext_policy, dict):
                    return ext_policy
                gbp_resources['ext_policy'] = ext_policy

            l2_policy_id = None

            # Create l3 and l2 policies explicitly. Default: not create 
            if kwargs.get("explicit_l3_l2_policy", False):
                ip_version = 4
                subnet_prefix_length = "24"
                ip_pool = "25.0.1.0/24"           
                l3policy_name = self.project_name + suffix_str +\
                            "_provider_l3_policy" 
                #external_segments=config.ext_segment_name
                ext_segment_name=config.ext_segment_name
                ext_segment_details = \
                        self.gbp_res_obj.get_external_segment(ext_segment_name)
                if not isinstance(ext_segment_details, dict):
                    return ext_segment_details
                external_segments = {ext_segment_details['id']: []}
                l3_policy_info = self.gbp_res_obj.create_l3policy(
                    l3policy_name, subnet_prefix_length=subnet_prefix_length,
                    ip_version=ip_version, ip_pool=ip_pool,
                    external_segments=external_segments)
                if not isinstance(l3_policy_info, dict):
                    err_msg = "failed to create l3policy."
                    LOG.error("failed to create l3policy.")
                    return err_msg
                print "\nl3_policy_info ----- %s" % l3_policy_info
                l3_policy_id = l3_policy_info["id"]
                l2_policy_name = self.project_name + suffix_str +\
                                 "_provider_l2_policy"
                l2_policy_info = self.gbp_res_obj.create_l2policy(
                     l2_policy_name, l3_policy_id=l3_policy_id)
                if not isinstance(l2_policy_info, dict):
                    err_msg = "failed to create l2policy."
                    LOG.error("failed to create l3policy.")
                    return err_msg
                print "\nl2_policy_info ----- %s" % l2_policy_info
                l2_policy_id = l2_policy_info['id']
            #raw_input("Going to create provider...")
            print "Creating provider ..."
            LOG.info("Creating provider ...")
            provider_tg = self.create_policy_tgt_group_helper(
                rule_set_ids,
                pg_name=self.project_name + suffix_str + "_provider",
                nsp_id=nsp_id, l2_policy_id=l2_policy_id)
            if not isinstance(provider_tg, dict):
                return provider_tg
            gbp_resources['ptg_info']['provider']['ptg_details'] = provider_tg
            # ptg_pair_ids[1] = provider_tg['id']

            # Determine no. of provider targets to create.
            no_of_targets = 1
            if self.is_service_in_chain("lb", service_chain_nodes):
                no_of_targets = kwargs.get('no_of_provider_members', 3)

            # Prepare the info for provider members (targets)
            create_fip_for_member = False
            # Create floating IP for each provider target if the service
            # chain has ONLY FW and the traffic_type is N-S.
            if traffic_type == "n-s" and len(service_chain_nodes) == 1 and\
                    self.is_service_in_chain("fw", service_chain_nodes):
                create_fip_for_member = True
            ptgs_info.append({
                'no_of_vms': no_of_targets,
                'ptg_id': provider_tg['id'],
                'ptg_name': provider_tg['name'],
                'create_floating_ip': create_fip_for_member
            })

            # ptg_pair_nw_ids = []
            # ptg_pair_nw_ids.append((gbp_resources['consumer_nw_id'],
            #                        gbp_resources['provider_nw_id']))
            # Get the service(s) details and store them in the gbp_resources.
            # NOTE: Services will be launched only when the consumer and
            # provider are created.

            if not redirect_action:  # TO handle plain allow actions.
                services = []

            service_lb = None
            for service in services[:]:
                # Note: we are reusing one service vm both for vpn and fw.
                # If VPN is there then no need to get the details of the fw vm.
                if gbp_resource_info.get("vpn_type") and\
                        service['service_type'].lower() == "fw":
                    continue
                # NOTE: Done temporarily. Poll on the stack
                stack_details = get_stack_by_node_id(self.heat_lib_obj,
                                                     service["node"]['id'])
                if not isinstance(stack_details, dict):
                    return stack_details

                service['service_details'] = {}
                if config.nfp_model == "advanced":
                    # Get the service vm related ips.
                    # NOTE:- We need service vm details in case of
                    # NFP advanced model. In NFP base model service
                    # will be part of namespaces.
                    svm_ip_info = self.get_svm_info(
                        service['service_type'],
                        [provider_tg['id']],
                        vpnfw_service_image=gbp_resource_info.get(
                            "vpnfw_service_image", "vyos"),
                        service_ha=service['service_ha'])
                    if not isinstance(svm_ip_info, dict):
                        return svm_ip_info
                    # If vpn in ha: get the ha_vip_fip (fip of the vip)
                    if service['service_ha'] and \
                            service['service_type'].lower() == "vpn":
                        out = self.get_ha_vip(stack_details)
                        if not out[0]:
                            return out[1]
                        svm_ip_info['ha_vip_fip'] = out[1]
                        svm_ip_info['ha_vip_fix'] = out[2]

                    # Store the service vm ip info.
                    service['service_details'] = svm_ip_info
                else:  # NFP base model
                    # TODO: (Kiran/ Dilip) get namespace details.
                    # To validate dump traffic on namespace in case
                    # of nfp base model
                    pass

                # Also store the stack id.
                service['stack_id'] = stack_details['id']

                # GET the vip details for load balancer service.
                # if service['service_type'].lower() == "lb":
                # Create fip if traffic is NS and vpn is not there.
                #    create_floating_ip = traffic_type == "n-s" and\
                #        not gbp_resource_info.get("vpn_type", False)
                #    vip_details = self.get_vip_details(
                #        stack_details['id'], create_floating_ip)
                #    if not isinstance(vip_details, dict):
                #        return vip_details
                #    service['service_details']['vip_details'] = vip_details

                # Work around for lb case.
                if service['service_type'].lower() == "lb":
                    service_lb = service

            # Create the members in the policy target group(s).
            targets = self.add_ptg_members(config.image_name, ptgs_info)
            if not isinstance(targets, list):
                return targets
            # NOTE: order matters here. And also length and index
            if len(targets) > 1:
                provider_targets = targets[1][1]
            else:
                provider_targets = targets[0][1]

            gbp_resources['ptg_info']['provider'][
                'policy_targets'] = provider_targets
            # Get the nw id. This can also be done from provider group's
            # l2 policy show.
            gbp_resources['provider_nw_id'] = provider_targets[0]['network_id']

            # GET the vip details for load balancer service.
            # NOTE: This is done here to avoid the issue of stack update else
            # this logic should be moved before adding ptg members.
            # This logic will work when lb is in last of chain,
            # which is fine in SG case.
            if redirect_action and service_lb:
                # Create fip for vip if traffic is NS and vpn is not there.
                create_floating_ip = traffic_type == "n-s" and\
                    not gbp_resource_info.get("vpn_type", False)

                stack_details = get_stack_by_node_id(self.heat_lib_obj,
                                                     service_lb["node"]["id"])
                if not isinstance(stack_details, dict):
                    return stack_details

                vip_details = self.get_vip_details(
                    stack_details['id'], create_floating_ip,
                    subnet_id=provider_targets[0]["subnet_id"],
                    version=lb_version)
                if not isinstance(vip_details, dict):
                    return vip_details

                if config.nfp_model == 'advanced':
                    service_lb['service_details']['vip_details'] = vip_details
                else:
                    service_lb["service_details"]["vip_details"] = vip_details

            # Associate floating IP to each provider target if the service
            # chain has ONLY FW and the traffic_type is N-S.
            # if traffic_type == "n-s" and len(service_chain_nodes) == 1 and\
            #        self.is_service_in_chain("fw"):

            #    floating_ips = create_floatingip_for_targets(
            #        self.lib_os_obj, provider_targets)
            #    if not isinstance(floating_ips, list):
            #        return floating_ips

            # Get the consumer targets, if any
            if len(targets) > 1:
                # NOTE: order matters here. And also index.
                consumer_targets = targets[0][1]
                gbp_resources['ptg_info']['consumer'][
                    'policy_targets'] = consumer_targets
                gbp_resources['consumer_nw_id'] = consumer_targets[0][
                    'network_id']
                # NOTE: In the 2.0 for cisco, as there are no namespace
                # suppoerted, so we are using floating ip.
                floating_ips = create_floatingip_for_targets(
                    self.lib_os_obj, consumer_targets)
                if not isinstance(floating_ips, list):
                    return floating_ips

            # If lb is in chain, update the weights of the pool members.
            if self.is_service_in_chain("lb", service_chain_nodes):
                for member, weight in zip(provider_targets,
                                          gbp_config.member_weight):
                    member['weight'] = weight

            # msg = "\n" + 80 * "#" + "\nAll gbp resources are created"\
            # " successfully: \n%s\n" % gbp_resources + 80 * "#"
            # print msg
            # LOG.info(msg)

            return gbp_resources
        except Exception as err:
            LOG.exception(err)
            return "Problem while creating gbp resources."

    def add_ptg_members(self, image_name, ptgs_info, **kwargs):
        """
        It adds member(s) to policy target group.

        (1) First create policy targets on the policy traget group.
        (2) Using the neutron port correspondiong to policy target,
            it launches vm.
        params:
            image_name,
            ptgs_info: [{no_of_vms: 1, ptg_id: xx, ptg_name="provider",
                        create_floating_ip=False},

                        {no_of_vms: 1, ptg_id: yy, ptg_name="consumer",
                        create_floating_ip=False}]

                no_of_vms: (Int) No. of vms to be launhed,
                ptg_id: Policy traget group ID,
                ptg_name: Name of policy target group (Optional)
                create_floating_ip: Create floating ip for member (Optional)
                                    (Defualt is False)
        Optional params:
            flavor_name: Default is m1.small
        Return:
            List of tuples. A tuple contains the ptg_id and its
            targets( in a list of dictionary).
            Ex: [(ptg_id, targets), ()]
            Note:
                Each target in targets is a dictionary containing info
                like vm_ip, port_id, network_id,
                floating_ip (if create_floating_ip is True) etc ...
        """
        try:
            print "Adding members in port-groups ..."
            LOG.info("Adding members in port-groups ...")

            flavor_name = kwargs.get('flavor_name', config.flavor_name)
            policy_targets = []
            all_targets = []
            for ptg_no, ptg_info in enumerate(ptgs_info):
                # Create the policy targets.
                ptg_name = ptg_info.get('ptg_name', "ptg_" + str(ptg_no + 1))
                targets = self.create_policy_target_helper(
                    ptg_info['no_of_vms'],
                    ptg_info['ptg_id'],
                    policy_target_group_name=ptg_name)
                if not isinstance(targets, list):
                    return targets
                # Check whether to create floating ip for the targets or not.
                if ptg_info.get('create_floating_ip', False):
                    floating_ips = create_floatingip_for_targets(
                        self.lib_os_obj, targets)
                    if not isinstance(floating_ips, list):
                        return floating_ips

                policy_targets.append((ptg_info['ptg_id'], targets))
                # Append all the targets in all_targset
                all_targets += [target for target in targets]

            # Launch vms on each target port.
            server_ids = launch_vms_using_targets(self.lib_os_obj,
                                                  image_name, all_targets,
                                                  flavor_name=flavor_name)
            if not isinstance(server_ids, list):
                return server_ids

            return policy_targets
        except Exception as err:
            LOG.exception(err)
            return "ERROR: Problem while adding members to ptgs."

    def configure_remote_resources(self, remote_resources_info,
                                   cloud_vpn_server_info,
                                   cloud_client_subnet_id=None,
                                   cloud_client_subnet_cidr="",
                                   vpn_type="s2s",
                                   vpn_img_vendor="vyos"):
        """It configures the remote vpn server and/or the client which is
            outside the cloud [simulating].

        params:
            remote_resources_info: A dict containing the server and client info
                    This is what the create_remote_resources() returns.
            cloud_vpn_server_info: A dict containing the service vm [in cloud]
                                    info corresponding to stitching interface.
                Ex: cloud_vpn_server_info = {
                 'fixed_ip': <Fixed ip of the svm in stitching nw,
                 'floating_ip', <floating ip associated to the above fixed_ip}
                                For ha, this fip is the vip ip's fip.
            cloud_client_subnet_id: Remote client subnet id (which is nothing
                        but the provider subnet's id). This will be optional
                        if cloud_client_subnet_cidr is specified.
        Optional param:
            cloud_client_subnet_cidr: Remote client cidr (which is nothing
                               but the provider subnet's cidr.)
              NOTE: If this is passed then cloud_client_subnet_id is optional.
            vpn_type: Type of vpn (remote/s2s)
            vpn_img_vendor: Image vendor name (vyos/asav/paloalto).
        Return:
            True on success.
            String, on failure.

        NOTE: For remote vpn case, this updates the remote client dict (in
            remote_resources_info) with the tunnel interface ip in, inplace.
        """
        try:
            if vpn_type.lower() == 's2s' and not cloud_client_subnet_cidr:
                if cloud_client_subnet_id is None:
                    err_msg = "Subnet id (subnet id of the client"\
                        "in cloud) is required for configuring the VPN"
                    LOG.error(err_msg)
                    return err_msg

                # Get the cloud side client's cidr.
                cloud_client_subnet_info = \
                    self.lib_os_obj.get_subnet_details(
                        subnet_id=cloud_client_subnet_id)
                if not isinstance(cloud_client_subnet_info, dict):
                    err_msg = "Problem while getting details of subnet:%s"\
                        % cloud_client_subnet_id
                    LOG.error(err_msg)
                    return str(err_msg)
                cloud_client_subnet_cidr = cloud_client_subnet_info['cidr']

            remote_server_info = remote_resources_info.get(
                'vpn_server_info', {})
            remote_vpn_node_id = remote_server_info.get('node_id')
            remote_vpn_server_id = remote_server_info.get('vm_id')

            cloud_vpn_server_info = copy.deepcopy(cloud_vpn_server_info)
            cloud_vpn_server_fip = cloud_vpn_server_info['floating_ip']
            # cloud_vpn_server_info['listen_iface'] = cloud_vpn_server_fip
            # NOTE: For cross tenant with remote as vyos and cloud as asav then
            # for listen iface (peer_id) will be fixed_ip.

            # Configure the remote vpn server with info of cloud server in s2s.
            if vpn_type.lower() == 's2s':
                # Create a new VPN template with the cloud vpn resources.
                status_string = \
                    Template.get_template_in_json_form(
                        'vpn', vpn_type=vpn_type,
                        vpn_server_info=cloud_vpn_server_info,
                        remote_client_info={'cidr': cloud_client_subnet_cidr})
                if not status_string[0]:
                    return status_string[1]
                # Update the Remote server node
                # Use the token of the remote server tenant.
                if not isinstance(gbp_construct(
                        remote_resources_info['project_info']['token'],
                        self.lib_os_obj.host_ip).update_service_chain_node(
                        remote_vpn_node_id, config=status_string[1]), dict):
                    LOG.error("Problem while updating node of remote vpn.")
                    return "Problem while updating node of remote vpn."
                # Check whether the remote vpn server is intact or not.
                # NOTE: This will work, as the poll uses the admin context.
                status = self.lib_os_obj.poll_on_server_to_delete(
                    remote_vpn_server_id, 20)
                if isinstance(status, bool):
                    err_msg = "The remote vpn server is deleted after "\
                        "it's node got updated!"
                    LOG.error(err_msg)
                    return err_msg
            # Configure remote client.
            elif vpn_type.lower() == 'remote':
                remote_client_info = {
                    'ip_address': remote_resources_info[
                        'remote_client_info']['floating_ip'],
                    'user_name': config.image_user,
                    'password': config.image_pass,
                    'remote_gw': remote_resources_info["remote_client_info"
                                                       ]["gateway_ip"]}
                vpn_user_creds = \
                    {"vpn_user": config.vpn_user_details['user_name'],
                     "vpn_passwd": config.vpn_user_details['password']}

                out = RemoteVpnClientConfigure().remote_vpn_config_master(
                    remote_client_info, vpn_user_creds,
                    cloud_vpn_server_fip, vpn_img_vendor)
                if not out[0]:
                    return out[1]
                # NOTE: Update the tun iface in the remote client dict, INPLACE
                remote_resources_info['remote_client_info'][
                    'tun_iface_ip'] = out[1]

            return True
        except Exception as err:
            LOG.exception(err)
            return "Problem while confguring the remote resources."

#
#            Test data
#
"""
gbp_resource_info = {
    'shared': False,  # True: Tenant uses admin's spec and nodes.
    'traffic_type': 'n-s',  # North-South/East-West.
    'service_chain_nodes': [  # Note: The order of nodes matters.
        {
            'service_type': 'fw'
        }
    ],
    'policy_rules': [  # Note: We support only ONE Redirect Action.
        {
            'policy_classifier': {
                "direction": "bi",
                "protocol": "tcp",
                "ports": "80"  # Same for single and range of ports.
            },
            'policy_action_type': "redirect",
            # If redirect then nodes will be created as per above -
            # service_chain_nodes info (in-order)

        },  # Rule1
    ]
}  # gbp_resource_info

from atf.config.setup_config import setupInfo
os_ip = setupInfo["os-controller-node"]["pubip"]
project_name = "dkn_prj"

lib_obj = OpenStackLibrary(os_ip)
lib_obj.project_info['project_name'] = "dkn_prj"
token = lib_obj.get_keystone_v3_token('dkn_prj', 'dkn_dom', 'dkn_mem',
                                      'dkn_pass', "tenant")
lib_obj.project_info['token_project'] = token
lib_obj.project_info[
    'project_id'] = lib_obj.get_keystone_v3_project_id(project_name)

gbp_helper_obj = GbpResourceCreator(lib_obj)
print gbp_helper_obj.create_gbp_resources(gbp_resource_info)
"""
