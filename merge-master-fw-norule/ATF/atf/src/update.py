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

"""
This module contains classes & methods for validating gbp
resources (which are part of service chain) updation.
"""

import copy
import json
import sys
import time

from atf.config import template_config, gbp_config
import atf.config.common_config as config
import atf.lib.gbp_resource_create as gbp_resource_create
import atf.lib.nvp_atf_logging as log
from atf.lib.gbp_resource_create import get_stack_by_node_id
from atf.src.service_resources import ServiceResources
sys.path.append("../../")

LOG_OBJ = log.get_atf_logger()


class UpdateTestsHelper(ServiceResources):
    """
    Class contains helper functions used in gbp resource update
    tests.
    """
    def __init__(self, gbp_resources_info, update_tc_info, gbp_resource_obj,
                 traffic_obj, traffic_prepare_obj):

        ServiceResources.__init__(self, gbp_resources_info,
                                  update_tc_info)
        self.gbp_resource_create_obj = gbp_resource_obj
        self.lib_os_obj = self.gbp_resource_create_obj.lib_os_obj
        # set cloud admin token.
        self.lib_os_obj.set_cloud_admin_info(only_token=True)
        self.traffic_obj = traffic_obj
        self.traffic_prepare_obj = traffic_prepare_obj

    def validate_service_vm_deletion(self):
        """
        Validates if service vms got deleted or not. Function will
        get service vm details from gbp resource dictionary.
        Returns:
            1. On success returns list of dictionaries containing
                status of service vm.
                [{
                    "vm_id": vm_id,
                    "service_type": service_type,
                    "status": "active / deleted"  # deleted if vm deleted.
                                                # active if vm is not deleted.
                }, {}, ...]
            2. On failure returns string containing error message.
        """
        try:
            svm_del_report = []
            service_details = self.get_service_details()
            if type(service_details) is str:
                return service_details

            for service in service_details:
                if service["service_type"].lower() == "fw" and\
                        not service.get("service_details"):
                    # fw & vpn services shares same vm.
                    continue

                vm_id = service["service_details"][
                                    "consumer_provider_interfaces"][0][1][
                                                                "vm_id"]
                service_type = service["service_type"]
                status = self.lib_os_obj.poll_on_server_to_delete(vm_id)
                if type(status) is bool:
                    svm_del_report.append({"vm_id": vm_id,
                                           "service_type": service_type,
                                           "status": "deleted"
                                           })
                else:
                    svm_del_report.append({"vm_id": vm_id,
                                           "service_type": service_type,
                                           "status": "active"
                                           })
            LOG_OBJ.info("Service vm delete report: %s" % svm_del_report)
            return svm_del_report
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while validating service vm deletion."

    def get_stack_details_by_node_id(self, **kwargs):
        """
        Gets details of stacks by node id.
        Optional Arguments:
            node_id: service chain node id.
        Returns: On success returns list of stack ids.
            On failure returns string containing error message.
        """
        try:
            # get service chain node details.
            stack_id_list = []
            if kwargs.get("node_id"):
                stack_details = get_stack_by_node_id(
                        self.gbp_resource_create_obj.heat_lib_obj,
                        kwargs["node_id"])
                if type(stack_details) is str:
                    return stack_details
                return [stack_details["id"]]

            # get node details from gbp resources dictionary.
            node_details = self.get_service_chain_node_details()
            if type(node_details) is str:
                return node_details
            for node in node_details:
                stack_details = get_stack_by_node_id(
                        self.gbp_resource_create_obj.heat_lib_obj, node["id"])
                if type(stack_details) is str:
                    return stack_details
                stack_id_list.append(stack_details["id"])
            LOG_OBJ.info("Stack id list: %s" % stack_id_list)

            return stack_id_list
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while getting stack details."

    def validate_stack_cleanup(self, stack_id_list, **kwargs):
        """
        Validates if stacks are deleted or not.
        Arguments:
            1. stack_id_list: list of stack ids.
        Returns: On successful deletion of stacks return True.
            On failure string containing error message.
        """
        try:
            try:
                assert type(stack_id_list) is list, "ATFError: stack id"\
                    " list must be list."
            except AssertionError, err:
                LOG_OBJ.error(err)
                return str(err)

            # get stack list.
            stack_list = self.gbp_resource_create_obj.\
                heat_lib_obj.stack_list()
            if type(stack_list) is not list:
                err_msg = "Stacks cleanup validation failed as "\
                    "listing stacks failed."
                LOG_OBJ.error(err_msg)
                return err_msg

            # validate stack cleanup.
            for stack in stack_list:
                if stack["id"] in stack_id_list:
                    err_msg = "Stack with id %s didn't cleaned"\
                        " up." % stack["id"]
                    LOG_OBJ.warning(err_msg)
                    return err_msg
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while validating stack cleanup."

    def get_new_services_details(self, service_type, provider_ptg_ids,
                                 traffic_type='e-w', node_id=None, **kwargs):
        """
        Arguments:
            1. service_type: lb, vpn, fw.
            2. provider_ptg_ids: list of provider ptg ids.
            3. traffic_type: e-w / n-s.
            4. node_id: service chain node id. required if service type is lb.
        Returns:
            1. Dictionary containing details of services.
                {
                    "service_type": "",
                    "service_details" : {
                        'consumer_provider_interfaces': [
                                    (
                                        { # consumer iface details.
                                            'subnet_id': "",
                                            'fixed_ip': "",
                                            'cidr': ""
                                        },  # will None if n-s
                                        { # provider iface details.
                                            'network_id': "",
                                            'subnet_id': "",
                                            'cidr': "",
                                            'host_name': ""
                                            'fixed_ip': "",
                                            'vm_id': "",
                                            'iface_name': "",
                                            'port_id': ""
                                        }
                                        ), (), ...],
                    "vip_details": {
                                    "pool_id": "",
                                    "fixed_ip": "",
                                    "id": "",
                                    "floating_ip": ""
                                }  # if service type is lb.
                }
            2. On failure returns string containing error message.
        """
        try:
            try:
                assert type(service_type) is str and service_type.lower() in\
                    ["lb", "fw", "vpn"], "ATFError: Service type %s is not"\
                    " valid to access svm details." % service_type
                assert traffic_type.lower() in ['e-w', 'n-s'], "ATFError:"\
                    " Invalid traffic type %s" % traffic_type
                assert type(provider_ptg_ids) is list, "ATFError: provider"\
                    "ptg ids should provided in list."
            except Exception, err:
                LOG_OBJ.error(err)
                return str(err)
            service_details = {}
            service_details["service_type"] = service_type
            # get service vm details.
            svm_info = self.gbp_resource_create_obj.get_svm_info(
                                    self.lib_os_obj.project_info["project_id"],
                                    service_type,
                                    provider_ptg_ids
                                    )
            if type(svm_info) is str:
                return svm_info
            service_details["service_details"] = svm_info

            # vip details if service type is lb.
            if service_type.lower() == "lb":
                # get stack details.
                stack_details = get_stack_by_node_id(
                                self.gbp_resource_create_obj.heat_lib_obj,
                                node_id)
                if type(stack_details) is str:
                    return stack_details
                vip_floating_ip = True if traffic_type == 'n-s' else False
                # get vip details.
                vip_details = self.gbp_resource_create_obj.\
                    get_vip_details(stack_details["id"],
                                    create_floating_ip=vip_floating_ip)
                if type(vip_details) is str:
                    return vip_details
                service_details["service_details"]["vip_details"] = vip_details
            return service_details
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while getting details "\
                "of newly created services."


class UpdateAction(UpdateTestsHelper):
    """Class for action updation test case"""

    def __init__(self, gbp_resources_info, update_tc_info,
                 gbp_resource_obj, validate_traffic_obj, traffic_prepare_obj):
        UpdateTestsHelper.__init__(
                    self, gbp_resources_info, update_tc_info,
                    gbp_resource_obj, validate_traffic_obj,
                    traffic_prepare_obj)

    def update_action(self):
        """ master method
            Returns: On Success: True
                On Failure: string containing error message.
        """
        if self.operation == "delete":
            status = self.update_action_redirect2redirect()
            if type(status) is str:
                return (False, status)
            return (True, "")
        return (False, "ATFError: Unsupported update action test scenario.")

    def update_action_redirect2redirect(self):
        """
        updates the action i.e, redirect from n-s fw+lb to n-s fw.
        checks fw + lb deleted and new fw launched.
        Does traffic validation.

        Return: On success: True
            On Failure: string containing error message.
        """
        try:
            # Get action details
            action = self.get_policy_action_details(action_type="redirect")
            if not isinstance(action, list):
                return action

            # Get the fw node details
            fw_node = self.get_servicechain_node_details(service_type="fw")
            if not isinstance(fw_node, list):
                return fw_node

            # create service chain spec for fw chain.
            fw_spec = self.gbp_resource_create_obj.\
                create_srvc_chain_spec_helper([fw_node[0]["node"]["id"]])
            if not isinstance(fw_spec, dict):
                return fw_spec

            # Update the action, with new spec for chain containing firewall.
            updated_action = self.gbp_resource_create_obj.gbp_res_obj.\
                update_policy_action(action[0].get("action_id"),
                                     action_value=fw_spec['id'])
            if not isinstance(updated_action, dict):
                return updated_action

            # validate service vm deletion on updating policy action.
            svm_del_report = self.validate_service_vm_deletion()
            if type(svm_del_report) is str:
                return svm_del_report

            # validate if lb service vm deleted or not.
            if "deleted" not in [vm["status"] for vm in svm_del_report
                                 if vm["service_type"].lower() == "lb"]:
                err_msg = "Service vm related load balancer service"\
                    " didn't deleted."
                LOG_OBJ.error(err_msg)
                return err_msg
            # firewall service vm deleted or not.
            if "deleted" not in [vm["status"] for vm in svm_del_report
                                 if vm["service_type"].lower() == "fw"]:
                err_msg = "Service vm related firewall service"\
                    " didn't deleted."
                LOG_OBJ.error(err_msg)
                return err_msg

            # prepare dictionary for traffic validation.
            traffic_resource_dict = self.traffic_prepare_obj.\
                prepare_for_traffic_validation()
            if not isinstance(traffic_resource_dict, dict):
                return traffic_resource_dict

            # NOTE: if only firewall in chain & traffic direction in
            # north-south vms in provider target group must have
            # floating ips associated.
            # Associating floating ips to the provider side targets
            pt_dict = self.get_policy_targets()
            policy_targets = [pt_dict.get("provider")[0]]
            fix_ip = policy_targets[0].get("vm_ip")
            from atf.lib.gbp_resource_create import \
                create_floatingip_for_targets
            flip_list = create_floatingip_for_targets(
                        self.gbp_resource_create_obj.lib_os_obj,
                        policy_targets)
            for provider_pt in \
                    traffic_resource_dict.get("provider_pt_details"):
                if fix_ip == provider_pt.get("pt_ip"):
                    break
            else:
                msg = "Not able to map floating ip"
                LOG_OBJ.error(msg)
                return msg

            provider_pt["floating_ip"] = flip_list[0]
            traffic_resource_dict["provider_pt_details"] = [provider_pt]

            # Get details of newly created firewall service vm.
            provider_ptg_ids = [pt_dict["provider"][0][
                                            "policy_target_group_id"]]
            fw_service_details = self.get_new_services_details(
                                        "FW", provider_ptg_ids,
                                        "n-s", node_id=None)
            if type(fw_service_details) is str:
                return fw_service_details

            service_details = self.traffic_prepare_obj.prepare_service_details(
                                        False, services=[fw_service_details])
            if type(service_details) is str:
                return service_details
            traffic_resource_dict["service_details"] = service_details

            # validate the traffic.
            status, msg = self.traffic_obj.generate_validate_traffic(
                                                        traffic_resource_dict)
            if not status:
                return msg
            return True
        except Exception as err:
            err_msg = "Exception occurred in policy action update tests."
            LOG_OBJ.exception(err)
            return err_msg


class UpdateRule(UpdateTestsHelper):
    """ Class contains methods for validating policy rule update
        test cases.
          tests:-
              (1) policy rule update (redirect action ==> allow action).
              (2) policy rule update (allow action ==> redirect action).
    """
    def __init__(self, gbp_resources_info, update_tc_info,
                 gbp_resource_obj, traffic_obj, traffic_prepare_obj):
        UpdateTestsHelper.__init__(
                    self, gbp_resources_info, update_tc_info,
                    gbp_resource_obj, traffic_obj, traffic_prepare_obj)

    def update_rule(self):
        """Master function for running rule update
           test cases."""
        if self.operation == "delete":
            status = self.rule_update_redirect2allow()
            if type(status) is str:
                return (False, status)
            return (True, "")
        elif self.operation == "add":
            status = self.rule_update_allow2redirect()
            if type(status) is str:
                return (False, status)
            return (True, "")
        else:
            err_msg = "Operation %s is not supported by automation"\
                " framework." % self.operation
            LOG_OBJ.error(err_msg)
            return (False, err_msg)

    def rule_update_redirect2allow(self):
        """ update policy rule (redirect action => allow action)
            Return: On success returns True.
                On Failure returns string containing error message.
        """
        try:
            # get policy rule details with action type redirect.
            policy_rules_details = self.get_policy_rule_details(
                                                        action_type="redirect")
            if type(policy_rules_details) is not list:
                err_msg = str(policy_rules_details)
                return err_msg

            LOG_OBJ.info("Policy rule details: %s" % policy_rules_details)

            # create new policy action with type allow.
            print "Creating new policy action with type \"allow.\""
            LOG_OBJ.debug("Creating new policy action with type \"allow.\"")
            allow_action_details = self.gbp_resource_create_obj.\
                create_policy_action_helper("allow")
            if type(allow_action_details) is not dict:
                return str(allow_action_details)

            # get stack details. before updating policy rule.
            stack_id_list = self.get_stack_details_by_node_id()
            if type(stack_id_list) == str:
                return stack_id_list
            LOG_OBJ.info("Stack before updating policy"
                         " rule: %s" % stack_id_list)

            # update policy rule (change redirect action with allow action)
            # After update policy rule from redirect -> allow service vms
            # should be deleted. Also stacks should be deleted.
            policy_rule_id = policy_rules_details[0].get("rule_id")
            allow_action_id = allow_action_details.get("id")
            updated_action = self.gbp_resource_create_obj.\
                gbp_res_obj.update_policy_rule(
                                            policy_rule_id,
                                            policy_actions=[allow_action_id])
            if type(updated_action) != dict or allow_action_id not in\
                    updated_action.get("policy_actions"):
                err_msg = "Failed to updating policy rule %s with new policy"\
                    " action %s." % (policy_rule_id, allow_action_id)
                LOG_OBJ.error(err_msg)
                return err_msg

            # After updating policy rule with allow action service vms should
            # deleted. Validate service vms got deleted or not.
            status_report = self.validate_service_vm_deletion()
            if type(status_report) is str:
                return status_report

            if "active" in [vm["status"] for vm in status_report]:
                err_msg = "Some service vms didn't deleted after"\
                    " updating policy rule."
                LOG_OBJ.error(err_msg)
                return err_msg
            print "After updating policy rule (redirect action to allow "\
                "action) service vms got deleted as expected."
            LOG_OBJ.debug("After updating policy rule (redirect action to "
                          "allow action) service vms got deleted as expected.")

            # validate if stacks are cleaned up or not.
            status = self.validate_stack_cleanup(stack_id_list)
            if type(status) is str:
                return status
            print "After updating policy rule (redirect action to "\
                "allow action) stacks deleted properly."
            LOG_OBJ.debug("After updating policy rule (redirect action to "
                          "allow action) stacks deleted properly.")

            # Planned not to validate traffic as there is no
            # service in between target groups.

            return True
        except Exception as err:
            err_msg = "Exception occurred while executing policy "\
                "rule update test case."
            LOG_OBJ.exception(err)
            return err_msg

    def rule_update_allow2redirect(self):
        """ Update policy rule (allow action => redirect action.)
            Returns: On success returns True
                On failure returns string containing error message.
        """
        try:
            services = []
            # create policy target groups with policy targets
            # with action type allow.
            gbp_resources_info = self._create_gbp_resources_with_allow_action()
            if type(gbp_resources_info) is str:
                return gbp_resources_info

            # set gbp_resources_info of class ServiceResources.
            self.set_gbp_resources_info(gbp_resources_info)
            # set gbp_resources_info of class TafficPreparation.
            self.traffic_prepare_obj.set_gbp_resources_info(
                                                gbp_resources_info)

            # get policy rule id.
            allow_policy_rules = self.get_policy_rule_details(
                                                        action_type="allow")
            if type(allow_policy_rules) is str:
                return allow_policy_rules

            # create policy chain node.
            # TODO: modify to read protocol & port from config file.
            classifier_details = {"protocol": "tcp", "port": gbp_config.
                                  protocol_port_details['tcp'].split(':')[0],
                                  "direction": "in"}
            node_details = self.gbp_resource_create_obj.\
                create_srvc_chain_node_helper("FW", **classifier_details)
            if type(node_details) is not dict:
                err_msg = "Service chain node creation failed."
                LOG_OBJ.error(err_msg)
                return err_msg

            # create service chain spec.
            spec_details = self.gbp_resource_create_obj.\
                create_srvc_chain_spec_helper([node_details["id"]])
            if type(spec_details) is not dict:
                err_msg = "Service chain spec creation failed."
                LOG_OBJ.error(err_msg)
                return err_msg
            # create redirect action.
            action_details = self.gbp_resource_create_obj.\
                create_policy_action_helper("redirect",
                                            action_value=spec_details["id"])
            if type(action_details) is not dict:
                err_msg = "Redirect action creation failed."
                LOG_OBJ.error(err_msg)
                return err_msg

            # update policy rule (allow action => redirect action).
            rule_id = allow_policy_rules[0]["rule_id"]
            gbp_construct_driver = self.gbp_resource_create_obj.gbp_res_obj
            updated_policy_rule = gbp_construct_driver.\
                update_policy_rule(rule_id,
                                   policy_actions=[action_details["id"]])
            if type(updated_policy_rule) is not dict or\
                    action_details["id"] not in\
                    updated_policy_rule["policy_actions"]:
                err_msg = "Failed to update policy rule %s with new"\
                    " action %s." % (rule_id, action_details["id"])
                LOG_OBJ.error(err_msg)
                return err_msg

            # validate if service vm is created or not.
            service_type = "FW"
            traffic_type = "e-w"

            # get policy target group details.
            ptg_details = self.get_ptg_ids()
            consumer_id = ptg_details.get("consumer_id")
            provider_id = ptg_details.get("provider_id")
            if consumer_id is None and provider_id is None:
                err_msg = "Failed get provider & consumer details of"\
                    " policy target groups."
                LOG_OBJ.error(err_msg)
                return err_msg
            provider_ptg_ids = [provider_id]
            service_details = self.get_new_services_details(
                                        service_type, provider_ptg_ids,
                                        traffic_type)
            if type(service_details) is not dict:
                err_msg = "Failed to get service vm details after"\
                    " updating policy rule."
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.info("Service details: %s" % service_details)
            services.append(service_details)

            # prepare dictionaries for traffic validation.
            traffic_resource_dict = self.prepare_for_traffic_validation(
                                            services, classifier_details,
                                            traffic_type)
            if type(traffic_resource_dict) is not dict:
                return str(traffic_resource_dict)
            LOG_OBJ.info("Traffic dictionary: %s" % traffic_resource_dict)

            # validate traffic after updating policy rule.
            status, msg = self.traffic_obj.generate_validate_traffic(
                                                    traffic_resource_dict)
            if not status:
                LOG_OBJ.error(msg)
                return msg
            return True
        except Exception as err:
            err_msg = "Problem while executing policy rule update test case."
            LOG_OBJ.exception(err)
            return err_msg

    def _create_gbp_resources_with_allow_action(self):
        """
        It will create consumer & provider groups with policy targets.
        without service vm in between . And return details of resources
        created.
        Returns: On Success returns dictionary containing gbp resources info.
            On Failure returns string containing error message.
        """
        try:
            # input dictionary for creating gbp resources.
            gbp_resource_info = {
                        "shared": False,
                        "traffic_type": "e-w",
                        "policy_rules": [
                                    {
                                        "policy_classifier": {
                                                "direction": "in",
                                                "protocol": "tcp",
                                                "ports": gbp_config.
                                                protocol_port_details["tcp"].
                                                split(':')[0]
                                                },
                                        "policy_action_type": "allow"
                                     }
                                ]
                        }
            # create gbp resources.
            resource_info = self.gbp_resource_create_obj.create_gbp_resources(
                                                            gbp_resource_info)
            if type(resource_info) is str:
                return resource_info
            print "GBP Resources: %s" % resource_info
            LOG_OBJ.info("GBP Resources: %s" % resource_info)
            return resource_info
        except Exception as err:
            err_msg = "Exception occurred."
            LOG_OBJ.exception(err)
            return err_msg

    def prepare_for_traffic_validation(self, services, classfier_details,
                                       traffic_type="e-w"):
        """
        Prepares dictionaries for traffic validation.
        Argument:
            1. services: list of dictionaries containing service vm details.
            2. classfier_details: classifier details like protocol, port,
                direction.
                e.g.
                    {"protocol": "", "port": "", "direction": ""}
            3. tarffic_type: e-w / n-s
        Returns: On success returns dictionary.
                {
                    'classifiers': [],
                    'consumer_pt_details': [],
                    'provider_pt_details': [],
                    'service_details': []
                }
            On Failure returns string containing error message.
        """
        try:
            traffic_resource_dict = {'classifiers': [],
                                     'consumer_pt_details': [],
                                     'provider_pt_details': [],
                                     'service_details': []}
            # Fill the consumer details.
            consumers = self.traffic_prepare_obj.\
                prepare_consumer_details(traffic_type=traffic_type)
            if not isinstance(consumers, list):
                return consumers
            traffic_resource_dict['consumer_pt_details'] = consumers

            # Filling provider details
            providers = self.traffic_prepare_obj.\
                prepare_provider_details(traffic_type=traffic_type)
            if not isinstance(providers, list):
                return providers
            traffic_resource_dict['provider_pt_details'] = providers

            traffic_resource_dict['classifiers'].append(classfier_details)

            # Filling service node details
            service_details = self.traffic_prepare_obj.prepare_service_details(
                                                False, services=services,
                                                traffic_type=traffic_type)
            if not isinstance(service_details, list):
                return service_details
            traffic_resource_dict['service_details'] = service_details

            LOG_OBJ.debug("traffic_resource_dict : %s" % traffic_resource_dict)
            return traffic_resource_dict

        except Exception, err:
            LOG_OBJ.exception(err)
            return "Problem while preparing for traffic validation."


class UpdateSpec(UpdateTestsHelper):
    """
    This class is for service-chain-spec update test cases.
    """

    def __init__(self, gbp_resource_info, update_tc_info,
                 gbp_resource_obj, validate_traffic_obj,
                 traffic_prepare_obj):
        UpdateTestsHelper.__init__(self, gbp_resource_info, update_tc_info,
                                   gbp_resource_obj, validate_traffic_obj,
                                   traffic_prepare_obj)

    def update_spec(self):
        """
        Wrapper function which would be called by master function.
        Returns: Tuple
            On success: (True, "")
            On failure: (False, "Failure/Error Message")
        """
        if self.operation == 'add':
            status = self.update_spec_add_service()
            if type(status) is str:
                return (False, status)
            return (True, "")
        else:
            status = self.update_spec_delete_service()
            if type(status) is str:
                return (False, status)
            return (True, "")

    def update_spec_add_service(self):
        """
        Function to test service-chain-spec update by adding new
        resources (service chain nodes).

        Returns: On success True
            On failure string containing error message.
        """
        try:
            # Get service-chain-spec details.
            spec_details = self.get_servicechain_spec_details()
            if type(spec_details) is str:
                return spec_details
            spec_id = spec_details[0]
            # get service details from gbp_resources_dictionary.
            services = self.get_service_details()
            if type(services) is str:
                return services
            # get service chain node ids from gbp resources dictionary.
            node_fw = ""
            node_lb = ""
            for service in services:
                if service['service_type'].lower() == 'fw':
                    node_fw = service['node']['id']
                if service['service_type'].lower() == 'lb':
                    node_lb = service['node']['id']
            if not node_fw or not node_lb:
                err_msg = "ATFError: Firewall or loadbalancer node "\
                    "details missing in gbp resources dictionary."
                LOG_OBJ.error(err_msg)
                return err_msg

            # create new remote tenant.
            # Get the remote project info and update it.
            self.remote_project_info = \
                config.remote_project_info[0].copy()
            self.remote_project_info['project_name'] += \
                str(self.remote_project_info['project_no'])
            config.remote_project_info[0]['project_no'] += 1

            vpn_server_required = True
            svc_type = 'vpn'
            # Create remote resources.
            remote_info = self.gbp_resource_create_obj.\
                create_remote_resources(self.lib_os_obj.host_ip,
                                        self.remote_project_info,
                                        vpn_server_required)
            if isinstance(remote_info, str):
                return remote_info

            # Create VPN node to add.
            node_dict = {
                'node_name': svc_type,
                'vpn_server_info': remote_info['vpn_server_info'],
                'remote_client_info': remote_info[
                    'remote_client_info'],
                'vpn_type': 's2s'
            }
            node_vpn = self.gbp_resource_create_obj.\
                create_srvc_chain_node_helper(svc_type, **node_dict)
            if isinstance(node_vpn, str):
                return node_vpn

            # update service-chain-spec. Add vpn node to chain (fw + lb)
            spec = self.gbp_resource_create_obj.gbp_res_obj.\
                update_service_chain_spec(spec_id, nodes=[node_vpn['id'],
                                                          node_fw, node_lb])
            if not isinstance(spec, dict):
                err_msg = "Problem while updating service chain spec."
                LOG_OBJ.error(err_msg)
                return err_msg
            # valiadte service vm deletion.
            svm_del_report = self.validate_service_vm_deletion()
            if type(svm_del_report) is str:
                return svm_del_report
            if "deleted" in [vm['status'] for vm in svm_del_report]:
                err_msg = "After updating service chain spec, "\
                    "firewall or loadbalancer vm get deleted."
                LOG_OBJ.error(err_msg)
                return err_msg

            # validate that VPN, FW & LB service VMs launched properly.
            ptg_pair_ids = self.get_ptg_ids()
            if not ptg_pair_ids["provider_id"]:
                err_msg = "Problem while getting ptg details."
                LOG_OBJ.error(err_msg)
                return err_msg

            services = []
            for service in ['VPN', 'FW', 'LB']:
                if service.lower() == "fw":
                    continue   # vpn & fw shares same service vm.
                node_id = node_lb if service.lower() == "lb" else None
                svm_details = self.get_new_services_details(
                                    service, [ptg_pair_ids["provider_id"]],
                                    self.traffic_type, node_id=node_id)
                if type(svm_details) is str:
                    return svm_details
                services.append(svm_details)

            # Create traffic_resource_dict.
            service_details = self.traffic_prepare_obj.\
                prepare_service_details(True, services)
            if not isinstance(service_details, list):
                return service_details

            consumer_details = self.traffic_prepare_obj.\
                prepare_consumer_details(
                            policy_targets=[remote_info['remote_client_info']])
            if not isinstance(consumer_details, list):
                return consumer_details

            policy_targets = self.traffic_prepare_obj.\
                prepare_provider_details(lb_in_chain=True)
            if not isinstance(policy_targets, list):
                return policy_targets

            classifier = self.traffic_prepare_obj.prepare_classifier_details()
            if not isinstance(classifier, dict):
                err_msg = "Problem while getting classifier details."
                LOG_OBJ.error(err_msg)
                return err_msg

            traffic_resource_dict = {
                'classifiers': [classifier],
                'consumer_pt_details': consumer_details,
                'provider_pt_details': policy_targets,
                'service_details': service_details
                }

            # Configure the new site to site remote server and client.
            # Get the VPN service details.
            vpn_service = [service for service in services if
                           service["service_type"].lower() == "vpn"][0]

            # Get the provider PTG details.
            provider_tg = \
                self.gbp_resources_info['ptg_info']['provider']['ptg_details']

            status = self.gbp_resource_create_obj.configure_remote_resources(
                remote_info,
                vpn_service['service_details'][
                            'consumer_provider_interfaces'][0][0],
                cloud_client_subnet_id=provider_tg['subnets'][0])
            if not isinstance(status, bool):
                return status

            # Validate the traffic.
            status, err_msg = \
                self.traffic_obj.generate_validate_traffic(
                    traffic_resource_dict)
            if status is True:
                return status
            LOG_OBJ.error(err_msg)
            return err_msg
        except Exception as err:
            err_msg = "Exception occurred while executing service"\
                " chain spec update test."
            LOG_OBJ.exception(err)
            return err_msg

    def update_spec_delete_service(self):
        """
        Function to test service-chain-spec update by deleting resources
        (service chain nodes).

        Returns: On success: True.
            On failure: string containing error message.
        """
        try:
            # Get service-chain-spec ID.
            spec_details = self.get_servicechain_spec_details()
            if type(spec_details) is str:
                return spec_details
            spec_id = spec_details[0] if len(spec_details) > 0 else None

            # Get services details.
            services = self.get_service_details()
            if type(services) is str:
                return services

            # Get service chain node details.
            node_details = self.get_servicechain_node_details()
            if type(node_details) is str:
                return node_details
            if len(node_details) < 3:
                err_msg = "Details of service chain nodes missing in gbp "\
                    "resources dictionary. Test expecting details for "\
                    "vpn, fw, and lb services."
                LOG_OBJ.error(err_msg)
                return err_msg
            node_ids = {"fw": None, "vpn": None, "lb": None}
            for node in node_details:
                node_ids[node["service_type"].lower()] = node["node"]["id"]

            # Update service chain spec. Remove lb node from spec.
            spec = self.gbp_resource_create_obj.gbp_res_obj.\
                update_service_chain_spec(
                        spec_id, nodes=[node_ids["vpn"], node_ids["fw"]])
            if not isinstance(spec, dict):
                err_msg = "Problem while updating service chain spec."
                LOG_OBJ.error(err_msg)
                return err_msg

            # poll on service vm deletion. LB service vm should be deleted.
            # vpn & fw vms should not be deleted.
            svm_del_report = self.validate_service_vm_deletion()
            if type(svm_del_report) is str:
                return svm_del_report
            if "active" in [vm["status"] for vm in svm_del_report
                            if vm["service_type"].lower() == "lb"]:
                err_msg = "Service vm related to load balancer service didn't"\
                    " deleted after updating service chain spec."
                LOG_OBJ.error(err_msg)
                return err_msg
            # vpn & fw vms should br intact.
            if "deleted" in [vm["status"] for vm in svm_del_report
                             if vm["service_type"].lower() != "lb"]:
                err_msg = "Service vm related to vpn or fw got"\
                    " deleted after updating service chain spec."
                LOG_OBJ.error(err_msg)
                return err_msg

            # Verify LB service's stack got deleted.
            stack_details = self.get_stack_details_by_node_id(
                                                node_id=node_ids["lb"])
            if isinstance(stack_details, list):
                err_msg = "Stack related to the load balancer service vm"\
                     "didn't deleted, after updating service chain spec."
                LOG_OBJ.error(err_msg)
                return err_msg

            # Create traffic_resource_dict.
            traffic_resource_dict = self.traffic_prepare_obj.\
                prepare_for_traffic_validation()
            if not isinstance(traffic_resource_dict, dict):
                err_msg = traffic_resource_dict
                return err_msg

            for ind, svm_info in enumerate(services):
                if svm_info["service_type"].lower() == "lb":
                    del services[ind]

            service_details = self.traffic_prepare_obj.\
                prepare_service_details(True, services)
            if not isinstance(service_details, list):
                return service_details
            traffic_resource_dict['service_details'] = service_details

            provider_pt_details = self.traffic_prepare_obj.\
                prepare_provider_details(lb_in_chain=False)
            if type(provider_pt_details) is str:
                return provider_pt_details
            traffic_resource_dict["provider_pt_details"] = provider_pt_details

            # Validate the traffic.
            status, err_msg = \
                self.validate_traffic_obj.generate_validate_traffic(
                    traffic_resource_dict)
            if status is True:
                return status
            LOG_OBJ.error(err_msg)
            return err_msg
        except Exception as err:
            err_msg = "Exception occurred."
            LOG_OBJ.exception(err)
            return err_msg


class UpdateNode(ServiceResources):
    """Update the Service Chain Node"""

    def __init__(self, gbp_resources_info, update_tc_info,
                 gbp_resource_obj, validate_traffic_obj,
                 traffic_preparation_obj):
        # Initialize the super class constructor.
        ServiceResources.__init__(self, gbp_resources_info, update_tc_info)

        self.gbp_resource_obj = gbp_resource_obj
        self.gbp_construct_obj = gbp_resource_obj.gbp_res_obj
        self.lib_os_obj = gbp_resource_obj.lib_os_obj
        self.heat_lib_obj = gbp_resource_obj.heat_lib_obj
        self.lbaas_obj = gbp_resource_obj.lbaas_obj

        self.validate_traffic_obj = validate_traffic_obj
        self.traffic_prep_obj = traffic_preparation_obj

    # @decorator
    # def process_template(fun, template, **kwargs):
    #    pass
    @staticmethod
    def update_fw_template(template, protocol, port=""):
        """It updates the given fw template with new protocol and/or port.
        params: template: Template in json
                protocol: Protocol for which fw allow rule to be added.
                port: Port for which fw allow rule to be added.
        return: tuple containing status(bool) and template/error message (str).
        """
        try:
            fw_template_in_dict = json.loads(template)
            resources = fw_template_in_dict["resources"]
            fw_policy_rules = resources["Firewall_Policy"]["properties"][
                "firewall_rules"]
            rule_name = "Rule_%s" % (len(fw_policy_rules) + 1)
            fw_policy_rules.append({"get_resource": rule_name})
            properties = {"action": "allow",
                          "enabled": True,
                          "protocol": protocol,
                          "name": rule_name}
            if protocol.lower() != "icmp" and port:
                properties.update({"destination_port": str(port)})

            resources[rule_name] = {"type": "OS::Neutron::FirewallRule",
                                    "properties": properties}

            fw_template_in_json = json.dumps(fw_template_in_dict)
            LOG_OBJ.debug("FW template updated successfully. Template: %s" %
                          fw_template_in_json)
            return (True, fw_template_in_json)

        except Exception as err:
            LOG_OBJ.exception(err)
            return (False, "Problem while updating template")

    @staticmethod
    def update_vpn_template(template, remote_resources):
        """It updates the site-to-site vpn template with the new remote
        resources. It basically adds the new remote in the existing
        remote resources.
        params:
            template: Template in json.
            remote_resources: Remote resources info.
        return: tuple containing status(bool) and template/error message (str).
        """
        try:
            vpn_template_in_dict = json.loads(template)
            # print ("vpn template:%s" % vpn_template_in_dict)
            # LOG_OBJ.debug(("vpn template:%s" % vpn_template_in_dict))

            resources = vpn_template_in_dict["resources"]
            total_sites = len([site for site in resources.keys()
                               if 'site_to_site_connection' in site])
            key_name = 'site_to_site_connection' + str(total_sites + 1)

            # Get the S2S connection template format
            s2s_conn = template_config.vpn_s2s_connection.values()[0]
            s2s_conn_properties = s2s_conn['properties']

            # Update the node with the remote resource info.
            s2s_conn_properties.update({
                'peer_address':
                remote_resources['vpn_server_info']['floating_ip'],
                'peer_id': remote_resources['vpn_server_info']['listen_iface'],
                'peer_cidrs': [remote_resources['remote_client_info']['cidr']],
                'psk': gbp_config.vpn_s2s_secret_key,
                'name': key_name
            })
            resources.update({key_name: s2s_conn})

            vpn_template_in_json = json.dumps(vpn_template_in_dict)
            LOG_OBJ.debug("VPN template updated successfully. Template: %s" %
                          vpn_template_in_json)
            return (True, vpn_template_in_json)

        except Exception as err:
            LOG_OBJ.exception(err)
            return (False, "Problem while updating template")

    def __validate_pool_resources__(self, vip_details):
        """This validates the pool resources: pool, vip, and members after
        the  LB node is updated."""
        try:
            pool_id = vip_details['pool_id']
            vip_id = vip_details['id']
            # Get the members of the pool.
            members = self.lbaas_obj.get_pool_members(pool_id)
            if not isinstance(members, list):
                err_msg = "Problem while getting members."
                LOG_OBJ.error(err_msg)
                return err_msg
            ids = [pool_id, vip_id]
            ids.extend(members)
            # poll on each resources
            resource_name = "pool"
            for _id in ids:
                if _id == vip_id:
                    resource_name = "vip"
                elif _id in members:
                    resource_name = "member"
                out = self.gbp_resource_obj.lbaas_obj.poll_on_resource_status(
                    resource_name, _id, "ACTIVE", monitor_duration=60)
                if not isinstance(out, str) or out.lower() == "error":
                    err_msg = "Problem while polling on %s" % resource_name
                    if isinstance(out, str):
                        err_msg = "The %s is in state: %s after LB node "\
                            " update" % (resource_name, out)
                    LOG_OBJ.error(err_msg)
                    return str(err_msg)
                LOG_OBJ.debug("The %s is active after LB node update." %
                              resource_name)

            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while validating pool resources."

    def __update_validate_helper__(self, svm_id, node_id, template,
                                   traffic_resource_dict, resource="FW",
                                   operation="rule add", vip_details=None):
        """It updates the node, validate traffic."""
        try:
            # print "===>template: %s, traffic_resource_dict:%s" % \
            #    (template, traffic_resource_dict)
            # LOG_OBJ.debug("===>template: %s, traffic_resource_dict:%s" % \
            #    (template, traffic_resource_dict))

            # Update the node
            updated_node = self.gbp_construct_obj.update_service_chain_node(
                node_id, config=template)
            if not isinstance(updated_node, dict):
                LOG_OBJ.error("Problem while updating %s node!" % resource)
                return "Problem while updating %s node!" % resource
            # Get stack details and Poll on the newly created stack.
            stack_details = gbp_resource_create.get_stack_by_node_id(
                self.heat_lib_obj, node_id)
            if not isinstance(stack_details, dict):
                return stack_details
            # Check whether the service is deleted or NOT.
            if isinstance(self.lib_os_obj.poll_on_server_to_delete(
                    svm_id, monitor_time=20), bool):
                err_msg = "The SVM is deleted after %s updated!" % (resource)
                LOG_OBJ.error(err_msg)
                return err_msg
            msg = "%s node: %s updated (%s) successfully." % \
                (resource, node_id, operation)
            print msg
            LOG_OBJ.info(msg)
            # For LB, also check the pool, vip and member status.
            if resource.lower() == "lb":
                out = self.__validate_pool_resources__(vip_details)
                if not isinstance(out, bool):
                    return out
            LOG_OBJ.info("Validating traffic after %s node update." % resource)
            # Validate traffic after updation.
            status, msg = self.validate_traffic_obj.generate_validate_traffic(
                traffic_resource_dict)
            LOG_OBJ.debug("Traffic validation after %sed in %s node."
                          "\nStatus:%s, msg:%s" %
                          (operation, resource, status, msg))
            if not status:
                err_msg = "Traffic validation failed after updating %s" \
                    " node (for %s). Reason:" % \
                    (resource, operation) + msg
                LOG_OBJ.error(err_msg)
                return err_msg

            return True

        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while updating and validating traffic."

    def update_node(self):
        """This is the interface for this class. This basically updates
        the nodes.
        return: True on success."""
        try:
            if self.resource.lower() == "fw":
                status = self.update_node_fw()
            elif self.resource.lower() == "lb":
                status = self.update_node_lb()
            elif self.resource.lower() == "vpn":
                status = self.update_node_vpn()

            if not isinstance(status, bool):
                return False, status
            return True, status
        except Exception as err:
            LOG_OBJ.exception(err)
            return (False, "Problem while updating node for resource type: %s"
                    % self.update_resource_type)

    def update_node_fw(self):
        """This updates the firewall node by adding the extra allow rule
        and then deletes the newly added rule.
        return: True on success.
        """
        try:
            protocol = "icmp"  # For addding extra allow rule: ICMP
            # Get the fw node details used in the insertion.
            nodes = self.get_servicechain_node_details(service_type="fw")
            if not isinstance(nodes, list):
                return nodes
            fw_node = copy.deepcopy(nodes[0]["node"])
            fw_template = fw_node["config"]
            # Get the service vm ID.
            # NOTE: VPN+FW scenario, so vpn has only details of service vm.
            services = self.get_service_details(service_type="vpn")
            if not isinstance(services, list):
                return services

            fw_service_vm_id = services[0]['service_details'][
                'consumer_provider_interfaces'][0][1]['vm_id']

            # Get the traffic validation info.
            traffic_resource_dict = \
                self.traffic_prep_obj.prepare_for_traffic_validation()
            if not isinstance(traffic_resource_dict, dict):
                return traffic_resource_dict
            traffic_resource_dict_old = copy.deepcopy(traffic_resource_dict)
            # Append the new classifier.
            traffic_resource_dict['classifiers'].append({'protocol': protocol,
                                                         'direction': "in"
                                                         })
            # Phase-1: Add Allow Rule.
            # Get the fw template and update it with the ICMP protocol.
            status_template = self.update_fw_template(fw_template,
                                                      protocol=protocol)
            if not status_template[0]:
                return status_template[1]

            status = self.__update_validate_helper__(
                fw_service_vm_id, fw_node['id'], status_template[1],
                traffic_resource_dict, operation="allow ICMP")
            if not isinstance(status, bool):
                return status

            # Phase-2: Delete Rule.
            # Now delete the ICMP rule from the template and validate traffic.
            status = self.__update_validate_helper__(
                fw_service_vm_id, fw_node['id'], fw_template,
                traffic_resource_dict_old, operation="deny ICMP")
            if not isinstance(status, bool):
                return status

            LOG_OBJ.info("FW node update is successful.")
            return True

        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while updating fw node."

    def update_node_lb(self):
        """It updates the LB node. Update the vip port and protocol."""
        try:
            # TODO: Also update the protocol. Currently there is an issue.
            # protocol = "UDP"
            port = "70"

            # Get the service vm ID
            services = self.get_service_details(service_type="lb")
            if not isinstance(services, list):
                return services
            lb_service_vm_id = services[0]['service_details'][
                'consumer_provider_interfaces'][0][1]['vm_id']

            vip_details = services[0]['service_details']['vip_details']
            # Get the lb node details used in the insertion.
            lb_node = copy.deepcopy(services[0]["node"])
            new_lb_template = template_config.lb_template_config
            resources = new_lb_template["resources"]
            pool = resources["LoadBalancerPool"]['properties']
            # pool["protocol"] = protocol
            pool["vip"]["protocol_port"] = port
            new_lb_template = json.dumps(new_lb_template)

            # Get the traffic validation info.
            traffic_resource_dict = \
                self.traffic_prep_obj.prepare_for_traffic_validation()
            if not isinstance(traffic_resource_dict, dict):
                return traffic_resource_dict
            # Update the classifier to this new protocol and port.
            # traffic_resource_dict['classifiers'][0]['protocol'] = protocol
            traffic_resource_dict['classifiers'][0]['port'] = port

            # update the node and send traffic.
            status = self.__update_validate_helper__(
                lb_service_vm_id, lb_node['id'], new_lb_template,
                traffic_resource_dict, resource="LB",
                operation="VIP port & protocol update",
                vip_details=vip_details)
            if not isinstance(status, bool):
                return status

            LOG_OBJ.info("LB node update is successful.")
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while updating LB Node."

    def update_node_vpn(self):
        """It updates the VPN node (This is basically for Site-to-Site VPN).
        Update the vip port and protocol."""
        try:
            # Launch new remote vpn server and client.
            # Get the remote project info and update it.
            self.remote_project_info = config.remote_project_info[0].copy()
            self.remote_project_info['project_name'] += \
                str(self.remote_project_info['project_no'])
            config.remote_project_info[0]['project_no'] += 1

            # Create the new site2.
            remote_resources_site2 = self.gbp_resource_obj.\
                create_remote_resources(
                    self.lib_os_obj.host_ip, self.remote_project_info, True)
            if not isinstance(remote_resources_site2, dict):
                return remote_resources_site2

            # Get the service vm ID
            services = self.get_service_details(service_type="vpn")
            if not isinstance(services, list):
                return services
            vpn_service_vm_id = services[0]['service_details'][
                'consumer_provider_interfaces'][0][1]['vm_id']
            # Get the vpn node details used in the insertion.
            vpn_node = copy.deepcopy(services[0]["node"])
            vpn_template_old = vpn_node['config']

            # Get the traffic validation info.
            traffic_resource_dict = \
                self.traffic_prep_obj.prepare_for_traffic_validation()
            if not isinstance(traffic_resource_dict, dict):
                return traffic_resource_dict
            traffic_resource_dict_old = copy.deepcopy(traffic_resource_dict)

            # Phase-1: Add a new site to site, validate traffic.

            # Add the consumer side details with the new remote client info.
            client = remote_resources_site2['remote_client_info']

            consumer_info = self.traffic_prep_obj.prepare_consumer_details(
                                            policy_targets=[client])
            if not isinstance(consumer_info, list):
                return consumer_info
            traffic_resource_dict['consumer_pt_details'].extend(consumer_info)

            # Update the VPN template to add this new site.
            status_template = self.update_vpn_template(vpn_template_old,
                                                       remote_resources_site2)
            if not status_template[0]:
                return status_template[1]
            # Configure the new site2's remote server and client.
            # Get the vpn service details.
            services = self.get_service_details(service_type="vpn")
            if not isinstance(services, list):
                return services
            vpn_service = services[0]

            # Get the provider ptg details.
            provider_tg = self.gbp_resources_info['ptg_info'][
                'provider']['ptg_details']
            status = self.gbp_resource_obj.configure_remote_resources(
                remote_resources_site2,
                vpn_service['service_details'][
                                'consumer_provider_interfaces'][0][0],
                cloud_client_subnet_id=provider_tg['subnets'][0])
            if not isinstance(status, bool):
                return status
            # update the VPN node and send traffic.
            status = self.__update_validate_helper__(
                vpn_service_vm_id, vpn_node['id'], status_template[1],
                traffic_resource_dict, resource="VPN",
                operation="New site added")
            if not isinstance(status, bool):
                return status
            # raw_input("proceed to delete the site..")

            # Phase-2: Delete the new site2 and validate traffic.
            if "delete" in self.operation.lower():
                # update the node and send traffic.
                status = self.__update_validate_helper__(
                    vpn_service_vm_id, vpn_node['id'], vpn_template_old,
                    traffic_resource_dict_old, resource="VPN",
                    operation="New site deleted")
                if not isinstance(status, bool):
                    return status

            LOG_OBJ.info("VPN node update is successful.")
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while updating LB Node."


class UpdatePrs(UpdateTestsHelper):
    """Class contains methods for validating policy rule set update
        test cases.
          tests:-
              (1) policy rule set update (add_delete allow rules).
              (2) policy rule set update (redirect rule => redirect rule).
    """
    def __init__(self, gbp_resources_info, update_tc_info,
                 gbp_resource_obj, traffic_obj, traffic_prepare_obj):
        UpdateTestsHelper.__init__(self, gbp_resources_info,
                                   update_tc_info, gbp_resource_obj,
                                   traffic_obj, traffic_prepare_obj)

    def update_prs(self):
        """
        Master method for policy rule set update tests.
        Returns: On success True (bool)
            On failure returns string containing error message. (string)
        """
        try:
            if self.operation == "add" and self.resource == "allow_rule":
                status = self.update_prs_add_delete_allow_rules("add")
                if type(status) == str:
                    return (False, status)
                return (True, "")
            if self.operation == "delete" and self.resource == "allow_rule":
                status = self.update_prs_add_delete_allow_rules("delete")
                if type(status) == str:
                    return (False, status)
                return (True, "")
            if self.operation == "add":
                status = self.update_prs_redirect2redirect_rule()
                if type(status) == str:
                    return (False, status)
                return (True, "")

            err_msg = "There is no test case for policy rule set "\
                "update with operation %s." % self.operation
            LOG_OBJ.error(err_msg)
            return (False, err_msg)
        except Exception, err:
            LOG_OBJ.exception(err)
            err_msg = "There is no test case for policy rule set "\
                "update with operation %s." % self.operation
            return (False, err_msg)

    def update_prs_add_delete_allow_rules(self, operation):
        """
        Delete implicit allow rule & validate traffic.
        Add implicit allow rule & validate traffic.
        Arguments:
            operation: add / delete
        Return: On success True.
            On failure string containing error message.
        """
        try:
            # get policy rule set details.
            prs_details = self.get_policy_rule_set_details()
            if type(prs_details) == str:
                return prs_details
            LOG_OBJ.info("policy rule set details: %s" % prs_details)
            prs_id = prs_details["prs_id"]
            LOG_OBJ.info("policy rule set id: %s" % prs_id)

            # get implicit allow rule details.
            policy_rule_id = ""
            rule_id_list = []
            for rule in prs_details["rules"]:
                rule_id_list.append(rule["rule_id"])
                if rule["protocol"] == None and\
                        rule["action_type"] == "allow":
                    policy_rule_id = rule["rule_id"]

            if not policy_rule_id:
                err_msg = "Couldn't find implicit allow rule in "\
                    "policy rule details."
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.info("Implicit allow rule id: %s" % policy_rule_id)
            LOG_OBJ.info("Policy rule ids belonging to policy"
                         " rule set %s: %s" % (prs_id, rule_id_list))

            # get stack ids. before updating policy rule set.
            stack_id_list = self.get_stack_details_by_node_id()
            if type(stack_id_list) is str:
                return stack_id_list
            LOG_OBJ.info("Stack ids before updating prs"
                         ": %s" % stack_id_list)

            #############################################################
            # Test Section (1): delete implicit allow policy rule.     ##
            #############################################################

            # update policy rule set. remove allow rule from prs.
            rule_id_list.remove(policy_rule_id)
            status = self.__prs_update_wrapper(prs_id, rule_id_list)
            if status is not True:
                return status

            # Update firewall Node. (Add new tcp rule)
            fw_node = self.get_servicechain_node_details(service_type="FW")
            if type(fw_node) is str:
                return fw_node
            fw_template = fw_node[0]["node"]["config"]
            protocol = "tcp"
            port = gbp_config.protocol_port_details["tcp"].split(':')[1]
            update_template_status = UpdateNode.update_fw_template(
                                        fw_template, protocol, port)
            if not update_template_status[0]:
                return str(update_template_status[1])
            fw_template = update_template_status[1]
            updated_node = self.gbp_resource_create_obj.gbp_res_obj.\
                update_service_chain_node(fw_node[0]["node"]['id'],
                                          config=fw_template)
            if updated_node is None:
                err_msg = "Failed to add new tcp firewall rule."
                LOG_OBJ.error(err_msg)
                return err_msg

            # validate service vms deleted or not.
            svm_del_report = self.validate_service_vm_deletion()
            if type(svm_del_report) is str:
                return svm_del_report
            if "deleted" in [vm["status"] for vm in svm_del_report]:
                err_msg = "Some service vms got deleted after removing "\
                    "allow rule from policy rule set."
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.debug("Service vms didn't rescreated after removing"
                          " allow rule from policy rule set.")

            # validate stack got recreated or not.
            # get stack ids. after updating policy rule set.
            stack_id_list_after = self.get_stack_details_by_node_id()
            if type(stack_id_list_after) is str:
                return stack_id_list_after
            LOG_OBJ.debug("Stack id list after updating"
                          " prs: %s" % stack_id_list_after)

            for stack_id in stack_id_list:
                if stack_id in stack_id_list_after:
                    err_msg = "Stack with id %s didn't recreated."
                    LOG_OBJ.warning(err_msg)
                    # return err_msg

            stack_id_list = stack_id_list_after

            # prepare dictionary for traffic validation.
            traffic_dict = self.traffic_prepare_obj.\
                prepare_for_traffic_validation()
            if type(traffic_dict) is not dict:
                err_msg = "Dictionary preparation for traffic validation"\
                    " failed."
                LOG_OBJ.error(err_msg)
                return err_msg
            # add new firewall rule in traffic dict
            traffic_dict["classifiers"].append({"protocol": protocol,
                                               "port": port})

            # validate traffic
            # NOTE: After removing allow rule from prs, traffic validation
            # should fail. As traffic from  consumer to provider will not
            # reach service vms without allow rule.
            status = self.traffic_obj.generate_validate_traffic(traffic_dict)
            if type(status) is tuple and status[0]:
                err_msg = "After deleting allow rule from policy rule "\
                    "set, traffic validation expected to fail, but it didn't."
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.debug("Tarffic validation failed as expected after "
                          "removing allow rule from policy rule set.")

            if operation.lower() == "delete":
                return True

            #############################################################
            # Test Section (2): add implicit allow policy rule.        ##
            #############################################################

            # add allow rule to policy rule set.
            LOG_OBJ.debug("Adding allow policy rule to policy "
                          "rule set: %s" % prs_id)
            rule_id_list.append(policy_rule_id)
            status = self.__prs_update_wrapper(prs_id, rule_id_list)
            if status is not True:
                return status
            time.sleep(30)

            # validate if service vm is deleted or not.
            svm_del_report = self.validate_service_vm_deletion()
            if type(svm_del_report) is str:
                return svm_del_report
            if "deleted" in [vm["status"] for vm in svm_del_report]:
                err_msg = "Some service vms got deleted after adding "\
                    "allow rule in policy rule set."
                LOG_OBJ.error(err_msg)
                return err_msg

            # get stack ids. after updating policy rule set.
            stack_id_list_after = self.get_stack_details_by_node_id()
            if type(stack_id_list_after) is str:
                return stack_id_list_after
            LOG_OBJ.debug("Stack id list after updating"
                          " prs: %s" % stack_id_list_after)
            for stack_id in stack_id_list:
                if stack_id in stack_id_list_after:
                    err_msg = "stack with id %s didn't recreated." % stack_id
                    LOG_OBJ.warning(err_msg)
                    # return err_msg

            # validate traffic.
            # NOTE: After adding allow rule to prs, traffic validation
            # shouldn't fail.
            status = self.traffic_obj.generate_validate_traffic(traffic_dict)
            if type(status) is tuple and not status[0]:
                return "Traffic validation failed after adding back "\
                    " allow rule."

            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while executing policy rule"\
                " set update test for %s operation." % self.operation

    def __prs_update_wrapper(self, prs_id, rule_id_list):
        """ supporting function """
        try:
            kwargs = {"policy_rules": rule_id_list}
            updated_prs = self.gbp_resource_create_obj.gbp_res_obj.\
                update_policy_rule_set(prs_id, **kwargs)
            if type(updated_prs) is not dict or\
                    updated_prs["policy_rules"] != rule_id_list:
                err_msg = "Failed to update policy rule set: %s." % prs_id
                LOG_OBJ.error(err_msg)
                return str(err_msg)
            print "Updated policy rule set: %s" % prs_id
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            err_msg = "Exception occurred while updating policy rule set."
            return err_msg

    def update_prs_redirect2redirect_rule(self):
        """
        updates prs with new policy rule such that
        fw n-s service chain gets updated to fw+lb n-s service chain.
        """
        try:
            # Get the fw node details.
            fw_node = self.get_servicechain_node_details(service_type="fw")
            if not isinstance(fw_node, list):
                return fw_node

            # Create Lb node.
            lb_node = self.gbp_resource_create_obj.\
                create_srvc_chain_node_helper("lb", protocol="tcp",
                                              port="1321")
            if not isinstance(lb_node, dict):
                return lb_node

            # Create spec fw + lb
            fw_lb_spec = self.gbp_resource_create_obj.\
                create_srvc_chain_spec_helper(
                            [fw_node[0].get("node").get("id"), lb_node["id"]])
            if not isinstance(fw_lb_spec, dict):
                return fw_lb_spec

            # Create network service policy
            nsp = self.gbp_resource_create_obj.create_nw_srvc_policy_helper()
            if not isinstance(nsp, dict):
                return nsp

            # update provider target group with network service policy
            # NOTE: If lb in chain, one need to add network service policy
            # in provider target group.
            ptg_ids = self.get_ptg_ids(ptg_type="provider")
            if not isinstance(ptg_ids, dict):
                return ptg_ids

            pt_details = self.get_policy_targets()
            if not isinstance(pt_details, dict):
                return pt_details
            ptg_name = pt_details.get("provider")[0].get("ptg_name")

            provider_ptg_details = self.gbp_resource_create_obj.\
                gbp_res_obj.update_policy_target_group(
                            ptg_ids.get("provider_id"), ptg_name,
                            network_service_policy_id=nsp.get("id"))
            if not isinstance(provider_ptg_details, dict):
                return provider_ptg_details

            # create a redirect policy action with newly created spec.
            new_policy_action = self.gbp_resource_create_obj.gbp_res_obj.\
                create_policy_action("new_rdr_action", action_type="redirect",
                                     action_value=fw_lb_spec.get("id"))
            if not isinstance(new_policy_action, dict):
                return new_policy_action

            # create redirct classifier
            classifier = {"direction": "bi", "protocol": "tcp", "port": "90"}
            new_classifier = self.gbp_resource_create_obj.\
                create_policy_classifier_helper(classifier)
            if not isinstance(new_classifier, dict):
                return (False, new_classifier)

            # create a new policy rule with new_classifier and
            # new policy redirect action
            new_policy_rule = self.gbp_resource_create_obj.\
                create_policy_rule_helper([new_policy_action.get("id")],
                                          new_classifier.get("id"))
            if not isinstance(new_policy_rule, dict):
                return new_policy_rule

            # Get policy rule set details
            prs_details = self.get_policy_rule_set_details()
            if not isinstance(prs_details, dict):
                return (False, prs_details)

            # Prepare list of policy rule ids
            rule_id_list = []
            rule_id_list.append(new_policy_rule.get("id"))
            for rule in prs_details["rules"]:
                if rule.get("action_type") != "redirect":
                    rule_id_list.append(rule["rule_id"])

            # update policy rule set with rule_id_list.
            status = self.__prs_update_wrapper(prs_details.get("prs_id"),
                                               rule_id_list)
            if status is not True:
                return status

            # validate service vm in chain deleted or not after
            # updating policy action with new redirect spec.
            svm_del_report = self.validate_service_vm_deletion()
            if "active" in [vm["status"] for vm in svm_del_report]:
                err_msg = "Looks like service vms didn't deleted "\
                    "after updating policy action."
                LOG_OBJ.error(err_msg)
                return err_msg

            # Get new service vm details. after updating policy action.
            service_details = []
            provider_ptg_ids = [ptg_ids.get("provider_id")]
            for service in ["FW", "LB"]:
                if service.lower() == "fw":
                    node = fw_node
                if service.lower() == "lb":
                    node = lb_node
                service_info = self.get_new_services_details(
                                    service, provider_ptg_ids,
                                    traffic_type="n-s", node_id=node["id"])
                if type(service_info) is str:
                    return service_info
                service_details.append(service_info)

            # Prepare traffic dictionary
            traffic_resource_dict = self.traffic_prepare_obj.\
                prepare_for_traffic_validation()
            if not isinstance(traffic_resource_dict, dict):
                return traffic_resource_dict
            services = self.traffic_prepare_obj.prepare_service_details(
                                            False, services=service_details)
            if type(services) is str:
                return services
            traffic_resource_dict["service_details"] = services
            # traffic_resource_dict["classifier_details"] = ""
            status, msg = self.validate_traffic_obj.generate_validate_traffic(
                               traffic_resource_dict)
            if not status:
                return msg
            return True
        except Exception, err:
            LOG_OBJ.exception(err)
            return "Exception occurred while executing policy rule"\
                " set update test for %s operation." % self.operation


class UpdatePtg(UpdateTestsHelper):
    """
        class contains methods for valtating policy Target group update.
        Tests: -
                1. prs1 (FW) ==> prs2 (FW+LB)
    """

    def __init__(self, gbp_resources_info, update_tc_info,
                 gbp_resource_obj, traffic_obj, traffic_prepare_obj):
        UpdateTestsHelper.__init__(self, gbp_resources_info,
                                   update_tc_info, gbp_resource_obj,
                                   traffic_obj, traffic_prepare_obj)

    def update_ptg(self):
        """
        Master method for policy target group update tests.
        Returns: On success True (bool)
            On failure returns string containing error message. (string)
        """
        try:
            if self.operation == "add":
                status = self.update_ptg_prs2prs()
                if type(status) is str:
                    return (False,  status)
                return (True, "")
            err_msg = "Operation %s is not supported in policy target "\
                "group update tests." % self.operation
            LOG_OBJ.error(err_msg)
            return (True, err_msg)
        except Exception as err:
            LOG_OBJ.exception(err)
            err_msg = "Exception occurred while exceuting policy "\
                "target group update tests."
            return (False, err_msg)

    def update_ptg_prs2prs(self):
        """
        Method will update policy target groups (consumer & provider), with new
        policy rule set. And will validate traffic through new chain
        of services.

        Returns: On success True.
            On failure string containing error message.
        """
        try:
            insertion_type = "e-w"
            # get provider ptg details.
            ptg_ids = self.get_ptg_ids()
            provider_ptg_id = ptg_ids.get("provider_id")
            consumer_ptg_id = ptg_ids.get("consumer_id")
            if not provider_ptg_id:
                err_msg = "ATFError: Gbp resources dictionary missing policy "\
                    "target group details."
                LOG_OBJ.error(err_msg)
                return err_msg

            if not consumer_ptg_id:
                # if not consumer_ptg_id, get external policy id.
                ext_policy_info = self.get_external_policy_details()
                if type(ext_policy_info) is str:
                    return ext_policy_info
                ext_policy_id = ext_policy_info["id"]
                insertion_type = "n-s"

            # get services details.
            service_details = self.get_service_details()
            if type(service_details) is str:
                return service_details

            # get stack list before updating target groups.
            stack_id_list = self.get_stack_details_by_node_id()
            if type(stack_id_list) is str:
                return stack_id_list

            #############################################
            #         update policy target group.       #
            #############################################
            # create network service policy.
            nsp_details = self.gbp_resource_create_obj.\
                create_nw_srvc_policy_helper()
            if type(nsp_details) is str:
                return nsp_details

            # create new policy rule set for chain (FW + LB)
            # get classifier details.
            classifier_details = self.get_classifier_details()
            if type(classifier_details) is str:
                return classifier_details
            protocol = classifier_details["protocol"]
            port = classifier_details["port"]

            # create node for lb.
            kwargs = {"node_name": "lb_new",
                      "protocol": protocol}
            if port:
                kwargs["port"] = port
            node_lb_info = self.gbp_resource_create_obj.\
                create_srvc_chain_node_helper("lb", **kwargs)
            if type(node_lb_info) is str:
                return node_lb_info

            # get fw node details from gbp resources dict.
            node_details = self.get_service_chain_node_details(
                                                service_type="fw")
            if type(node_details) is str:
                return node_details
            fw_node_id = node_details[0]["id"]

            # create spec fw + lb.
            spec_details = self.gbp_resource_create_obj.\
                create_srvc_chain_spec_helper([fw_node_id, node_lb_info["id"]])
            if type(spec_details) is str:
                return spec_details

            # create new redirect action.
            action_details = self.gbp_resource_create_obj.\
                create_policy_action_helper("redirect", spec_details["id"])
            if type(action_details) is str:
                return action_details

            # create new redirect rule.
            rule_details = self.gbp_resource_create_obj.\
                create_policy_rule_helper([action_details["id"]],
                                          classifier_details["id"])
            if type(rule_details) is str:
                return rule_details

            # create new prs with new redurect rule & allow rules.
            rule_details_list = self.get_policy_rule_details(
                                                action_type="allow")
            if type(rule_details_list) is str:
                return rule_details_list

            rule_id_list = [rule["rule_id"] for rule in rule_details_list]
            rule_id_list.append(rule_details["id"])

            prs_details = self.gbp_resource_create_obj.\
                create_policy_rule_set_helper(rule_id_list)
            if type(prs_details) is str:
                return prs_details

            # update consumer ptg.
            if insertion_type == "e-w":
                kwargs = {"consumed_policy_rule_sets":
                          {prs_details['id']: prs_details['id']}}
                updated_consumer = self.__update_policy_target_group_helper(
                                consumer_ptg_id, grp_type="internal", **kwargs)
                if type(updated_consumer) is str:
                    return updated_consumer
            else:
                # update external policy rule set.
                kwargs = {"consumed_policy_rule_sets":
                          {prs_details['id']: prs_details['id']}}
                updated_ext_policy = self.__update_policy_target_group_helper(
                                ext_policy_id, grp_type="external", **kwargs)
                if type(updated_ext_policy) is str:
                    return updated_consumer

            # update provider ptg.
            kwargs = {"provided_policy_rule_sets":
                      {prs_details['id']: prs_details['id']},
                      "network_service_policy_id": nsp_details["id"]}
            updated_provider = self.__update_policy_target_group_helper(
                                provider_ptg_id, grp_type="internal", **kwargs)
            if type(updated_provider) is str:
                return updated_provider

            # validate old service vm cleanup.
            status_report = self.validate_service_vm_deletion()
            if type(status_report) is str:
                return status_report

            if "active" in [vm["status"] for vm in status_report]:
                err_msg = "After updating policy target groups service "\
                    "vms didn't cleaned up properly."
                LOG_OBJ.error(err_msg)
                return err_msg

            # validate stack cleanup.
            status = self.validate_stack_cleanup(stack_id_list)
            if type(status) is str:
                return status
            LOG_OBJ.debug("Stack with ids: %s :deleted after updating policy"
                          " target groups." % stack_id_list)

            # new service vm details.
            service_details = []
            for service in ["FW", "LB"]:
                if service.lower() == 'fw':
                    node_info = node_details[0]
                if service.lower() == 'lb':
                    node_info = node_lb_info
                # ptg_ids = [None, None]
                # ptg_ids[0] = consumer_ptg_id if consumer_ptg_id else None
                ptg_ids = [provider_ptg_id]
                service_info = self.get_new_services_details(
                                            service, ptg_ids,
                                            insertion_type,
                                            node_info['id'])
                if type(service_info) is str:
                    return service_info
                service_info['node'] = node_info
                service_details.append(service_info)

            # prepare traffic dictionary.
            traffic_dict = self.traffic_prepare_obj.\
                prepare_for_traffic_validation()
            if type(traffic_dict) is str:
                return traffic_dict
            # prepare service details & update traffic dict.
            service_details = self.traffic_prepare_obj.prepare_service_details(
                                        False, services=service_details)
            if type(service_details) is str:
                return service_details
            traffic_dict["service_details"] = service_details

            # validate traffic.
            status = self.traffic_obj.generate_validate_traffic(traffic_dict)
            if type(status) is tuple and status[0]:
                return True

            return status[0] if type(status) is tuple else\
                "Traffic validation failed."
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while exceuting policy "\
                "target group update tests."

    def __update_policy_target_group_helper(self, grp_id, grp_type="internal",
                                            **kwargs):
        """
        Helper function.
        Arguments:
            1. grp_id: policy target group id. ext policy id
                    if grp_type is "external"
            2. grp_type: interanl/external. if external will
                    update external policy.
        Optional Argument:
            1. name
            2. description
            3. provided_policy_rule_sets: {prs_id:prs_id}
            4. consumed_policy_rule_sets: {prs_id:prs_id}
            5. network_service_policy_id
        Returns:
            1. On success returns dictionary containing details
                of updated ptg or ext policy.
            2. On Failure returns string containing error message.
        """
        try:
            try:
                assert grp_type.lower() in ["internal", "external"],\
                    "ATFError: Invalid policy target group type. PTG"\
                    " type should either 'internal' or 'external'."
                assert len(kwargs) != 0, "ATFError: No key value paris "\
                    "provided for policy target groups."
            except AssertionError, err:
                LOG_OBJ.error(err)
                return str(err)
            # update policy target group.
            if grp_type == "internal":
                LOG_OBJ.debug("Updating policy target group: %s" % grp_id)
                updated_grp = self.gbp_resource_create_obj.gbp_res_obj.\
                    update_policy_target_group(grp_id,
                                               "updated_grp",
                                               **kwargs)
                if type(updated_grp) is not dict:
                    err_msg = "Updating policy target group %s "\
                        "failed." % grp_id
                    LOG_OBJ.error(err_msg)
                    return str(err_msg)
                return updated_grp
            else:
                # update external policy.
                LOG_OBJ.debug("Updating external policy: %s" % grp_id)
                updated_ext_policy = self.gbp_resource_create_obj.gbp_res_obj.\
                    update_external_policy(grp_id, **kwargs)
                if type(updated_ext_policy) is not dict:
                    err_msg = "Failed to update external policy: %s" % grp_id
                    LOG_OBJ.error(err_msg)
                    return str(err_msg)
                return updated_ext_policy
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while updating policy target groups."
