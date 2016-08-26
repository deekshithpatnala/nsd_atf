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
File contains class & methods for parsing dictionary (gbp_resources_info)
returned by create_gbp_resources() method of GbpResourceCreator class.
ServiceResources class in this module have getter methods for getting details
gbp resources created.
"""
import copy

import atf.lib.nvp_atf_logging as log
from atf.lib.lib_common import commonLibrary


LOG_OBJ = log.get_atf_logger()


class ServiceResources():
    """
    Contains methods for parsing gbp_resource_info dictionary.
    """
    def __init__(self, gbp_resources_info, update_tc_info,
                 common_lib_obj=None):
        """
        Arguments:
            1. gbp_resources_info: (output dict returned by the
                create_gbp_resources of gbp_resource_create.)
            2. update_tc_info: (dictionary)
                {
                    "update_resource_type: rule/prs/node/spec/...,
                    "operation": "add/delete/add_delete/update",
                    "resource": fw/lb/vpn/vpn+lb/prs_allow_rule/
                }
            3. common_lib_obj: Common library object. (optional.)
        """
        self.gbp_resources_info = gbp_resources_info.copy()
        # update action add /delete/ add_delete
        self.operation = update_tc_info.get("operation")
        # gbp resource to be updated
        self.update_resource_type = update_tc_info.get("update_resource_type")
        self.resource = update_tc_info.get("resource")
        # common library object.
        self.common_lib_obj = common_lib_obj
        if not self.common_lib_obj:
            self.common_lib_obj = commonLibrary()

        self.traffic_type = "E-W"
        self.vpn_in_chain = False
        if self.gbp_resources_info.get('remote_resource_info'):
            self.traffic_type = "N-S"
            if self.gbp_resources_info['remote_resource_info'].get('vpn_type'):
                self.vpn_in_chain = True

    def _get_prs_dict(self):
        """
        supporting function.
        """
        try:
            if not self.gbp_resources_info.get("policy_rule_set"):
                err_msg = "service details missing in gbp_resources_info."
                LOG_OBJ.error("%s" % err_msg)
                return None
            return self.gbp_resources_info.get("policy_rule_set")
        except Exception as err:
            err_msg = "Problem occurred while getting prs details."
            LOG_OBJ.exception(err)
            return None

    def set_gbp_resources_info(self, gbp_resources_info):
        LOG_OBJ.debug("setting gbp_resources_info.")
        LOG_OBJ.debug("New gbp_resources_info: %s" % gbp_resources_info)
        self.gbp_resources_info = gbp_resources_info.copy()
        if self.gbp_resources_info.get('remote_resource_info'):
            self.traffic_type = "N-S"
            if self.gbp_resources_info['remote_resource_info'
                                       ].get('vpn_type'):
                self.vpn_in_chain = True

    def get_service_details(self, **kwargs):
        """
        Parse gbp_resouerce_info dictionary & returns service details.

        Optional Arguments:
            service_type: FW/LB/VPN
        Return: (a) On Failure returns string containing error message.
            (b) On success returns list containing services details.
                [
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

                        "standby_consumer_provider_interfaces": []
                                # Stand by service details. if services
                                # launched HA mode.
                                        },

                    stack_id: ""  # stack id.
                    "node": {
                                'name': '',
                                'shared': '',
                                'service_type': '',
                                'tenant_id': '',
                                'description': '',
                                'config': '','id': '',
                                'service_profile_id': ''
                            } # service chain node details.
                ]
        """
        try:
            services_list = []
            policy_rule_set = self._get_prs_dict()
            policy_rules = policy_rule_set.get("policy_rules")

            if policy_rules:
                for rule in policy_rules:
                    policy_action = rule.get("action")
                    if policy_action:
                        service_chain = policy_action.get("service_chain")
                        if service_chain:
                            services = copy.deepcopy(service_chain.
                                                     get("services"))
                            for service in services:
                                services_list.append(service)

            if kwargs.get("service_type") and\
                    kwargs.get("service_type").lower() in ["fw", "vpn", "lb"]:
                service_info = []
                for service in services_list:
                    if service["service_type"].lower() == kwargs.\
                            get("service_type").lower():
                        service_info.append(service)
                services_list = copy.deepcopy(service_info)

            if len(services_list) == 0:
                err_msg = "Required service details missing in "\
                    "gbp_resources_info."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg

            return services_list
        except Exception as err:
            err_msg = "Problem getting services details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_servicechain_node_details(self, **kwargs):
        """
        Parse gbp_resouerce_info dictionary & returns service
        chain node details.

        Optional Arguments:
            "service_type:" FW/LB/VPN

         Returns: (a) On Failure returns string containing error message.
            (b) On Success returns list containing service chain node
                details in below format.
                [
                    {
                        "node": "",
                        "service_type": "FW/LB/VPN"
                    }, {}, {}
                ]
        """
        try:
            service_chain_node_details = []

            policy_rule_set = self._get_prs_dict()
            policy_rules = policy_rule_set.get("policy_rules")

            if policy_rules:
                for rule in policy_rules:
                    policy_action = rule.get("action")
                    if policy_action and policy_action.get("service_chain"):
                        service_chain = policy_action.get("service_chain")
                        if service_chain and service_chain.get("services"):
                            for service in service_chain.get("services"):
                                service_type = copy.\
                                    deepcopy(service.get("service_type"))
                                node = copy.deepcopy(service.get("node"))
                                service_chain_node_details.\
                                    append({"node": node,
                                            "service_type": service_type})

            if kwargs.get("service_type") and\
                    kwargs.get("service_type").lower() in ["fw", "vpn", "lb"]:
                chain_details = []
                for node_info in service_chain_node_details:
                    if node_info["service_type"].lower() == kwargs.\
                            get("service_type").lower():
                        chain_details.append(node_info)
                service_chain_node_details = copy.deepcopy(chain_details)

            if len(service_chain_node_details) == 0:
                err_msg = "Required Service chain node details "\
                    "missing in gbp_resources_info."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg

            return service_chain_node_details
        except Exception as err:
            err_msg = "Problem getting policy target details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_servicechain_spec_details(self):
        """
        Parse gbp_resouerce_info dictionary & returns service "
        "chain spec details.

        Returns: (a) On Failure returns string containing error message.
            (b) On success returns list of service chain spec
                ids.
                e.g.
                    [spec_id_1, spec_id_2, ....]
        """
        try:
            spec_id_list = []

            policy_rule_set = self._get_prs_dict()
            policy_rules = policy_rule_set.get("policy_rules")

            if policy_rules:
                for rule in policy_rules:
                    policy_action = rule.get("action")
                    if policy_action and policy_action.get("service_chain"):
                        service_chain = policy_action.get("service_chain")
                        if service_chain and service_chain.get("spec_id"):
                            spec_id_list.append(service_chain.get("spec_id"))

            if len(spec_id_list) == 0:
                err_msg = "service chain spec details missing in gb"\
                    "p_resource_info_dict."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg
            return spec_id_list
        except Exception as err:
            err_msg = "Problem getting service chain spec details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_policy_action_details(self, **kwargs):
        """
        Arguments:
            action_type: allow/redirect
        Parse gbp_resouerce_info dictionary & returns policy action details.
        Returns: (a) On success returns list of policy action
            info in below format.
                e.g.
                [
                    {
                        "name": "policy_action_1",
                        "action_id": "7a95cf85-2aea-4973-a612-d7e19fed5cf6"
                    }, {}, {}, ....
                ]
            (b) On failure returns string containing error message.
        """
        try:
            policy_action_details = {
                                     "redirect": [],
                                     "allow": []
                                     }

            policy_rule_set = self._get_prs_dict()
            policy_rules = policy_rule_set.get("policy_rules")

            if policy_rules:
                for rule in policy_rules:
                    policy_action = rule.get("action")
                    if policy_action and policy_action.get("name") and\
                            policy_action.get("action_id"):
                        action_name = policy_action.get("name")
                        action_id = policy_action.get("action_id")
                        if policy_action.get("service_chain"):
                                policy_action_details["redirect"].\
                                    append({"name": action_name,
                                            "action_id": action_id})
                        else:
                            if not policy_action.get("service_chain"):
                                policy_action_details["allow"].\
                                    append({"name": action_name,
                                            "action_id": action_id})

            if kwargs.get("action_type") and kwargs.get("action_type")\
                    in ["allow", "redirect"]:
                if kwargs["action_type"] == "allow" and\
                        len(policy_action_details["allow"]) != 0:
                    return policy_action_details["allow"]
                elif kwargs["action_type"] == "redirect" and\
                        len(policy_action_details["redirect"]) != 0:
                    return policy_action_details["redirect"]
                else:
                    err_msg = "Required policy action details missing in gb"\
                        "p_resource_info_dict."
                    LOG_OBJ.error("%s" % err_msg)
                    return err_msg
            else:
                if len(policy_action_details["allow"] +
                       policy_action_details["redirect"]) != 0:
                    return policy_action_details["allow"] +\
                        policy_action_details["redirect"]
                else:
                    err_msg = "policy action details missing in gb"\
                        "p_resource_info_dict."
                    LOG_OBJ.error("%s" % err_msg)
                    return err_msg
        except Exception as err:
            err_msg = "Problem getting policy action details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_policy_rule_details(self, **kwargs):
        """
        Parse gbp_resouerce_info dictionary & returns policy rule details.

        Optional Arguments:
            action_type: allow/redirect (if action_type is "allow" function
                will return rules with allow action. if action_type is
                "redirect" returns all rules with redirect actions.)
            protocol: tcp/udp/icmp/ ... (returns rules which given
                                        classifier)

        Returns: (a) On success returns list containing policy rules details
            in below format.
                [
                    {
                        "rule_id": "0518452b-4bb6-4270-b0dc-1c8e82d3c264",
                        "name": "policy_rule_1",
                        "action_type": "redirect/allow"
                        "protocol": tcp, udp, icmp, ...
                    }
                ]
            (b) On failure returns string containing error message.
        """
        try:
            policy_rule_details = []

            policy_rule_set = self._get_prs_dict()
            if not policy_rule_set:
                err_msg = "Policy rule set details missing in gbp "\
                    "resource dictionary."
                print err_msg
                LOG_OBJ.error(err_msg)
                return err_msg

            policy_rules = policy_rule_set.get("policy_rules")

            if policy_rules:
                for rule in policy_rules:
                    policy_action = rule.get("action")
                    if policy_action and policy_action.get("service_chain"):
                        action_type = "redirect"
                    else:
                        action_type = "allow"
                    rule_id = copy.deepcopy(rule.get("rule_id"))
                    rule_name = copy.deepcopy(rule.get("name"))
                    classifier_protocol = rule["classifier"]["protocol"]
                    if rule_id and rule_name:
                        policy_rule_details.append({
                                                "rule_id": rule_id,
                                                "name": rule_name,
                                                "action_type": action_type,
                                                "protocol": classifier_protocol
                                                    })

            if kwargs.get("action_type") and\
                    kwargs.get("action_type").lower() in ["allow", "redirect"]:
                rule_list = []
                for rule in policy_rule_details:
                    if rule["action_type"].lower() == kwargs.\
                            get("action_type").lower():
                        rule_list.append(rule)
                policy_rule_details = copy.deepcopy(rule_list)

            if kwargs.get("protocol"):
                rule_list = []
                for rule in policy_rule_details:
                    if rule["protocol"].lower() == kwargs["protocol"].lower():
                        rule_list.append(rule.copy())
                policy_rule_details = copy.deepcopy(rule_list)

            if len(policy_rule_details) == 0:
                err_msg = "Required policy rule details missing in gbp_reso"\
                    "urce_info_dict."
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.info("policy rule resources: %s" % policy_rule_details)
            return policy_rule_details
        except Exception as err:
            err_msg = "Problem getting policy rule details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_policy_targets(self, **kwargs):
        """
        Parse gbp_resouerce_info dictionary & returns policy target details.

        Returns: (a) On Failure returns string containing error message.
            (b) On Success returns dictionary containing policy target
            details in below format.
                {
                    "consumer": [
                            {
                                "server_id": "",
                                "ptg_name": "",  # policy target group name
                                "description": "",
                                "vm_ip": "",
                                "tenant_id": "",
                                "policy_target_group_id": "",
                                "network_id": "",
                                "port_id": "",
                                "name": ""
                            }, {}, {}, ...
                        ]
                    "provider": [
                            {
                                "server_id": "",
                                "ptg_name": "",  # policy target group name
                                "description": "",
                                "vm_ip": "",
                                "tenant_id": "",
                                "policy_target_group_id": "",
                                "network_id": "",
                                "port_id": "",
                                "name": ""
                            }, {}, {}, ...
                        ]
                }
        """
        try:
            pt_details = {"consumer": [], "provider": []}
            if not self.gbp_resources_info.get("ptg_info"):
                err_msg = "Policy target details missing in "\
                    "gbp_resourc_info_dict."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg
            ptg_info = self.gbp_resources_info.get("ptg_info")
            consumer_ptg_info = ptg_info.get("consumer")
            provider_ptg_info = ptg_info.get("provider")
            if consumer_ptg_info:
                pt_details["consumer"] = consumer_ptg_info.\
                            get("policy_targets")
            if provider_ptg_info:
                pt_details["provider"] = provider_ptg_info.\
                            get("policy_targets")
            if not pt_details["consumer"] and not pt_details["provider"]:
                err_msg = "Policy target details missing in "\
                    "gbp_resourc_info_dict."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg

            return pt_details
        except Exception as err:
            err_msg = "Problem getting policy target details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_policy_rule_set_details(self, **kwargs):
        """
        Parse gbp_resouerce_info dictionary & returns prs details.

        Returns: (a) On success returns policy rule set details
            in below format.

            {
                "name": "policy_rule_set_fw",
                "prs_id": "44e82b0f-113b-409d-be97-249695c94834",
                "rules": [
                            {
                                "rule_id": "",
                                "name": "",
                                "action_type": "",
                                "protocol": ""
                            }, {}, ..
                        ]
            }

            (b) On failure returns string containing error message.
        """
        try:
            prs_details = {}
            # get policy rule details.
            policy_rules = self.get_policy_rule_details()
            if type(policy_rules) == str:
                return policy_rules

            # policy rule set details.
            if not self.gbp_resources_info.get("policy_rule_set"):
                err_msg = "Policy rule details missing in gbp_"\
                    "resource_info_dict."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg

            prs_id = self.\
                gbp_resources_info["policy_rule_set"].get("prs_id")
            prs_name = self.\
                gbp_resources_info["policy_rule_set"].get("name")
            if not prs_id or not prs_name:
                err_msg = "Policy rule details missing in gbp_"\
                    "resource_info_dict."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg

            prs_details["name"] = prs_name
            prs_details["prs_id"] = prs_id
            prs_details["rules"] = policy_rules
            return prs_details
        except Exception as err:
            err_msg = "Problem getting policy rule set details from "\
                "gbp_resources_info."
            LOG_OBJ.exception(err)
            return err_msg

    def get_svm_mgmt_interface_details(self, service_type):
        """
        Arguments:
            service_type: FW/VPN/LB

        Returns: (a) On success returns service management interface details.
            e.g.[
                    {
                        'fixed_ip': "",
                        'vm_id': "",
                        'floating_ip': "",
                        'iface_name': "",
                        'host_name': ""

                    }, {}, ..
                ]
            (b) On Failure returns string containing error message.
        """
        try:
            mgmt_interface_details = []
            if service_type.lower() not in ["fw", "vpn", "lb"]:
                err_msg = "Invalid service type %s" % service_type
                LOG_OBJ.error("%s" % err_msg)
                return err_msg

            # get service vm details.
            service_details = self.get_service_details(
                                            service_type=service_type.lower())
            if type(service_details) is str:
                return service_details

            for service in service_details:
                if service.get("service_details"):
                    mgmt_iface_info = service.get("service_details").\
                        get("svc_mgmt_details")
                    if mgmt_iface_info:
                        mgmt_interface_details.append(mgmt_iface_info)

            if len(mgmt_interface_details) == 0:
                err_msg = "Service mgmt interface details missing in gbp "\
                    "resource info dictionary."
                LOG_OBJ.error("%s" % err_msg)
                return err_msg
            return mgmt_interface_details
        except Exception as err:
            err_msg = "Problem getting service vm mgmt interface details."
            LOG_OBJ.exception(err)
            return err_msg

    def get_ptg_ids(self, ptg_type=None):
        """
        Gets the ptg ids.
        Optional args:
        ptg_type : "consumer" or "provider"
        Returns:
        dictionary of ptg ids.
        example: { "consumer_id" : consumer_id, "provider_id":provider_id}
        On failure of retrieving details returns None for corresponding
        ptg.
        example: if retreving consumer_id failed returns
        {"consumer_id" : None, "provider_id" : provider_id}
        If both failed, both will be none.
        """
        ptg_id = {"consumer_id": None, "provider_id": None}
        try:
            if ((ptg_type is None) or (ptg_type.lower() == "consumer")) and \
               ("ptg_info" in self.gbp_resources_info) and ("consumer" in
               self.gbp_resources_info.get("ptg_info")) and \
                ("ptg_details" in self.gbp_resources_info.get("ptg_info").
                 get("consumer")) and \
                ("id" in self.gbp_resources_info.get("ptg_info").
                 get("consumer").get("ptg_details")):
                consumer_id = self.gbp_resources_info.get("ptg_info"). \
                            get("consumer").get("ptg_details").get("id")
                ptg_id["consumer_id"] = consumer_id
                if (ptg_type is not None) and \
                        (ptg_type.lower() == "consumer"):
                    return {"consumer_id": consumer_id}
            elif (ptg_type is not None) and \
                    (ptg_type.lower() == "consumer"):
                msg = "Not able to retreive consumer details"
                LOG_OBJ.error(msg)
                return {"consumer_id": None}
            else:
                msg = "Not able to retreive consumer details"
                LOG_OBJ.error(msg)

            if ((ptg_type is None) or (ptg_type.lower() == "provider")) and \
               ("ptg_info" in self.gbp_resources_info) and ("provider" in
               self.gbp_resources_info.get("ptg_info")) and \
                ("ptg_details" in self.gbp_resources_info.get("ptg_info").
                 get("provider")) and \
                ("id" in self.gbp_resources_info.get("ptg_info").
                 get("provider").get("ptg_details")):
                provider_id = self.gbp_resources_info.get("ptg_info"). \
                            get("provider").get("ptg_details").get("id")
                ptg_id["provider_id"] = provider_id
                if (ptg_type is not None) and \
                        (ptg_type.lower() == "provider"):
                    return {"provider_id": provider_id}
            elif (ptg_type is not None) and \
                    (ptg_type.lower() == "provider"):
                msg = "Not able to retreive provider details"
                LOG_OBJ.error(msg)
                return {"provider_id": None}
            else:
                msg = "Not able to retreive provider details"
                LOG_OBJ.error(msg)

            return ptg_id

        except Exception as err:
            LOG_OBJ.exception(err)
            return ptg_id

    def get_external_policy_details(self):
        """
        Returns: dictionary containing external policy details.
            On failure returns string containing error message.
        """
        try:
            ext_policy_info = self.gbp_resources_info.get("ext_policy")
            if not ext_policy_info:
                err_msg = "ATFError: External policy details "\
                    "missing in gbp resources dictionary."
                LOG_OBJ.error(err_msg)
                return err_msg
            return ext_policy_info
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while getting external policy"\
                " details from gbp resources dictionary."

    def get_classifier_details(self):
        """
        Returns: Dictionary containing redirect classifier details.
            On failure returns string containing error message.
        """
        try:
            temp_classifier = {}
            for rule in self.gbp_resources_info['policy_rule_set'][
                                                            'policy_rules']:
                if not rule['action'].get('service_chain'):
                    continue
                # Filling classifier details
                temp_classifier['protocol'] = rule['classifier'][
                                                    'protocol_original_name']
                if rule['classifier']['port_range']:
                    temp_classifier['port'] = rule['classifier']['port_range']
                temp_classifier["id"] = rule["classifier"]["id"]

            if len(temp_classifier) == 0:
                err_msg = "ATFError: Redirect classifier details missing in"\
                    " gbp resources dictionary."
                LOG_OBJ.error(err_msg)
                return err_msg
            return temp_classifier
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while getting redirect classifier details."

    def get_service_chain_node_details(self, **kwargs):
        """
        Optional arguments:
            service_type: lb/fw/vpn.
        Returns:
            1. On success returns list of dictionaries containing
                service chain node details.
            2. On failure returns string containing error message.
        """
        try:
            try:
                assert kwargs.get("service_type") in\
                    ["lb", "fw", "vpn", None, "FW", "LB", "VPN"],\
                    "Couldn't get details for "\
                    "service type: %s" % kwargs.get("service_type")
            except AssertionError, err:
                LOG_OBJ.error(err)
                return err

            node_details = []
            # get service details.
            service_details = self.get_service_details()
            if type(service_details) is str:
                return service_details

            if kwargs.get("service_type"):
                for service in service_details:
                    node = service.get("node")
                    if service["service_type"].lower() == kwargs.get(
                                                    "service_type").lower():
                        node_details.append(node)
            else:
                for service in service_details:
                    node_details.append(service.get("node"))

            if len(node_details) == 0:
                err_msg = "Couldn't find required service chain node "\
                    "details in gbp resource dictionary."
                LOG_OBJ.error(err_msg)
                return err_msg
            return node_details
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while getting service chain node "\
                "details from gbp resources dictionary."
