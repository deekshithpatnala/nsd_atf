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

import sys
# import pdb
import time
import traceback

from atf.lib.lib_common import commonLibrary
import atf.lib.nvp_atf_logging as log
from atf.lib.gbp_constructs import gbp_construct
import atf.config.gbp_config as gbp_config

sys.path.append("../../")

# pylint: disable=W0142

# pylint: disable=W0702


class GbpResourceCleanup(object):
    """class contains methods for cleaning
        gbp resources created by test cases.
    """
    def __init__(self, os_pub_ip):
        """
        Argu: os_pub_ip (Openstack Controller public ip.)
        """
        # os public ip
        self.os_pub_ip = os_pub_ip
        # logging object
        self.logger = log.get_atf_logger()
        # commonLibrary object.
        self.common_obj = commonLibrary()
        # creating object of gbp_construct class
        # passing empty token while creating object.
        self.gbp_driver = gbp_construct("", self.os_pub_ip)

    def delete_all_gbp_resources(self, tenant_info):
        """
        This is master function
        delete all GBP resources of a tenant.

        Required Args:
        (1) tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }

        Returns: On Success returns True.
            On failure returns string containing error message
        """
        try:
            err_msg = ""
            tenant_id = tenant_info["tid"]

            for gbp_res in gbp_config.gbp_res_cleanup_seq:
                res_deleted = False
                self.gbp_driver.token = tenant_info["token"]
                # NOTE: Deleting gbp resources using token of
                # same project in which gbp resources are created.
                print "Started deleting %s in %s"\
                    " project." % (gbp_res, tenant_id)
                self.logger.debug("Started deleting %s in %s"
                                  " project." % (gbp_res, tenant_id))
                cleanup_method_name = "self.delete_all_" + gbp_res +\
                    "(tenant_info)"
                # if resources cleanup fails, retrying several times.
                for retry in range(0, 3):
                    self.logger.info("GBP Resource Delete. Retry attempt"
                                     ": %s" % retry)
                    status = eval(cleanup_method_name)
                    self.logger.debug("@@@@@@@@ %s  ### %s" % (
                                                    status, type(status)))
                    if type(status) is str or type(status) is unicode:
                        err = "Problem occurred while deleting %s "\
                            "in %s project." % (gbp_res, tenant_id)
                        self.logger.error(err)
                        time.sleep(10)
                        if not retry:
                            err_msg += status
                    else:
                        res_deleted = True
                        self.logger.debug("Deleted all %s in successf"
                                          "ully." % gbp_res)
                        break

                # NOTE: If gbp resources deletion is failed using member
                # project token. Use cloud admin token to delete target
                # gbp resources.
                if not res_deleted:
                    pass

            if err_msg == "":
                print "Cleaned up all GBP resources successfully "\
                    "of tenant %s" % tenant_id
                self.logger.debug("Cleaned up all GBP resources successfully "
                                  "of tenant %s" % tenant_id)
                return True
            return err_msg
        except Exception:
            err_msg += "Exception occurred while cleaning GBP "\
                "resources in tenant %s" % tenant_id
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_policy_targets(self, tenant_info):
        """
        For deleting all the policy targets in given tenant.
        Argu: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            # Get all policy targets
            policy_target_list = self.gbp_driver.list_policy_target()
            if policy_target_list is None:
                err_msg = "List Policy Targets Failed in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Policy Target List: %s" % policy_target_list)

            if len(policy_target_list) == 0:
                self.logger.debug("There are not policy targets in tenant "
                                  "%s for deletion" % tenant_info["tid"])
                return True

            for policy_target in policy_target_list:
                if policy_target["tenant_id"] != tenant_info['tid']:
                    continue

                status = self.gbp_driver.\
                    delete_policy_target(policy_target["id"])
                if status is None:
                    err_msg = "Error while deleting policy target %s "\
                        "in tenant %s" % (policy_target["id"],
                                          tenant_info['tid'])
                    self.logger.error(err_msg)
                    return err_msg
                self.logger.debug("Policy Target %s Deleted Successfully"
                                  % policy_target["id"])
            return True
        except Exception:
            err_msg = "Exception occurred while deleting policy targets."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_policy_target_groups(self, tenant_info):
        """
        For Deleting all policy target groups in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            # Get policy target groups.
            policy_target_group_list = self.gbp_driver.\
                list_policy_target_group()
            if policy_target_group_list is None:
                err_msg = "Policy Target Group List Failed in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Policy Target Group List: %s"
                              % policy_target_group_list)

            if len(policy_target_group_list) == 0:
                self.logger.debug("There are not policy target groups to "
                                  "delete in tenant %s" % tenant_info["tid"])
                return True

            # local fix. Will go away later.
            consumer_group_ids = []

            stiching_group_id = None
            for target_group in policy_target_group_list:
                if target_group["tenant_id"] != tenant_info['tid']:
                    continue
                if "stitching" in target_group["name"]:
                    stiching_group_id = target_group["id"]
                    continue

                # Local Fix. Will go away later.
                if "consumer" in target_group["name"]:
                    consumer_group_ids.append(target_group["id"])
                    continue

                # unset policy rule set from policy target group.
                # kwargs = {}
                # kwargs["consumed_policy_rule_sets"] = {}
                # kwargs["provided_policy_rule_sets"] = {}
                # updated_group = self.gbp_driver.\
                #    update_policy_target_group(target_group['id'],
                #                               "updated_name",
                #                               **kwargs)
                # if type(updated_group) is not dict:
                #   err_msg = "Failed to unset policy rule set from"\
                #        "group %s" % target_group['id']
                #    print err_msg
                #    self.logger.error(err_msg)
                #    return err_msg

                status = self.gbp_driver.\
                    delete_policy_target_group(target_group['id'])
                if status is None:
                    err_msg = "Error While Deleting policy target groups %s"\
                        % target_group['id']
                    self.logger.error(err_msg)
                    return err_msg

            if stiching_group_id is not None:
                status = self.gbp_driver.\
                    delete_policy_target_group(stiching_group_id)
                if status is None:
                    err_msg = "Error While Deleting policy target groups %s"\
                        % stiching_group_id
                    self.logger.error(err_msg)
                    return err_msg

            # Local Fix. Will go away later.
            for consumer_ptg_id in consumer_group_ids:
                status = self.gbp_driver.\
                    delete_policy_target_group(consumer_ptg_id)
                if status is None:
                    err_msg = "Error While Deleting policy target groups %s"\
                        % consumer_ptg_id
                    self.logger.error(err_msg)
                    return err_msg

            return True
        except:
            err_msg = "Exception occurred while deleting policy "\
                "target groups in tenant %s" % tenant_info["tid"]
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_policy_rule_sets(self, tenant_info):
        """
        For Deleting all policy target groups in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            # Get policy target groups.
            policy_rule_set_list = self.gbp_driver.list_policy_rule_set()
            if policy_rule_set_list is None:
                err_msg = "List Policy Rule Set Failed in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Policy Rule Set List: %s"
                              % policy_rule_set_list)

            if len(policy_rule_set_list) == 0:
                self.logger.debug("There are not policy Rule Sets to "
                                  "delete in tenant %s" % tenant_info["tid"])
                return True

            for rule_set in policy_rule_set_list:
                if rule_set["tenant_id"] != tenant_info['tid']:
                    continue
                status = self.gbp_driver.delete_policy_rule_set(rule_set["id"])
                if status is None:
                    err_msg = "Error While Deleting policy Rule Set %s "\
                        "of tenant %s" % (rule_set["id"],
                                          tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting policy rule sets."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_policy_rules(self, tenant_info):
        """
        For Deleting all policy rules in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            # get all policy rules
            policy_rule_list = self.gbp_driver.list_policy_rule()
            if policy_rule_list is None:
                err_msg = "Failed to list policy rules in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Policy Rule List: %s" % policy_rule_list)

            if len(policy_rule_list) == 0:
                msg = "There are not policy rules to delete in tenant %s."\
                    % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for policy_rule in policy_rule_list:
                if policy_rule["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.delete_policy_rule(policy_rule["id"])
                if status is None:
                    err_msg = "Failed to delete policy rule %s in tenant %s"\
                        % (policy_rule["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting policy rules."
            self.logger.error(err_msg)
            return err_msg

    def delete_all_policy_classifiers(self, tenant_info):
        """
        For Deletion of all policy classifiers in a given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            # Get all classifier list
            policy_classifier_list = self.gbp_driver.list_policy_classifier()
            if policy_classifier_list is None:
                err_msg = "policy classifier list failed in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Policy Classifier List: %s"
                              % policy_classifier_list)

            if len(policy_classifier_list) == 0:
                msg = "There are not classifiers to delete in tenant %s"\
                    % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for classifier in policy_classifier_list:
                if classifier["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.\
                    delete_policy_classifier(classifier["id"])
                if status is None:
                    err_msg = "Failed to delete policy classifier %s "\
                        "of tenant %s." % (classifier["id"],
                                           tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting policy classifier."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_policy_actions(self, tenant_info):
        """
        For Deleting all policy actions in a given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success returns True.
            On Failure returns string containing error message.
        """
        try:
            # get policy actions.
            policy_action_list = self.gbp_driver.list_policy_action()
            if policy_action_list is None:
                err_msg = "Failed to list policy actions in tenant %s ."\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Policy Action List: %s"
                              % policy_action_list)

            if len(policy_action_list) == 0:
                msg = "There are not policy actions to delete in tenant %s . "\
                    % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for action in policy_action_list:
                if action["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.delete_policy_action(action["id"])
                if status is None:
                    err_msg = "Failed to delete policy action %s of "\
                        "tenant %s." % (action["id"],
                                        tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting policy actions."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_service_chain_specs(self, tenant_info):
        """
        For Deleting all service chain specs in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None
                            'cloud_admin_token': None
                        }
        Returns: On Success returns True.
            On failure returns string containing error message.
        """
        try:
            # get all service chain specs.
            service_chain_spec_list = self.gbp_driver.\
                list_service_chain_spec()
            if service_chain_spec_list is None:
                err_msg = "Failed to list service chain specs in "\
                    "tenant %s ." % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Service Chain Spec List: %s"
                              % service_chain_spec_list)

            if len(service_chain_spec_list) == 0:
                msg = "There are not service chain spec to delete in "\
                    "tenant %s" % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for spec in service_chain_spec_list:
                self.gbp_driver.token = tenant_info["token"]
                if spec["tenant_id"] != tenant_info["tid"] and\
                        str(spec["shared"]).lower() == "true" and\
                        tenant_info["name"] + "_" in spec["name"]:
                    # delete using cloud admin token, if spec is
                    # shared resource.
                    self.gbp_driver.token = tenant_info.\
                        get("cloud_admin_token")
                elif spec["tenant_id"] != tenant_info["tid"]:
                    continue

                status = self.gbp_driver.\
                    delete_service_chain_spec(spec["id"])
                if status is None:
                    err_msg = "Failed to delete service chain spec %s of "\
                        "tenant %s." % (spec["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting service chain specs."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_service_chain_nodes(self, tenant_info):
        """
        For Deleting all service chain nodes in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success return True.
            On failure returns string containing error message.
        """
        try:
            # get all service chain nodes.
            service_chain_node_list = self.gbp_driver.\
                list_service_chain_node()
            if service_chain_node_list is None:
                err_msg = "Failed to list service chain node in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Service Chain Node List: %s"
                              % service_chain_node_list)

            if len(service_chain_node_list) == 0:
                msg = "There are not service chain nodes to delete "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for node in service_chain_node_list:
                self.gbp_driver.token = tenant_info["token"]
                if node["tenant_id"] != tenant_info["tid"] and\
                        str(node["shared"]).lower() == "true" and\
                        tenant_info["name"] + "_" in node["name"]:
                    # use cloud admin token to delete service chain
                    # node. if node is shared resource.
                    self.gbp_driver.token = tenant_info["cloud_admin_token"]
                elif node["tenant_id"] != tenant_info["tid"]:
                    continue

                status = self.gbp_driver.\
                    delete_service_chain_node(node["id"])
                if status is None:
                    err_msg = "Failed to delete service chain node %s of "\
                        "tenant %s." % (node["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting service chain nodes."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_l2policies(self, tenant_info):
        """
        For Deleting all l2policies in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On Success returns True
            On failure returns string containing error message.
        """
        try:
            # get all l2policies
            l2policy_list = self.gbp_driver.list_l2policy()
            if l2policy_list is None:
                err_msg = "Failed to list l2policies in tenant %s"\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("L2policy List: %s" % l2policy_list)

            if len(l2policy_list) == 0:
                msg = "There are not l2policies to delete in tenant %s."\
                    % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for policy in l2policy_list:
                if policy["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.delete_l2policy(policy["id"])
                if status is None:
                    err_msg = "Failed to delete l2policy %s of tenant %s."\
                        % (policy["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting l2policie."
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_l3policies(self, tenant_info):
        """
        For Deleting all l3policies in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            # get l3policies
            # pdb.set_trace()
            l3policy_list = self.gbp_driver.list_l3policy()
            if l3policy_list is None:
                err_msg = "Failed to list l3policies in tenant %s."\
                    % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("L3policy List: %s" % l3policy_list)

            if len(l3policy_list) == 0:
                msg = "There are not l3policies to delete in tenant %s."\
                    % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for policy in l3policy_list:
                if policy["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.delete_l3policy(policy["id"])
                if status is None:
                    err_msg = "Failed to delete l3policy %s of tenant %s."\
                        % (policy["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting l3policies"
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_external_policies(self, tenant_info):
        """
        For Deleting all external policies in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            # list network service policies in the tenant.
            external_policy_list = self.gbp_driver.list_external_policy()
            if external_policy_list is None:
                err_msg = "Failed to list external policies "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("External policy list: %s"
                              % external_policy_list)

            if len(external_policy_list) == 0:
                msg = "There are not external policies to delete "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for policy in external_policy_list:
                if policy["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.delete_external_policy(policy["id"])
                if status is None:
                    err_msg = "Failed to delete external policy %s "\
                        "of tenant %s" % (policy["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting external "\
                "policies in tenant %s" % tenant_info["tid"]
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_external_segments(self, tenant_info):
        """
        For Deleting all external segments in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            # list network service policies in the tenant.
            external_segment_list = self.gbp_driver.list_external_segments()
            if external_segment_list is None:
                err_msg = "Failed to list external segments "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("External segment list: %s"
                              % external_segment_list)

            if len(external_segment_list) == 0:
                msg = "There are not external segment to delete "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for segment in external_segment_list:
                if segment["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.delete_external_segment(segment["id"])
                if status is None:
                    err_msg = "Failed to delete external policy %s "\
                        "of tenant %s" % (segment["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting external "\
                "policies in tenant %s" % tenant_info["tid"]
            self.logger.error("%s" % traceback.format_exc())
            return err_msg

    def delete_all_network_service_policies(self, tenant_info):
        """
        For Deleting all network service policies in given tenant.
        Arguments: (1) tenant_info (dict)
                e.g. tenant_info = {
                            'name': None,
                            'tid': None,
                            'token': None,
                            "cloud_admin_token": None
                        }
        Returns: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            # list network service policies in the tenant.
            net_service_policy_list = self.gbp_driver.\
                list_network_service_policy()
            if net_service_policy_list is None:
                err_msg = "Failed to list network service policies "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.error(err_msg)
                return err_msg

            self.logger.debug("Network service policy list: %s"
                              % net_service_policy_list)

            if len(net_service_policy_list) == 0:
                msg = "There are not network service policies to delete "\
                    "in tenant %s" % tenant_info["tid"]
                self.logger.debug(msg)
                return True

            for policy in net_service_policy_list:
                if policy["tenant_id"] != tenant_info["tid"]:
                    continue
                status = self.gbp_driver.\
                    delete_network_service_policy(policy["id"])
                if status is None:
                    err_msg = "Failed to delete network service policy %s "\
                        "of tenant %s" % (policy["id"], tenant_info["tid"])
                    self.logger.error(err_msg)
                    return err_msg
            return True
        except:
            err_msg = "Exception occurred while deleting network service "\
                "policies in tenant %s" % tenant_info["tid"]
            self.logger.error("%s" % traceback.format_exc())
            return err_msg
