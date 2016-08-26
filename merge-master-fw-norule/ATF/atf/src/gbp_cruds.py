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


"""This file contains functions for validating REST API (CREATE, SHOW, LIST,
UPDATE, DELETE) of gbp resources like service chain node, service chain spec,
policy classifier, policy action, policy rule, policy rule set, policy target
group, policy target, external segment, external
policy & network service policy.
"""

import json
import inspect
import threading

import atf.config.common_config as common_config
import atf.config.setup_config as setup_config
import atf.config.gbp_config as gbp_config
from atf.lib.lib_common import commonLibrary, StressTestHelper
from atf.lib.gbp_constructs import gbp_construct
from atf.lib.lib_os import OpenStackLibrary
import atf.lib.nvp_atf_logging as log
from atf.lib.resource_cleanup import ResourceCleanup
from atf.config.template_config import lb_template_config

# pylint: disable=W0703
# pylint: disable=W1201

# logger object
LOG_OBJ = log.get_atf_logger()


class GbpCrudsValidation(object):
    """Class contains methods for validating gbp crud (create, list,
    show, update, & delete) api's.
    """
    def __init__(self):
        self.result_dict = {"create": "", "update": "", "list": "",
                            "show": "", "delete": ""}
        self.tc_id = ""
        self.tenant_creation = "pass"
        self.tenant_info = {"project_name": "",
                            "user_name": "", "password": "",
                            "roles": common_config.keystonev3_project_details[
                                            0]["roles"]}
        self.test_results = {}
        self.LIBOS = OpenStackLibrary(setup_config.setupInfo[
                                "os-controller-node"]["pubip"])
        self.cleanup = ResourceCleanup(self.LIBOS)
        self.common = commonLibrary()
        self.gbp_obj = gbp_construct("", setup_config.setupInfo[
                                    "os-controller-node"]["pubip"])

    def __set_result_dict(self, key_list, tc_reason=""):
        """For modifying instance variable "result_dict".
        Arguments:
            key_list: list
                e.g.
                    ["create", "list", "show", "update", "delete"]
            tc_reason: string (test failure reason). default empty string.
        """
        try:
            for key in key_list:
                try:
                    self.result_dict[key] = tc_reason
                except KeyError:
                    pass
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while updating result dictionary."

    def __update_result_file(self):
        """For updating test case result in result file. """
        try:
            test_failure_reason = ""
            for key in self.result_dict:
                tcreason = self.result_dict[key]
                tc_id = self.tc_id + "_" + key
                if tcreason:
                    tcstatus = "FAIL"
                    message = "Test Case ID: %s" % tc_id + "\nTest Case"\
                        " Status: %s" % tcstatus + "\nFailure "\
                        "Reason: %s" % tcreason
                    decorated_msg = self.common.get_decorated_message(
                                                message, "-", 70)
                    LOG_OBJ.info(decorated_msg)
                    print decorated_msg
                    if tcreason not in test_failure_reason:
                        test_failure_reason += tcreason
                else:
                    tcstatus = "PASS"
                    message = "Test Case ID: %s" % tc_id + "\nTest Case"\
                        " Status: %s" % tcstatus
                    decorated_msg = self.common.get_decorated_message(
                                                    message, "-", 70)
                    LOG_OBJ.info(decorated_msg)

            tcstatus = 'FAIL' if test_failure_reason else "PASS"
            # During stress testing don't update result file.
            if "main" not in threading.currentThread().getName().lower():
                StressTestHelper().stress_test_result_update(
                            self.tc_id, tcstatus, test_failure_reason)
                return
            self.common.test_result_update(
                        self.tc_id, tcstatus, test_failure_reason)
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while updating test result"\
                " in result file."

    def __set_tenant_info(self):
        """ Setter to fill tenant_info """
        thread_name = ""
        if 'main' not in threading.currentThread().getName().lower():
            thread_name = "_" + threading.currentThread().getName()

        project_no = common_config.keystonev3_project_details[0]['project_no']
        project_name = common_config.keystonev3_project_details[0][
                        'project_name'] + str(project_no) + thread_name
        user_name = common_config.keystonev3_project_details[0][
                        'user_name'] + str(project_no) + thread_name
        passwd = common_config.keystonev3_project_details[0]['password']
        common_config.keystonev3_project_details[0]['project_no'] += 1
        self.tenant_info["project_name"] = project_name
        self.tenant_info["user_name"] = user_name
        self.tenant_info["password"] = passwd
        return True

    def gbp_crud_master_testcase(self, tc_no_string):
        """This function will convert test case number string
        into list of test numbers. Using this list it will execute
        test cases for gbp crud validation & will update result file.

        Arguments:
            tc_no_string (comma separated test cases number string)
                e..g.
                    1. tc_no_string = "1-13"
                    2. tc_no_string = "1,8,10-13"
                    3. tc_no_string = "12"
        """
        try:
            # convert test case no. string into list of comma separated tc nos.
            test_case_no_list = self.common.\
                build_testcase_no_list(tc_no_string)
            if type(test_case_no_list) != list:
                LOG_OBJ.error("Failed to build test case no. string to test"
                              " cases id list.")
                return

            print "GBP crud test case list: %s" % test_case_no_list
            LOG_OBJ.info("GBP crud test case list: %s" % test_case_no_list)
            if len(test_case_no_list) == 0:
                LOG_OBJ.debug("Test cases for execution are not mentioned in "
                              "test_cases_id.txt file.")
                return
            # starting gbp cruds validation.
            for tc_no in test_case_no_list:
                # get test cases id
                try:
                    if int(tc_no) not in gbp_config.\
                            gbp_crud_test_no_to_id_mapping.keys():
                        print "Invalid test cases number %s. There is "\
                            "no mapping for %s test number." % (tc_no, tc_no)
                        LOG_OBJ.error("Invalid test cases number %s. There"
                                      " is no mapping for %s test number."
                                      % (tc_no, tc_no))
                        return
                except Exception as err:
                    print "Invalid test cases number %s. There is no mapping"\
                            " for %s test number." % (tc_no, tc_no)
                    LOG_OBJ.exception(err)
                    LOG_OBJ.error("Invalid test cases number %s. There is no"
                                  " mapping for %s test number."
                                  % (tc_no, tc_no))
                    return

                tc_id = gbp_config.gbp_crud_test_no_to_id_mapping[int(tc_no)]
                print "Test cases number %s is mapped with test "\
                    "case id %s" % (tc_no, tc_id)
                LOG_OBJ.info("Test cases number %s is mapped with "
                             "test case id %s" % (tc_no, tc_id))
                try:   # executing test case.
                    eval('self.' + tc_id + '()')
                except Exception as err:
                    LOG_OBJ.exception(err)
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem occurred in gbp cruds master test case."

    def __create_tenant_common(self):
        """ Common method used to create a projects & users.

        Return: On success returns tuple like (tenant_id, token)
            On Failure returns string containing error message.
        """
        try:
            tenant_info = self.tenant_info
            # check if project & user exist.
            tenant_list = self.LIBOS.list_tenants()
            if type(tenant_list) is not list:
                err_msg = "Some problem occurred while listing tenants."
                LOG_OBJ.error(err_msg)
                return err_msg
            user_list = self.LIBOS.list_users()
            if type(user_list) is not list:
                err_msg = "Some problem occurred while listing users."
                LOG_OBJ.error(err_msg)
                return err_msg
            tenant_exist = False
            user_exist = False
            # check if tenant we going to create present already.
            for tenant in tenant_list:
                if tenant["name"] == tenant_info["project_name"]:
                    tenant_exist = True
            # check if user we going create already present.
            for user in user_list:
                if user["name"] == tenant_info["user_name"]:
                    user_exist = True

            if tenant_exist and user_exist:
                LOG_OBJ.debug("Tenant %s and user %s already present."
                              % (tenant_info["project_name"],
                                 tenant_info["user_name"]))
                status = self.__resource_cleanup()
                if type(status) is str:
                    err_msg = "Some problem occurred while deleting reso"\
                        "urces of tenant %s" % tenant_info["project_name"]
                    LOG_OBJ.error(err_msg)
                    return err_msg

            # create tenant.
            self.tenant_creation = "fail"
            tenant_id = self.LIBOS.create_tenant(tenant_info)
            if type(tenant_id) is not unicode:
                err_msg = "Some problem occurred while creating tenant."
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.debug("Tenant Created: %s" % tenant_id)
            self.tenant_creation = "pass"
            return (tenant_id, self.LIBOS.project_info["token_project"])
        except Exception as err:
            self.tenant_creation = "fail"
            LOG_OBJ.exception(err)
            return "Exception occurred while creating tenant."

    def __service_chain_node_create(self):
        """supporting function.
        Returns: on success returns service chain node id (unicode)
            on failure returns string containing error message.
        """
        try:
            chain_node_name = "test-service-chain-node"
            service_type = "LOADBALANCER"
            config = json.dumps(lb_template_config)
            service_chain_node_info = self.gbp_obj.\
                create_service_chain_node(chain_node_name,
                                          service_type=service_type,
                                          config=config)
            if not isinstance(service_chain_node_info, dict):
                err_msg = "Failed to create service chain node"
                LOG_OBJ.error(err_msg)
                return err_msg

            service_chain_node_id = service_chain_node_info["id"]
            return service_chain_node_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating service chain node."

    def __service_chain_spec_create(self):
        """supporting function.
        Return: on success returns service chain spec id (unicode)
            On failure returns string containing error message.
        """
        try:
            service_chain_node_id = self.__service_chain_node_create()
            if not isinstance(service_chain_node_id, unicode):
                err_msg = service_chain_node_id
                return err_msg

            spec_name = "test-service-chain-spec"
            service_chain_spec_info = self.gbp_obj.\
                create_service_chain_spec(spec_name,
                                          nodes=[service_chain_node_id])
            if not isinstance(service_chain_spec_info, dict):
                err_msg = "Failed to create service chain spec."
                LOG_OBJ.error(err_msg)
                return err_msg

            service_chain_spec_id = service_chain_spec_info["id"]
            return service_chain_spec_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while creating service chain spec."

    def __policy_action_create(self):
        """Supporting function.
        Return: On success returns policy action id. (unicode).
            On failure returns string containing error message.
        """
        try:
            service_chain_spec_id = self.__service_chain_spec_create()
            if not isinstance(service_chain_spec_id, unicode):
                return str(service_chain_spec_id)

            action_type = "redirect"
            action_name = "test-policy-action"
            policy_action_info = self.gbp_obj.create_policy_action(
                            action_name, action_type=action_type,
                            action_value=service_chain_spec_id)
            if not isinstance(policy_action_info, dict):
                err_msg = "Failed to create policy action"
                LOG_OBJ.error(err_msg)
                return err_msg
            policy_action_id = policy_action_info["id"]
            return policy_action_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while creating policy action."

    def __policy_rule_create(self):
        """Supporting function.
        Return: On success returns policy rule id (unicode)
            On failure returns string containing error message.
        """
        try:
            policy_action_id = self.__policy_action_create()
            if not isinstance(policy_action_id, unicode):
                err_msg = policy_action_id
                return err_msg

            policy_classifier_name = "test-classifier"
            classifier_direction = "bi"
            classifier_protocol = "tcp"
            classifier_port = "80"
            classifier_info = self.gbp_obj.create_policy_classifier(
                name=policy_classifier_name, direction=classifier_direction,
                protocol=classifier_protocol, port_range=classifier_port
                )
            if not isinstance(classifier_info, dict):
                err_msg = "Failed to create Policy classifier."
                LOG_OBJ.error(err_msg)
                return err_msg
            policy_classifier_id = classifier_info["id"]

            policy_rule_name = "test-policy-rule"
            policy_rule_info = self.gbp_obj.create_policy_rule(
                policy_rule_name, policy_classifier_id=policy_classifier_id,
                policy_actions=[policy_action_id]
                )
            if not isinstance(policy_rule_info, dict):
                err_msg = "Failed to create policy rule"
                LOG_OBJ.error(err_msg)
                return err_msg
            policy_rule_id = policy_rule_info["id"]
            return policy_rule_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating policy rule."

    def __policy_rule_set_create(self):
        """supporting function.
        Return: on success returns policy rule set id (unicode).
            On failure returns string containing error message.
        """
        try:
            policy_rule_id = self.__policy_rule_create()
            if not isinstance(policy_rule_id, unicode):
                err_msg = policy_rule_id
                return err_msg

            policy_rule_set_name = "test-policy-rule-set"
            policy_rules_list = [policy_rule_id]
            policy_rule_set_info = self.gbp_obj.create_policy_rule_set(
                    policy_rule_set_name, policy_rules=policy_rules_list
                    )
            if not isinstance(policy_rule_set_info, dict):
                err_msg = "Failed to create policy rule set."
                LOG_OBJ.error(err_msg)
                return err_msg

            policy_rule_set_id = policy_rule_set_info["id"]
            return policy_rule_set_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating policy rule set."

    def __validate_policy_target_group_creation(self, group_id):
        """Supporting function. Checks if default subnet &
        router getting created or not after creating
        policy target group.

        Argu: group_id: Id of policy target group id.

        Return: On success returns True.
            On Failure returns string containing error message.
        """
        try:
            group_details = self.gbp_obj.show_policy_target_group(group_id)
            if not isinstance(group_details, dict):
                err_msg = "failed to get details of policy target "\
                    "group: %s" % group_id
                LOG_OBJ.error(err_msg)
                return err_msg
            subnet_id = group_details["subnets"][0]
            l2policy_id = group_details["l2_policy_id"]

            l2policy_details = self.gbp_obj.show_l2policy(l2policy_id)
            if not isinstance(l2policy_details, dict):
                err_msg = "Failed to get details of l2policy: %s" % l2policy_id
                LOG_OBJ.error(err_msg)
                return err_msg
            LOG_OBJ.debug("L2policy %s got created as a effect of policy "
                          "target group %s creation" % (l2policy_id, group_id))
            l3policy_id = l2policy_details["l3_policy_id"]

            l3policy_details = self.gbp_obj.show_l3policy(l3policy_id)
            if not isinstance(l3policy_details, dict):
                err_msg = "Failed to get details of l3policy: %s" % l3policy_id
                LOG_OBJ.error(err_msg)
                return err_msg
            router_id = l3policy_details["routers"][0]
            LOG_OBJ.debug("L3policy %s got created as a effect of "
                          "policy target group %s creation"
                          % (l3policy_id, group_id))

            LOG_OBJ.debug("Default subnet %s & default router %s created after"
                          " creating policy target group %s"
                          % (subnet_id, router_id, group_id))
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while validating default resources"\
                "(router & subnet) after creating policy target group."

    def __l3_policy_create(self):
        """supporting function.
        Return: On success returns l3 policy id (unicode).
            On failure returns string containing error message.
        """
        try:
            l3policy_name = "test-l3policy"
            subnet_prefix_length = "24"  # TODO: read from config file.
            ip_version = 4    # TODO: modify to read from config file.
            ip_pool = "25.9.9.0/24"  # TODO: modify to read from config file.
            l3_policy_info = self.gbp_obj.create_l3policy(
                    l3policy_name, subnet_prefix_length=subnet_prefix_length,
                    ip_version=ip_version, ip_pool=ip_pool
                    )
            if not isinstance(l3_policy_info, dict):
                err_msg = "failed to create l3policy."
                LOG_OBJ.error("failed to create l3policy.")
                return err_msg
            l3policy_id = l3_policy_info["id"]
            return l3policy_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating policy rule set."

    def __clean_external_segment(self, ext_seg_info):
        """supporting function. used to clean resources (external segment &
        dummy external network after validating api's of external segments &
        external policies.)

        Argu: ext_seg_info (tuple)
            (external_segment_id, external_net_id)

        Return: On success returns True.
            On failure returns string containing error message.
        """
        try:
            old_token = None
            # need to clean external segment & ext network using
            # admin token. so modifying tokens object self.LIBOS & self.gbp_obj
            token_project = self.LIBOS.cloud_admin_info["token_project"]
            token_domain = self.LIBOS.cloud_admin_info["token_domain"]
            self.gbp_obj.token = token_project
            old_token = self.LIBOS.set_tenant_info(
                            common_config.cloud_admin_project,
                            token_domain, token_project,
                            self.LIBOS.cloud_admin_info["project_id"]
                            )
            if type(old_token) is not tuple:
                err_msg = "Failed to switch project context to "\
                    "cloud admin project"
                LOG_OBJ.error(err_msg)
                return err_msg

            ext_seg_id = ext_seg_info[0]
            ext_net_id = ext_seg_info[1]
            # delete external segment if present
            ext_seg_list = self.gbp_obj.list_external_segments()
            if not isinstance(ext_seg_list, list):
                err_msg = "Failed to list external segments in cloud "\
                    "admin project."
                LOG_OBJ.error(err_msg)
                return err_msg

            for segment in ext_seg_list:
                if segment["id"] == ext_seg_id:
                    status = self.gbp_obj.delete_external_segment(ext_seg_id)
                    if not isinstance(status, bool):
                        err_msg = "Failed to delete external segment: "\
                            "%s" % ext_seg_id

            # clean external network.
            status = self.LIBOS.delete_net(ext_net_id)
            if not isinstance(status, bool):
                err_msg = "Failed to delete dummy external network: "\
                    "%s" % ext_net_id
                LOG_OBJ.error(err_msg)
                return err_msg
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while cleaning external "\
                "segment & dummy external network."
        finally:
            # revert project context.
            if old_token:
                status = self.LIBOS.set_tenant_info(old_token[0], old_token[1],
                                                    old_token[2], old_token[3])
                if type(status) != tuple:
                    err_msg = "failed to revert back project context. after"\
                        "cleaning external segment & dummy external network"\
                        " using cloud admin token. ignoring."
                    LOG_OBJ.error(err_msg)

    def __external_segment_create(self, cidr):
        """Supporting function. Will create external segment.
        Return: On success returns tuple (ext_segment_id, exte_net_id).
            On Failure returns string containing error message.
        """
        try:
            # switch project context to cloud admin project
            old_token = None
            token_project = self.LIBOS.cloud_admin_info["token_project"]
            token_domain = self.LIBOS.cloud_admin_info["token_domain"]
            self.gbp_obj.token = token_project
            old_token = self.LIBOS.set_tenant_info(
                            common_config.cloud_admin_project,
                            token_domain, token_project,
                            self.LIBOS.cloud_admin_info["project_id"]
                            )
            if type(old_token) is not tuple:
                err_msg = "Failed to switch project context to "\
                    "cloud admin project"
                LOG_OBJ.error(err_msg)
                return err_msg

            # create external network.
            ext_net_info = self.__create_dummy_ext_net(cidr)
            if not isinstance(ext_net_info, tuple):
                err_msg = ext_net_info
                return err_msg

            # create external segment.
            kwrags = {"ip_version": 4, "cidr": cidr, "shared": True,
                      "subnet_id": ext_net_info[1]}
            external_segment_name = "test-external-segment"
            external_segment_info = self.gbp_obj.\
                create_external_segment(external_segment_name, **kwrags)
            if not isinstance(external_segment_info, dict):
                err_msg = "Failed to create external segment."
                LOG_OBJ.error(err_msg)
                return err_msg
            external_segment_id = external_segment_info["id"]
            return (external_segment_id, ext_net_info[0])
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating external network."
        finally:
            # revert project context.
            if old_token:
                status = self.LIBOS.set_tenant_info(old_token[0], old_token[1],
                                                    old_token[2], old_token[3])
                if type(status) != tuple:
                    err_msg = "failed to revert back project context. after"\
                        "cleaning external segment & dummy external network"\
                        " using cloud admin token. ignoring."
                    LOG_OBJ.error(err_msg)

    def __create_dummy_ext_net(self, cidr):
        """Supporting function. It will used for validating,
        external segment api's.

        Argu: cidr (e.g. 3.3.3.0/24)

        Return: On success returns tuple (ext_net_id, ext_subnet_id).
            On Failure returns string containing error message.
        """
        try:
            # switch project context to cloud admin project
            old_token = None
            token_project = self.LIBOS.cloud_admin_info["token_project"]
            token_domain = self.LIBOS.cloud_admin_info["token_domain"]
            self.gbp_obj.token = token_project
            old_token = self.LIBOS.set_tenant_info(
                            common_config.cloud_admin_project,
                            token_domain, token_project,
                            self.LIBOS.cloud_admin_info["project_id"]
                            )
            if type(old_token) is not tuple:
                err_msg = "Failed to switch project context to "\
                    "cloud admin project"
                LOG_OBJ.error(err_msg)
                return err_msg

            gateway = '.'.join(cidr.split('.')[:-1]) + '.254'
            start_ip = '.'.join(cidr.split('.')[:-1]) + '.30'
            end_ip = '.'.join(cidr.split('.')[:-1]) + '.60'
            # creating dummy external network for
            extnet_info = {'extnet_name': "test-dummy-ext-net",
                           'gateway': gateway,
                           'cidr': cidr,
                           'start_ip': start_ip,
                           'end_ip': end_ip
                           }
            ext_net_id = self.LIBOS.\
                create_external_network(extnet_info, ignore_privious=True)
            if not isinstance(ext_net_id, unicode):
                err_msg = "Failed to create dummy external network."
                LOG_OBJ.error(err_msg)
                return err_msg

            # get subnet id of the dummy external network created above.
            subnet_list = self.LIBOS.list_subnet()
            if not isinstance(subnet_list, list):
                err_msg = "Failed to list subnets in admin tenant."
                LOG_OBJ.error(err_msg)
                return err_msg
            subnet_id = ""
            for subnet in subnet_list:
                if subnet["network_id"] == ext_net_id:
                    subnet_id = subnet["id"]

            if subnet_id == "":
                err_msg = "External subnet not created for external network:"\
                    " %s" % ext_net_id
                LOG_OBJ.error(err_msg)
                return err_msg
            return (ext_net_id, subnet_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating dummy "\
                "external network."
        finally:
            # revert project context.
            if old_token:
                status = self.LIBOS.set_tenant_info(old_token[0], old_token[1],
                                                    old_token[2], old_token[3])
                if type(status) != tuple:
                    err_msg = "failed to revert back project context. after"\
                        "cleaning external segment & dummy external network"\
                        " using cloud admin token. ignoring."
                    LOG_OBJ.error(err_msg)

    def __resource_cleanup(self):
        """Supporting function. Used for cleaning resources post
        test case completion.

        Return: (a) On success returns True
            (b) On failure returns string containing error message.
        """
        try:
            tenant_info = self.tenant_info
            if self.tenant_creation is "fail":
                msg = "Looks like tenant %s or user %s is not created."\
                    " Skipping resource cleanup." %\
                    (tenant_info["project_name"], tenant_info["user_name"])
                LOG_OBJ.error(msg)
                return msg
            tenant_details_dict = {"local_project_details": [],
                                   "remote_project_details": []}
            tenant_details_dict["local_project_details"].append({
                                "project_name": tenant_info["project_name"],
                                "user_name": tenant_info['user_name'],
                                "password": tenant_info['password'],
                                "domain_name": "default", "sharable": False
                                })
            status = self.cleanup.clean_resources(tenant_details_dict)
            if not isinstance(status, bool):
                return status
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while cleaning resources after"\
                "test case completion"

    def gbp_crud_policy_target_group(self):
        """Validates api's (create, list, show, update, delete)
        of resource policy target group.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("################################################")

            tcreason = ""

            # tenant creation
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            # update gbp crud object.
            self.gbp_obj.token = tenant_details[1]

            # create policy target group
            group_name = "test-policy-target-group"
            ptgrp_info = self.gbp_obj.create_policy_target_group(group_name)
            if not isinstance(ptgrp_info, dict):
                tcreason += "Policy target group creation failed"
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            pt_grp_id = ptgrp_info["id"]
            LOG_OBJ.debug("Policy target group created with id:"
                          " %s" % pt_grp_id)

            # validate default resources created after
            # creating policy target group.
            status = self.__validate_policy_target_group_creation(pt_grp_id)
            if not isinstance(status, bool):
                tcreason = status
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # show policy target group
            ptg_show = self.gbp_obj.show_policy_target_group(
                                        group_id=pt_grp_id)
            if not isinstance(ptg_show, dict):
                tcreason = "Failed to show details of %s policy "\
                    "target group" % pt_grp_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Policy target group details: %s" % ptg_show)

            # list policy target group
            ptg_list = self.gbp_obj.list_policy_target_group()
            if not isinstance(ptg_list, list):
                tcreason = "List operation of policy target group failed."
                LOG_OBJ.error("List operation of policy target group failed.")
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("list operation of policy target "
                              "group successful")

            # update policy target group.
            updated_ptg_name = "updated_policy_target_group"
            updated_description = "updated description"
            updated_ptg_info = self.gbp_obj.\
                update_policy_target_group(pt_grp_id, updated_ptg_name,
                                           description=updated_description)
            if not isinstance(updated_ptg_info, dict):
                tcreason = "Some problem occurred while updating %s "\
                    "policy target group." % pt_grp_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_ptg_info["name"] != updated_ptg_name and\
                    updated_ptg_info["description"] != updated_description:
                tcreason = "Failed to update name & description of %s "\
                    "policy target group" % pt_grp_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated policy target "
                              "group: %s" % pt_grp_id)

            # delete policy target group.
            status = self.gbp_obj.delete_policy_target_group(pt_grp_id)
            if status is not True:
                tcreason = "Delete operation of policy target group "\
                    "%s failed." % pt_grp_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Delete operation of policy target group "
                          "successful completed.")
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while policy target group "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_policy_classifier(self):
        """Validates api's (create, list, show, update, delete)
        of resource policy classifier.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            protocol_list = ["tcp", "udp", "icmp"]
            direction = ["in", "out", "bi"]
            port_range = ["80", "80:13001"]
            classifier_id_list = []

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            # update class objects with new tenant token
            tenant_id = tenant_details[0]
            self.gbp_obj.token = tenant_details[1]

            # create policy classifier
            for protocol in protocol_list:
                for dire in direction:
                    for port in port_range:
                        policy_classifier_name = "classifier_" + "_" +\
                            protocol + "_" + dire + "_" + port
                        classifier_direction = dire
                        classifier_protocol = protocol
                        classifier_port = port
                        LOG_OBJ.debug("Creating policy classifier for "
                                      "protocol=%s, direction=%s, port=%s"
                                      % (protocol, dire, port))
                        classifier_info = self.gbp_obj.\
                            create_policy_classifier(
                                            policy_classifier_name,
                                            direction=classifier_direction,
                                            protocol=classifier_protocol,
                                            port_range=classifier_port
                                            )

                        if not isinstance(classifier_info, dict):
                            tcreason = "Failed to create Policy classifier"\
                                " in %s tenant for %s protocol, %s "\
                                "direction %s port" % (tenant_id, protocol,
                                                       dire, port)
                            LOG_OBJ.error(tcreason)
                            self.__set_result_dict(self.result_dict.keys(),
                                                   tcreason)
                            return
                        policy_classifier_id = classifier_info["id"]
                        classifier_id_list.append(policy_classifier_id)
                        LOG_OBJ.debug("Created policy classifier successfully "
                                      "with id : %s" % policy_classifier_id)

            # show policy classifier.
            classifier_info = self.gbp_obj.show_policy_classifier(
                                classifier_id=str(policy_classifier_id))
            if not isinstance(classifier_info, dict):
                tcreason = "Failed to show details of policy classifier"\
                    ": %s" % policy_classifier_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Show policy classifier details successful.")

            # list policy classifier.
            classifier_list = self.gbp_obj.list_policy_classifier()
            if not isinstance(classifier_list, list):
                tcreason = "failed to list policy classifiers of %s tenant."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed policy classifier in "
                              "%s tenant" % tenant_id)

            # update policy classifier.
            updated_classifier_name = "updated_policy_classifier"
            updated_classifier_description = "updated policy description"
            updated_classifier_info = self.gbp_obj.update_policy_classifier(
                    policy_classifier_id, name=updated_classifier_name,
                    description=updated_classifier_description
                    )
            if not isinstance(updated_classifier_info, dict):
                tcreason = "Failed to update policy classifier: "\
                    "%s" % policy_classifier_id
                LOG_OBJ.error("Failed to update policy classifier: "
                              "%s" % policy_classifier_id)
                self.__set_result_dict(["update"], tcreason)
            elif updated_classifier_info["name"] != updated_classifier_name\
                and updated_classifier_info["description"] !=\
                    updated_classifier_description:
                tcreason = "Failed to update policy classifier: "\
                    "%s" % policy_classifier_id
                LOG_OBJ.error("Failed to update policy classifier: "
                              "%s" % policy_classifier_id)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated policy classifier:"
                              " %s" % policy_classifier_id)

            # delete policy classifier.
            status = self.gbp_obj.delete_policy_classifier(
                                    policy_classifier_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete policy classifier:"\
                    " %s" % policy_classifier_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return

            LOG_OBJ.debug("Successfully deleted policy classifier:"
                          " %s" % policy_classifier_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while policy classifier "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_policy_target(self):
        """Validates api's (create, list, show, update, delete)
        of resource policy target.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("##################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("##################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create policy target group. for creating policy
            # target we need to create policy target group.
            policy_target_group_name = "test-policy-target-group"
            ptgrp_info = self.gbp_obj.\
                create_policy_target_group(policy_target_group_name)
            if not isinstance(ptgrp_info, dict):
                tcreason += "Policy target group creation failed"
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            pt_grp_id = ptgrp_info["id"]
            LOG_OBJ.debug("Created policy target group: %s" % pt_grp_id)

            # create policy target
            ptarget_name = "test-policy-target"
            ptarget_info = self.gbp_obj.\
                create_policy_target(name=ptarget_name, tenant_id=tenant_id,
                                     policy_target_group_id=pt_grp_id)
            if not isinstance(ptarget_info, dict):
                tcreason = "failed to create policy target in %s "\
                    "policy target group" % pt_grp_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            policy_target_id = ptarget_info["id"]
            LOG_OBJ.debug("Created policy target %s in %s policy "
                          "target group" % (policy_target_id, pt_grp_id))

            # show policy target
            policy_target_details = self.gbp_obj.\
                show_policy_target(policy_target_id)
            if not isinstance(policy_target_details, dict):
                tcreason = "failed to get details of policy target:"\
                    " %s" % policy_target_details
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Get policy target successful.")

            # list policy targets.
            policy_target_list = self.gbp_obj.list_policy_target()
            if not isinstance(policy_target_list, list):
                tcreason = "Failed to list policy targets in "\
                    "tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed policy targets "
                              "in tenant: %s" % tenant_id)

            # update policy target
            updated_name = "updated_policy_target"
            update_description = "updated policy target description"
            kwargs = {"name": updated_name, "description": update_description}
            updated_policy_target = self.gbp_obj.\
                update_policy_target(policy_target_id, **kwargs)
            if type(updated_policy_target) is not dict:
                tcreason = "Failed to update policy target:"\
                    " %s" % policy_target_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)

            elif updated_policy_target["name"] != updated_name and\
                    updated_policy_target["description"] != update_description:
                tcreason = "Failed to update policy target:"\
                    " %s" % policy_target_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated policy target:"
                              " %s" % policy_target_id)

            # delete policy_target.
            status = self.gbp_obj.delete_policy_target(policy_target_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete policy target: %s"\
                    % policy_target_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return

            LOG_OBJ.debug("Successfully deleted policy target:"
                          " %s" % policy_target_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while policy target "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
            return
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_service_chain_node(self):
        """Validates api's (create, list, show, update, delete)
        of resource service chain node.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("##################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("##################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                print tcreason
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create service chain node.
            service_chain_node_id = self.__service_chain_node_create()
            if not isinstance(service_chain_node_id, unicode):
                tcreason = service_chain_node_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # show policy chain node.
            chain_node_details = self.gbp_obj.\
                show_service_chain_node(service_chain_node_id)
            if not isinstance(chain_node_details, dict):
                tcreason = "Failed get details of service "\
                    "chain node: %s" % service_chain_node_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Get service chain node details successful")

            # list service chain node.
            chain_node_list = self.gbp_obj.list_service_chain_node()
            if not isinstance(chain_node_list, list):
                tcreason = "Failed to list service chain node in "\
                    "tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed service chain nodes in "
                              "tenant: %s" % tenant_id)

            # update service chain node.
            updated_service_chain_node_name = "updated_chain_node"
            updated_service_chain_node_desc = "updated SCN description."
            updated_service_chain_node_info = self.gbp_obj.\
                update_service_chain_node(
                                service_chain_node_id,
                                name=updated_service_chain_node_name,
                                description=updated_service_chain_node_desc)
            if not isinstance(updated_service_chain_node_info, dict):
                tcreason = "Failed to update service chain node: "\
                    "%s" % service_chain_node_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_service_chain_node_info["name"] !=\
                updated_service_chain_node_name and\
                    updated_service_chain_node_info["description"] !=\
                    updated_service_chain_node_desc:
                tcreason = "failed to update service chain node:"\
                    " %s" % service_chain_node_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated service chain node:"
                              " %s" % service_chain_node_id)

            # delete service chain node.
            status = self.gbp_obj.delete_service_chain_node(
                                    service_chain_node_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete service chain node:"\
                    " %s" % service_chain_node_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Deleted service chain node %s "
                          "successful" % service_chain_node_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while service chain node "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
            return
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_service_chain_spec(self):
        """Validates api's (create, list, show, update, delete)
        of resource service chain spec.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create service chain spec.
            service_chain_spec_id = self.__service_chain_spec_create()
            if not isinstance(service_chain_spec_id, unicode):
                tcreason = service_chain_spec_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # show service chain spec.
            spec_detail = self.gbp_obj.\
                show_service_chain_spec(service_chain_spec_id)
            if not isinstance(spec_detail, dict):
                tcreason = "Failed to get details of service chain spec: "\
                    "%s" % service_chain_spec_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Getting details of service chain spec %s "
                              "successful" % service_chain_spec_id)

            # list service chain spec.
            spec_list = self.gbp_obj.list_service_chain_spec()
            if not isinstance(spec_list, list):
                tcreason = "Failed to list service chain specs in "\
                    "tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("list operation of service chain"
                              " spec successful ")

            # update service chain spec.
            updated_spec_name = "updated_service_chain_spec"
            updated_spec_desc = "updated spec description"
            updated_spec = self.gbp_obj.\
                update_service_chain_spec(service_chain_spec_id,
                                          name=updated_spec_name,
                                          description=updated_spec_desc)
            if not isinstance(updated_spec, dict):
                tcreason = "Failed to update service chain spec: "\
                    "%s" % service_chain_spec_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_spec["id"] != updated_spec_name and\
                    updated_spec["description"] != updated_spec_desc:
                tcreason = "Failed to update service chain spec:"\
                    " %s" % service_chain_spec_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Updated service chain spec: %s"
                              % service_chain_spec_id)

            # delete service chain spec.
            status = self.gbp_obj.delete_service_chain_spec(
                                        service_chain_spec_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete service chain spec: "\
                    "%s" % service_chain_spec_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Deleted service chain spec: %s"
                          % service_chain_spec_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while service chain spec "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
            return
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_policy_action(self):
        """Validates api's (create, list, show, update, delete)
        of resource policy action.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create policy action with action type "redirect"
            policy_action_id = self.__policy_action_create()
            if not isinstance(policy_action_id, unicode):
                tcreason = policy_action_id
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # create policy action with type "allow"
            LOG_OBJ.debug("Creating policy action with action type allow.")
            action_name = "allow_policy_action"
            policy_action_info = self.gbp_obj.\
                create_policy_action(action_name, action_type="allow")
            if not isinstance(policy_action_info, dict):
                tcreason = "Failed to create policy action for action "\
                    "type \"allow\""
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            LOG_OBJ.debug("Created policy action for action type allow: "
                          "%s" % policy_action_info["id"])

            # show policy action
            policy_action_details = self.gbp_obj.\
                show_policy_action(policy_action_id)
            if not isinstance(policy_action_details, dict):
                tcreason = "Failed to get details of policy action:"\
                    " %s" % policy_action_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Get policy action details successful.")

            # list policy actions
            action_list = self.gbp_obj.list_policy_action()
            if not isinstance(action_list, list):
                tcreason = "Failed to list policy actions in "\
                    "tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed policy actions"
                              " in tenant: %s" % tenant_id)

            # update policy action
            updated_action_name = "updated_policy_action_name"
            updated_action_desc = "updated policy action description"
            updated_policy_action_info = self.gbp_obj.\
                update_policy_action(policy_action_id,
                                     name=updated_action_name,
                                     description=updated_action_desc)
            if not isinstance(updated_policy_action_info, dict):
                tcreason = "Failed to update policy action:"\
                    " %s" % policy_action_id
                LOG_OBJ.error("Failed to update policy action:"
                              " %s" % policy_action_id)
                self.__set_result_dict(["update"], tcreason)
            elif updated_policy_action_info["name"] != updated_action_name and\
                    updated_policy_action_info["description"] !=\
                    updated_action_desc:
                tcreason = "Failed to update policy action:"\
                    " %s" % policy_action_id
                LOG_OBJ.error("Failed to update policy action:"
                              " %s" % policy_action_id)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated policy action:"
                              " %s" % policy_action_id)

            # delete policy action
            status = self.gbp_obj.delete_policy_action(policy_action_id)
            if status is not True:
                tcreason = "Failed to delete policy action:"\
                    " %s" % policy_action_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return

            LOG_OBJ.debug("Successfully deleted policy action:"
                          " %s" % policy_action_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while policy action "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
            return
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_policy_rule(self):
        """Validates api's (create, list, show, update, delete)
        of resource policy rule.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create policy rule.
            policy_rule_id = self.__policy_rule_create()
            if not isinstance(policy_rule_id, unicode):
                tcreason = policy_rule_id
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # show policy rule
            policy_rule_details = self.gbp_obj.show_policy_rule(policy_rule_id)
            if not isinstance(policy_rule_details, dict):
                tcreason = "Failed to get details of policy rule:"\
                    " %s" % policy_rule_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Get policy rule details successful.")

            # list policy rule
            policy_rule_list = self.gbp_obj.list_policy_rule()
            if not isinstance(policy_rule_list, list):
                tcreason = "Failed to list policy rules in tenant"\
                    ": %s" % policy_rule_list
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed policy rules of "
                              "tenant: %s" % tenant_id)

            # update policy rule
            updated_rule_name = "updated_policy_rule"
            updated_policy_rule_desc = "updated policy rule description"
            updated_policy_rule = self.gbp_obj.\
                update_policy_rule(policy_rule_id, name=updated_rule_name,
                                   description=updated_policy_rule_desc)
            if not isinstance(updated_policy_rule, dict):
                tcreason = "Failed to update policy rule: %s" % policy_rule_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_policy_rule["name"] != updated_rule_name and\
                    updated_policy_rule["description"] !=\
                    updated_policy_rule_desc:
                tcreason = "Failed to update policy rule: %s" % policy_rule_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated policy rule:"
                              " %s" % policy_rule_id)

            # delete policy rule
            status = self.gbp_obj.delete_policy_rule(policy_rule_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete policy rule: %s" % policy_rule_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted policy "
                          "rule: %s" % policy_rule_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Exception occurred while policy rule "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_policy_rule_set(self):
        """Validates api's (create, list, show, update, delete)
        of resource policy rule set.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # policy rule set create
            policy_rule_set_id = self.__policy_rule_set_create()
            if not isinstance(policy_rule_set_id, unicode):
                tcreason = policy_rule_set_id
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # policy rule set show
            rule_set_details = self.gbp_obj.show_policy_rule_set(
                                            policy_rule_set_id)
            if not isinstance(rule_set_details, dict):
                tcreason = "Failed to get details of policy "\
                    "rule set: %s" % policy_rule_set_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Get policy rule set details successful.")

            # list policy rule set
            ruleset_list = self.gbp_obj.list_policy_rule_set()
            if not isinstance(ruleset_list, list):
                tcreason = "Failed to list policy rule sets "\
                    "in tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed policy rule sets of"
                              " tenant: %s" % tenant_id)

            # update policy rule set
            updated_rule_set_name = "updated_policy_rule_set"
            updated_rule_set_desc = "updated policy rule set description"
            updated_ruleset_info = self.gbp_obj.\
                update_policy_rule_set(policy_rule_set_id,
                                       name=updated_rule_set_name,
                                       description=updated_rule_set_desc
                                       )
            if not isinstance(updated_ruleset_info, dict):
                tcreason = "Failed to update policy rule set:"\
                    " %s" % policy_rule_set_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_ruleset_info["name"] != updated_rule_set_name and\
                    updated_ruleset_info["description"] !=\
                    updated_rule_set_desc:
                tcreason = "Failed to update policy rule set:"\
                    " %s" % policy_rule_set_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated policy rule"
                              " set: %s" % policy_rule_set_id)

            # delete policy rule set
            status = self.gbp_obj.delete_policy_rule_set(policy_rule_set_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete policy rule "\
                    "set: %s" % policy_rule_set_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted policy rule "
                          "set: %s" % policy_rule_set_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while policy rule set"\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_l3_policy(self):
        """Validates api's (create, list, show, update, delete)
        of resource l3 policy.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create l3policy
            l3policy_id = self.__l3_policy_create()
            if not isinstance(l3policy_id, unicode):
                tcreason = l3policy_id
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # show l3policy
            l3policy_details = self.gbp_obj.show_l3policy(l3policy_id)
            if not isinstance(l3policy_details, dict):
                tcreason = "Failed to get details of l3policy"\
                    ": %s" % l3policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Successfully accessed details of l3policy:"
                              " %s" % l3policy_id)

            # list l3policies.
            l3policy_list = self.gbp_obj.list_l3policy()
            if not isinstance(l3policy_list, list):
                tcreason = "Failed to list l3policies in tenant"\
                    ": %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed l3policies of "
                              "tenant: %s" % tenant_id)

            # update l3policy
            updated_l3policy_name = "updated_l3_policy"
            updated_l3_policy_desc = "updated l3 policy description"
            updated_l3_policy = self.gbp_obj.\
                update_l3policy(l3policy_id, name=updated_l3policy_name,
                                description=updated_l3_policy_desc)
            if not isinstance(updated_l3_policy, dict):
                tcreason = "Failed to update l3policy: %s" % l3policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_l3_policy["name"] != updated_l3policy_name and\
                    updated_l3_policy["description"] != updated_l3_policy_desc:
                tcreason = "Failed to update l3policy: %s" % l3policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated l3policy:"
                              " %s" % l3policy_id)

            # delete l3policy
            status = self.gbp_obj.delete_l3policy(l3policy_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete l3policy: %s" % l3policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted l3policy: %s" % l3policy_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while l3policy "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
            self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_l2_policy(self):
        """Validates api's (create, list, show, update, delete)
        of resource l2 policy.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create l3policy
            l3policy_id = self.__l3_policy_create()
            if not isinstance(l3policy_id, unicode):
                tcreason = l3policy_id
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # create l2policy
            l2policy_name = "test-l2policy"
            l2policy_info = self.gbp_obj.create_l2policy(
                                    l2policy_name, l3_policy_id=l3policy_id)
            if not isinstance(l2policy_info, dict):
                tcreason = "Failed to create l2 policy."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            l2policy_id = l2policy_info["id"]
            LOG_OBJ.debug("Successfully created l2policy: %s" % l2policy_id)

            # show l2policy.
            l2policy_details = self.gbp_obj.show_l2policy(l2policy_id)
            if not isinstance(l2policy_details, dict):
                tcreason = "Failed to get details of l2policy"\
                    ": %s" % l2policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Successfully accessed details of "
                              "l2policy: %s" % l2policy_id)

            # list l2policies.
            l2policy_list = self.gbp_obj.list_l2policy()
            if not isinstance(l2policy_list, list):
                tcreason = "Failed to list l2policies of "\
                    "tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed l2policies of tenant"
                              ": %s" % tenant_id)

            # update l2policy
            updated_l2policy_name = "updated-l2policy"
            updated_l2policy_desc = "updated l2policy description"
            updated_l2policy = self.gbp_obj.\
                update_l2policy(l2policy_id, name=updated_l2policy_name,
                                description=updated_l2policy_desc)
            if not isinstance(updated_l2policy, dict):
                tcreason = "Failed to update l2policy: %s" % l2policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_l2policy["name"] != updated_l2policy_name and\
                    updated_l2policy["description"] != updated_l2policy_desc:
                tcreason = "Failed to update l3policy: %s" % l2policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated l2policy"
                              ": %s" % l2policy_id)

            # delete l2 policy
            status = self.gbp_obj.delete_l2policy(l2policy_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete l2policy: %s" % l2policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted l2policy: %s" % l2policy_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while l2policy "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_external_segment(self):
        """Validates api's (create, list, show, update, delete)
        of resource external segment.
        """
        try:
            old_token_info = ()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # modifying self.LIBOS & self.gbp_obj object.
            self.gbp_obj.token = self.LIBOS.cloud_admin_info["token_project"]
            token_domain = self.LIBOS.cloud_admin_info["token_domain"]
            token_project = self.LIBOS.cloud_admin_info["token_project"]
            cloud_admin_project_id = self.LIBOS.cloud_admin_info["project_id"]
            cloud_admin_project = self.LIBOS.cloud_admin_info["project_name"]
            old_token_info = self.LIBOS.set_tenant_info(
                                        cloud_admin_project,
                                        token_domain,
                                        token_project,
                                        cloud_admin_project_id)
            if not isinstance(old_token_info, tuple):
                tcreason = "Failed to swicth project context to "\
                    "cloud admin project"
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return

            # create external segment in admin tenant.
            ext_cidr = "13.13.13.0/24"
            ext_segment_info = self.__external_segment_create(ext_cidr)
            if not isinstance(ext_segment_info, tuple):
                tcreason = ext_segment_info
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            ext_segment_id = ext_segment_info[0]

            # show external segment
            ext_seg_details = self.gbp_obj.show_external_segment(
                                            ext_segment_id)
            if not isinstance(ext_seg_details, dict):
                tcreason = "Failed to get details of external segment"\
                    ": %s" % ext_segment_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Successfully accessed details of external "
                              "segment: %s" % ext_segment_id)

            # list external segment
            external_seg_list = self.gbp_obj.list_external_segments()
            if not isinstance(external_seg_list, list):
                tcreason = "Failed to list external segments of "\
                    "tenant: %s" % common_config.admin_tenant
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed external segments "
                              "of tenant: %s" % common_config.admin_tenant)

            # update external segment
            updated_ext_seg_name = "updated_ext_segment"
            updated_ext_seg_desc = "updated external segment description"
            updated_ext_seg = self.gbp_obj.\
                update_external_segment(ext_segment_id,
                                        name=updated_ext_seg_name,
                                        description=updated_ext_seg_desc)
            if not isinstance(updated_ext_seg, dict):
                tcreason = "Failed to update external segment"\
                    ": %s" % ext_segment_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_ext_seg["name"] != updated_ext_seg_name and\
                    updated_ext_seg["description"] != updated_ext_seg_desc:
                tcreason = "Failed to update external segment"\
                    ": %s" % ext_segment_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated external segment:"
                              " %s" % ext_segment_id)

            # delete external segment
            status = self.gbp_obj.delete_external_segment(ext_segment_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete external segment"
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted external segment:"
                          " %s" % ext_segment_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while external segment "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # clean external segment, dummy network.
            status = self.__clean_external_segment(ext_segment_info)
            if type(status) == str:
                tcreason = status
                LOG_OBJ.error(status)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_external_policy(self):
        """Validates api's (create, list, show, update, delete)
        of resource external policy.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            tcreason = ""

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            # creating member tenant.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            cidr = "13.13.13.0/24"
            ext_segment_info = self.__external_segment_create(cidr)
            if not isinstance(ext_segment_info, tuple):
                tcreason = ext_segment_info
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            ext_segment_id = ext_segment_info[0]

            self.gbp_obj.token = tenant_details[1]

            # create external policy
            kwargs = {}
            ext_policy_name = "test-external-policy"
            kwargs["external-segments"] = [ext_segment_id]
            external_policy_info = self.gbp_obj.\
                create_external_policy(ext_policy_name, **kwargs)
            if not isinstance(external_policy_info, dict):
                tcreason = "Failed to create external policy."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            external_policy_id = external_policy_info["id"]
            LOG_OBJ.debug("Successfully created external policy:"
                          " %s" % external_policy_id)

            # show external policy
            ext_policy_details = self.gbp_obj.\
                show_external_policy(external_policy_id)
            if not isinstance(ext_policy_details, dict):
                tcreason = "Failed to get details of external "\
                    "policy: %s" % external_policy_id
                LOG_OBJ.debug(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Successfully accessed details of "
                              "external policy: %s" % external_policy_id)

            # list external policies
            external_policy_list = self.gbp_obj.list_external_policy()
            if not isinstance(external_policy_list, list):
                tcreason = "Failed to list external policies"
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed external policies.")

            # update external policy.
            updated_ext_policy_name = "updated-external-policy"
            updated_ext_policy_desc = "updated external policy description"
            updated_external_policy = self.gbp_obj.\
                update_external_policy(external_policy_id,
                                       name=updated_ext_policy_name,
                                       description=updated_ext_policy_desc)
            if not isinstance(updated_external_policy, dict):
                tcreason = "Failed to update external policy:"\
                    " %s" % external_policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_external_policy["name"] != updated_ext_policy_name\
                and updated_external_policy["description"] !=\
                    updated_ext_policy_desc:
                tcreason = "Failed to update external policy:"\
                    " %s" % external_policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated external policy: "
                              "%s" % external_policy_id)

            # delete external policy.
            status = self.gbp_obj.delete_external_policy(external_policy_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete external policy: %s"\
                    % external_policy_id
                LOG_OBJ.debug(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted external policy: %s"
                          % external_policy_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some problem occurred while external policy "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
            try:
                # clean external segment & external network if exist.
                status = self.__clean_external_segment(ext_segment_info)
            except:
                pass
            # update result file with test case result.
            self.__update_result_file()

    def gbp_crud_network_service_policy(self):
        """Validates api's (create, list, show, update, delete)
        of resource network service policy.
        """
        try:
            self.__set_tenant_info()
            self.tc_id = inspect.stack()[0][3]
            # initialize result dict.
            self.__set_result_dict(self.result_dict.keys(), "")

            LOG_OBJ.debug("#################################################")
            LOG_OBJ.debug("Starting Test Case : %s" % self.tc_id)
            LOG_OBJ.debug("#################################################")

            tcreason = ""

            # tenant creation.
            tenant_details = self.__create_tenant_common()
            if not isinstance(tenant_details, tuple):
                tcreason = tenant_details
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                LOG_OBJ.error(tcreason)
                return

            tenant_id = tenant_details[0]
            # update class objects with new tenant token
            self.gbp_obj.token = tenant_details[1]

            # create network service policy.
            name = "test-network-service-policy"
            network_service_params = [{"type": "ip_single", "name": "vip_ip",
                                       "value": "self_subnet"}]
            network_ser_policy_info = self.gbp_obj.\
                create_network_service_policy(
                        name, network_service_params=network_service_params)
            if not isinstance(network_ser_policy_info, dict):
                tcreason = "Failed to create network service policy."
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(self.result_dict.keys(), tcreason)
                return
            network_service_policy_id = network_ser_policy_info["id"]
            LOG_OBJ.debug("Successfully created network service policy:"
                          " %s" % network_service_policy_id)

            # show network service policy
            policy_details = self.gbp_obj.\
                show_network_service_policy(network_service_policy_id)
            if not isinstance(policy_details, dict):
                tcreason = "Failed to get details of network service "\
                    "policy: %s" % network_service_policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["show"], tcreason)
            else:
                LOG_OBJ.debug("Successfully accessed details of network "
                              "service policy: %s" % network_service_policy_id)

            # list network service policies
            policy_list = self.gbp_obj.list_network_service_policy()
            if not isinstance(policy_list, list):
                tcreason = "Failed to list network service policies of "\
                    "tenant: %s" % tenant_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["list"], tcreason)
            else:
                LOG_OBJ.debug("Successfully listed network service poli"
                              "cies of tenant: %s" % tenant_id)

            # update network service policies
            updated_name = "updated-network-service-policy"
            updated_desc = "updated network service policy description"
            updated_policy = self.gbp_obj.\
                update_network_service_policy(updated_name,
                                              network_service_policy_id,
                                              description=updated_desc)
            if not isinstance(updated_policy, dict):
                tcreason = "Failed to update network service "\
                    "policy: %s" % network_service_policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            elif updated_policy["name"] != updated_name and\
                    updated_policy["description"] != updated_desc:
                tcreason = "Failed to update network service "\
                    "policy: %s" % network_service_policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["update"], tcreason)
            else:
                LOG_OBJ.debug("Successfully updated network service "
                              "policy: %s" % network_service_policy_id)

            # delete network service policy.
            status = self.gbp_obj.\
                delete_network_service_policy(network_service_policy_id)
            if not isinstance(status, bool):
                tcreason = "Failed to delete network service policy: "\
                    "%s" % network_service_policy_id
                LOG_OBJ.error(tcreason)
                self.__set_result_dict(["delete"], tcreason)
                return
            LOG_OBJ.debug("Successfully deleted network service policy: %s"
                          % network_service_policy_id)
        except Exception as err:
            LOG_OBJ.exception(err)
            tcreason = "Some probelm occurred while network service policy "\
                "api validation."
            self.__set_result_dict(self.result_dict.keys(), tcreason)
        finally:
            # cleaning test resources.
            status = self.__resource_cleanup()
            if not isinstance(status, bool):
                tcreason = "ERROR: Some problem occurred while "\
                    "cleaning resources."
                LOG_OBJ.error(tcreason)
            self.__set_result_dict(self.result_dict.keys(), tcreason)
            # update result file with test case result.
            self.__update_result_file()
