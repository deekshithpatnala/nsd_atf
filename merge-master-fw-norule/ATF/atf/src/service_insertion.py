"""
Automation frame work.
This module contains master test-case and supported functions for
all test-cases.
"""

import copy
import time
import threading
# import sys
# sys.path.append("../../")

from atf.config import common_config
import atf.config.gbp_config as gbp_config
import atf.config.setup_config as setup_config
from atf.lib.lib_common import commonLibrary, StressTestHelper
import atf.lib.gbp_resource_create as gbp_resource_create
from atf.lib.lib_os import OpenStackLibrary
import atf.lib.nvp_atf_logging as log
from atf.lib.resource_cleanup import ResourceCleanup
from atf.lib.service_trafficgen import TrafficGenerationValidation
from atf.src.traffic_preparation import TrafficPreparation

LOG = log.get_atf_logger()


class InsertionTests():

    def __init__(self):
        self.os_host_ip = setup_config.setupInfo['os-controller-node'
                                                 ]['pubip']
        self.lib_os_obj = OpenStackLibrary(self.os_host_ip)
        self.common_lib = commonLibrary()

    def build_testcase_info(self, tc_no):
        """It builds the test case info from the test case number.
        param: tc_no: The test case no. (integer)
        Return: A dict containing the test case info.
            Ex: {'policy_rule': [{'policy_classifier': {'direction': 'IN'
                                                        'protocol': 'TCP'
                                                        'port': 103},
                                'policy_action_type': 'redirect'}],
                'shared': False,
                'vpnfw_service_image': 'vyos'/'asav'/ 'paloalto',
                'traffic_type': 'N-S',
                'vpn_type': S2S, # For N-S and with vpn
                'tc_id': 'service_insertion_project_E-W_FW_TCP_PORT_1',
                'service_chain_nodes': [{'service_type': 'FW'}],
                'service_chain': 'fw' # services appended with +
                }
        """
        try:
            tc_no = int(tc_no)
        except ValueError:
            err_msg = "Invalid test case no. %s" % tc_no
            LOG.error(err_msg)
            return err_msg
        # check tc_no should not exceed the max no. test cases
        if tc_no > gbp_config.MAX_INSERTION_TC_NO:
            err_msg = "The test case no:%s exceeds the maximum"\
                " test case no for service insertion." % tc_no
            LOG.error(err_msg)
            return err_msg
        try:
            tc_real_no = tc_no
            # As the internal implementation has test cases numbers
            # starting with 0
            # tc_no -= 1
            tc_info_dict = {}
            tc_id = ""
            lb_version = ""

            # fw without rules.
            #import pdb; pdb.set_trace()
            no_of_vpnfw_images = len(gbp_config.vpnfw_service_image)
            no_of_lb_images = len(gbp_config.lb_service_image)
            no_of_vpnfwlb_tcs = (no_of_vpnfw_images * 
                                 gbp_config.VPNFW_SERVICE_IMAGE_WT) + \
                               (no_of_lb_images * gbp_config.LB_SERVICE_IMAGE_WT)
            if tc_real_no >  no_of_vpnfwlb_tcs:
                tc_no -= ( no_of_vpnfwlb_tcs + 1 )
                fw_service_image_index = \
                    tc_no / gbp_config.FWNORULE_TYPE_WT
                if fw_service_image_index > 0:
                    tc_no %= gbp_config.FWNORULE_TYPE_WT
                tc_id += "_" + gbp_config.vpnfw_service_image[fw_service_image_index]
                tc_scope_index = tc_no / gbp_config.FWNORULE_SCOPE_WT
                if tc_scope_index > 0:
                    tc_no %= gbp_config.FWNORULE_SCOPE_WT

                #Fill the scope for testcase
                tc_info_dict['shared'] = False
                if "shared" in gbp_config.ownership_types[
                        tc_scope_index].lower():
                    tc_info_dict['shared'] = True

                traffic_type_index = tc_no % gbp_config.FWNORULE_TRAFFIC_TYPE

                # Fill the traffic type for test case.
                traffic = \
                    gbp_config.traffic_types[traffic_type_index].split("_")
                tc_info_dict['traffic_type'] = traffic[0]

                tc_id += "_" + gbp_config.traffic_types[traffic_type_index]

                # Prepare the service combination.
                service_chains = \
                    gbp_config.services[0]
                tc_id += "_" + "FW-NORULE"

                #import pdb; pdb.set_trace()
                # Prepare the classifier details.
                protocol = ""


            #############################deekshith#################################
            # If only LB in service chain
            #no_of_vpnfw_images = len(gbp_config.vpnfw_service_image)
            elif (tc_real_no > no_of_vpnfw_images * gbp_config.VPNFW_SERVICE_IMAGE_WT) and (tc_real_no < no_of_vpnfwlb_tcs ):
                tc_no -= ((no_of_vpnfw_images * gbp_config.VPNFW_SERVICE_IMAGE_WT) + 1)
                # Identify which image vendor to be used (haproxy/f5)
                lb_service_image_index = \
                    tc_no / gbp_config.LB_SERVICE_IMAGE_WT
                if lb_service_image_index > 0:
                    tc_no %= gbp_config.LB_SERVICE_IMAGE_WT
                tc_id += "_" + gbp_config.lb_service_image[lb_service_image_index]
                # Identify the version of the LB (v1/v2).
                lb_ver_index = tc_no / gbp_config.LB_VERSION_WT
                if lb_ver_index > 0:
                    tc_no %= gbp_config.LB_VERSION_WT
                lb_version = gbp_config.lb_versions[lb_ver_index]

                # Identify the scope of the project (project/shared)
                tc_scope_index = tc_no / gbp_config.LB_SCOPE_WT
                if tc_scope_index > 0:
                    tc_no %= gbp_config.LB_SCOPE_WT

                # Fill the scope of the test case.
                tc_info_dict['shared'] = False
                if "shared" in gbp_config.ownership_types[
                        tc_scope_index].lower():
                    tc_info_dict['shared'] = True

                traffic_type_index = tc_no / gbp_config.LB_TRAFFIC_TYPE_WT
                if traffic_type_index > 0:
                    tc_no %= (traffic_type_index *
                              gbp_config.LB_TRAFFIC_TYPE_WT)

                # Fill the traffic type for test case.
                traffic = \
                    gbp_config.traffic_types[traffic_type_index].split("_")
                tc_info_dict['traffic_type'] = traffic[0]

                tc_id += "_" + gbp_config.traffic_types[traffic_type_index]

                # Prepare the service combination.
                service_chains = \
                    gbp_config.services[gbp_config.LB_TRAFFIC_TYPE_WT]
                tc_id += "_" + service_chains + "(" + lb_version + ")"
                # Prepare the classifier details.
                protocol = gbp_config.protocol_lb[tc_no]
            else:
                tc_no -= 1
                # Identify which image vendor to be used (vyos/asav)
                vpnfw_service_image_index = \
                    tc_no / gbp_config.VPNFW_SERVICE_IMAGE_WT
                if vpnfw_service_image_index > 0:
                    tc_no %= gbp_config.VPNFW_SERVICE_IMAGE_WT

                # Identify the scope of the project (project/shared)
                tc_scope_index = tc_no / gbp_config.TC_SCOPE_WT
                if tc_scope_index > 0:
                    tc_no %= gbp_config.TC_SCOPE_WT

                # Prepare the service combination.
                service_chain_index = tc_no / (gbp_config.TRAFFIC_TYPE_WT * 2)
                service_chains = gbp_config.services[service_chain_index]

                traffic_type_index = tc_no / gbp_config.TRAFFIC_TYPE_WT
                if traffic_type_index > 0:
                    tc_no %= (traffic_type_index * gbp_config.TRAFFIC_TYPE_WT)

                # Fill the scope of the test case.
                tc_info_dict['shared'] = False
                if "shared" in gbp_config.ownership_types[
                        tc_scope_index].lower():
                    tc_info_dict['shared'] = True

                # Fill the VPN/FW service image type.
                tc_info_dict['vpnfw_service_image'] = gbp_config.\
                    vpnfw_service_image[vpnfw_service_image_index]
                service_images = tc_info_dict['vpnfw_service_image']

                # Fill the traffic type for test case.
                if traffic_type_index >= len(gbp_config.traffic_types):
                    traffic_type_index -= 2
                traffic = \
                    gbp_config.traffic_types[traffic_type_index].split("_")
                tc_info_dict['traffic_type'] = traffic[0]
                if len(traffic) > 1:
                    tc_info_dict['vpn_type'] = traffic[1]
                tc_id += "_" + gbp_config.traffic_types[traffic_type_index]

                # For LB case of service chains
                protocol_index = tc_no / gbp_config.SERVICE_CHAIN_WT
                if protocol_index > 0:
                    service_chains += "+" + gbp_config.services[3]
                    if tc_no >= 2 * gbp_config.SERVICE_CHAIN_WT:
                        tc_no %= gbp_config.SERVICE_CHAIN_WT
                        tc_no += gbp_config.SERVICE_CHAIN_WT    
                    else:
                        tc_no %= gbp_config.SERVICE_CHAIN_WT
           
                tc_id += "_" + service_chains
                # Prepare classifier details.
                if 'LB' in service_chains:
                    lb_image_wt = len(gbp_config.protocol_lb) * len(gbp_config.lb_versions)
                    lb_service_image_index = tc_no / lb_image_wt
                    # Fill the LB service image type.
                    tc_info_dict['lb_service_image'] = gbp_config.\
                    lb_service_image[lb_service_image_index]
                    service_images += "_" + tc_info_dict['lb_service_image']
 
                    tc_no = tc_no % lb_image_wt
                    lb_ver_wt = len(gbp_config.protocol_lb)
                    lb_ver_index = tc_no / lb_ver_wt
                    if lb_ver_index > 0:
                        tc_no %= lb_ver_wt
                    lb_version = gbp_config.lb_versions[lb_ver_index]
                    tc_id += "(" + lb_version + ")"
                    protocol = gbp_config.protocol_lb[
                        tc_no % gbp_config.SERVICE_CHAIN_WT]
                else:
                    protocol = gbp_config.protocol_types[
                        tc_no % gbp_config.SERVICE_CHAIN_WT]
                tc_id = "_" + service_images + tc_id

            #import pdb; pdb.set_trace()
            classifier = {'protocol': "", 'direction': "", 'ports': ""}
            classifier['direction'] = gbp_config.direction_types[0]
            if "NORULE" not in tc_id: 
                classifier['protocol'] = protocol.split("_")[0]

                # Right now only IN supported
                classifier['direction'] = gbp_config.direction_types[0]
                tc_id += "_" + protocol
                # Fill the port details.
                port_details = gbp_config.protocol_port_details[
                    classifier['protocol'].lower()]
                if protocol.upper() != "ICMP":
                    classifier['ports'] = port_details
                if "_PORT" in protocol:
                    classifier['ports'] = port_details.split(':')[0]

            # Filling policy rules
            tc_info_dict['policy_rules'] = [{'policy_classifier': classifier,
                                            'policy_action_type': "redirect"}]
            # Fill the services in chain
            tc_info_dict['service_chain'] = service_chains

            # Fill the service chain node
            tc_info_dict['service_chain_nodes'] = []
            for srvc in service_chains.split('+'):
                node = {'service_type': srvc}
                if srvc.upper() == "LB":
                    node.update({"version": lb_version})
                tc_info_dict['service_chain_nodes'].append(node)
            # Fill the test case id
            tc_info_dict['tc_id'] = 'service_insertion_' + \
                gbp_config.ownership_types[tc_scope_index] + tc_id +\
                "_" + str(tc_real_no)
            print tc_info_dict['tc_id']
            LOG.info("tc_info_dict : %s" % tc_info_dict)
            return tc_info_dict
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting tc details for tc no: %s" % tc_no

    def prepare_for_cleanup(self, project_info, traffic_type, **kwargs):
        """
        Wrapper function to prepare the required dictionary for the cleanup.
            params:
                project_info: {
                    'project_name': "", "project_id": "" "user_name": "",
                    "password": "", "domain_name": "","sharable": True/False
                                        # True if using shared node & spec.}
        """
        try:
            projects_detail = {'local_project_details': []}
            if not project_info.get('project_id'):
                return projects_detail
            # Fill the local project info.
            projects_detail['local_project_details'].append(project_info)

            # Check whether the remote project is created or not.
            if traffic_type.lower() == "n-s" and \
                    hasattr(self, 'gbp_resource_obj') and \
                    self.gbp_resource_obj.\
                    remote_project_info.get('project_id'):

                remote_project = self.gbp_resource_obj.remote_project_info
                remote_project['sharable'] = False
                projects_detail['local_project_details'].append(remote_project)

            return projects_detail
        except Exception as err:
            LOG.exception(err)
            return projects_detail

    def validate_member_add_and_delete(
            self, tc_info, gbp_resources, traffic_info,
            member_add_del='member_add_delete'):
        '''Wrapper function to add (and/or delete) new member in the PTGs
        and validate traffic.

        :param tc_info: Test case info dictionary.
        :param gbp_resources: The o/p of create_gbp_resources
        :param traffic_info: The i/p dict for validate traffic method.
        :param member_add_del: The flag that tells add/delete members.
                                values: member_add/member_add_delete.
        '''

        LOG.info("Adding new member in to PTG(s)")
        srvc_chain_nodes = tc_info.get('service_chain_nodes', [])
        traffic_type = tc_info['traffic_type']

        is_service_in_chain = lambda service_type: service_type.lower() in \
            [service['service_type'].lower() for service in srvc_chain_nodes]

        traffic_info_old = copy.deepcopy(traffic_info)
        ptgs_info = []
        pt_image_name = common_config.image_name
        ptg_info = gbp_resources['ptg_info']

        for ptg_type in ptg_info.keys():
            if traffic_type.lower() == "n-s" and ptg_type == "consumer":
                continue
            temp_ptg_info = {}
            temp_ptg_info['no_of_vms'] = 1
            temp_ptg_info['ptg_id'] = ptg_info[ptg_type]['ptg_details']['id']
            temp_ptg_info['ptg_name'] = \
                ptg_info[ptg_type]['ptg_details']['name']

            # For n-s with only fw case associate fip to the provider pts and
            # for E-W associate fip to consumer.
            if ptg_type == "consumer" or \
                (traffic_type.lower() == "n-s" and
                 is_service_in_chain('fw') and len(srvc_chain_nodes) == 1):
                temp_ptg_info['create_floating_ip'] = True

            ptgs_info.append(temp_ptg_info)

        # Add pts to port-target-group
        added_pt_info = self.gbp_resource_obj.add_ptg_members(pt_image_name,
                                                              ptgs_info)
        if not isinstance(added_pt_info, list):
            return added_pt_info

        # Update the traffic info dict with new member info.
        consumer_ptg_id = None
        if traffic_type.lower() != "n-s":
            consumer_ptg_id = ptg_info['consumer']['ptg_details']['id']

        provider_ptg_id = ptg_info['provider']['ptg_details']['id']

        # Update the traffic info dict with new member info.
        for pt_info in added_pt_info:
            if pt_info[0] == consumer_ptg_id:
                pts = self.traffic_prepare_obj.prepare_consumer_details(
                    pt_info[1], traffic_type)
                if not isinstance(pts, list):
                    return pts
                traffic_info['consumer_pt_details'].extend(pts)

            elif pt_info[0] == provider_ptg_id:
                pts = self.traffic_prepare_obj.prepare_provider_details(
                    pt_info[1], traffic_type, is_service_in_chain('lb'))
                if not isinstance(pts, list):
                    return pts
                traffic_info['provider_pt_details'].extend(pts)
            """
            for _pt in pt_info[1]:
                temp_resource_dict = {}
                temp_resource_dict['pt_ip'] = _pt['vm_ip']
                if temp_resource_dict.get('pt_ip'):
                    temp_resource_dict['floating_ip'] = _pt['floating_ip']
                if pt_info[0] == consumer_ptg_id:
                    traffic_info['consumer_pt_details'
                                          ].extend([temp_resource_dict])
                elif pt_info[0] == provider_ptg_id:
                    # If LB is there then add weight to new members.
                    if is_service_in_chain('lb'):
                        temp_resource_dict['weight'] = \
                            gbp_config.member_weight[0]

                    traffic_info['provider_pt_details'
                                          ].extend([temp_resource_dict])
            """
        time.sleep(5)
        status, msg = \
            self.traffic_obj.generate_validate_traffic(traffic_info)
        LOG.debug("Traffic validation after adding new member(s) into ptg(s):"
                  " Status:%s, msg: %s" % (status, msg))
        if not status:
            LOG.error(msg)
            return msg + " (after adding new members.)"

        if member_add_del != "member_add_delete":
            return True

        LOG.info("Deleting newly added member(s) from PTG's")

        for pt_info in added_pt_info:
            for _pt in pt_info[1]:
                output = self.gbp_construct_obj.delete_policy_target(_pt['id'])
                if not output:
                    err_msg = "Policy target [%s] deletion failed" % _pt['id']
                    LOG.error(err_msg)
                    return err_msg
        time.sleep(5)
        status, msg = self.traffic_obj.generate_validate_traffic(
            traffic_info_old)
        LOG.debug("Traffic validation after deletion of newly added member(s) "
                  "from ptg(s): Status:%s, msg: %s" % (status, msg))
        if not status:
            LOG.error(msg)
            return msg + " (after deleting new members)"

        return True

    def create_project_user(self, tc_info):
        """
        Creates project in a domain, Creates user and adds the user
        to domain and project.
        params:
              tc_info : dict containing the test case info.
        return: project information dictionary (dict)
               project_info : {'project_name': '',
                               'user_name': '',
                               'password': '',
                               'roles': []
                               'domain_name': '',
                               'project_id': ''
                              }
        """
        try:
            err_msg = ""

            project_info = \
                copy.deepcopy(common_config.keystonev3_project_details[0])
            # Update the project info
            thread_name = threading.currentThread().getName().lower()
            thread_name = '_' + thread_name
            if 'main' in thread_name:
                thread_name = ''

            project_info['project_name'] +=\
                str(project_info['project_no']) + thread_name
            project_info['user_name'] +=\
                str(project_info['project_no']) + thread_name
            common_config.keystonev3_project_details[0]['project_no'] += 1

            if common_config.keystone_api_version == 'v3':

                domain_name = common_config.keystonev3_domain_name
                domain_id = \
                    self.lib_os_obj.get_keystone_v3_domain_id(domain_name)
                if not isinstance(domain_id, unicode):
                    err_msg = ("Get domain id failed with reason"
                               " %s" % domain_id)
                    LOG.error(err_msg)
                    return err_msg

                project_info["domain_name"] = domain_name
                domain_role = common_config.domain_member_role_name
                # Create project and users
                project_id = self.lib_os_obj.create_keystone_v3_project_user(
                    domain_name, domain_role, project_info)
                if not isinstance(project_id, unicode):
                    return project_id
                project_info['project_id'] = project_id

                # Create the vpn user if vpn_type is "remote".
                if tc_info.get("vpn_type", "").lower() == "remote":
                    vpn_user_info = common_config.vpn_user_details.copy()
                    user_id = \
                        self.lib_os_obj.create_keystone_v3_user_and_add_roles(
                            vpn_user_info, domain_id, domain_role, project_id)
                    if not isinstance(user_id, unicode):
                        err_msg = ("Problem while creating vpn user. Reason %s"
                                   % user_id)
                        LOG.error(err_msg)
                        return err_msg

            else:
                #project_info["roles"] = common_config.\
                #        remote_project_info[0]["roles"]
                tenant_id = self.lib_os_obj.create_tenant(project_info)
                if not tenant_id:
                    err_msg = "Failed to create tenant using keystone v2 api."
                    LOG.error(err_msg)
                    return err_msg
                project_info['project_id'] = tenant_id
                # todo: Create vpn user for v2.0

            return project_info
        except Exception as err:
            LOG.exception(err)
            return "Exception occured during Creation of project and user"

    def run_insertion_testcase(self, tc_info, member_add_delete):
        """Function to run GBP test-cases.
        params:
            tc_info: test-case information dictionary (dict)
            member_add_delete: Flag to add/delete ports to existing ptg.

            Ex: tc_info for test case no. 1
                {'policy_rules': [{'policy_classifier': {'direction': 'IN'
                                                        'protocol': 'TCP'
                                                        'port': 103},
                                   'policy_action_type': 'redirect'}],
                'shared': False,
                'vpnfw_service_image': 'asav' / 'vyos' / 'paloalto'
                'traffic_type': 'N-S',
                'vpn_type': S2S, # For N-S and with vpn
                'tc_id': 'service_insertion_project_E-W_FW_TCP_PORT_1',
                'service_chain_nodes': [{'service_type': 'FW'}]}
        """
        try:
            tc_err_msg = ""
            gbp_resources_info = {}

            # TODO: Revisit (Kiran), currently service chains with paloalto
            # vpn service is not supported. When supported remove 'if' block.
            vpnfw_service_image = tc_info.get('vpnfw_service_image')
            if vpnfw_service_image and "paloalto" in\
                    vpnfw_service_image.lower()\
                    and "vpn" in tc_info["tc_id"].lower():
                tc_err_msg = "Network Service chains with PaloAlto"\
                    " VPN services is not supported."
                LOG.error("%s" % tc_err_msg)
                return

            msg = commonLibrary.get_decorated_message(
                "Starting Test case: %s" % tc_info['tc_id'], "*", 80)
            print msg
            LOG.info(msg)

            project_info = self.create_project_user(tc_info)
            if not isinstance(project_info, dict):
                tc_err_msg = project_info
                LOG.error(tc_err_msg)
                return

            # Create the GBP resources (insert service).
            self.gbp_resource_obj = \
                gbp_resource_create.GbpResourceCreator(self.lib_os_obj)
            self.gbp_construct_obj = self.gbp_resource_obj.gbp_res_obj

            gbp_resources_info = \
                self.gbp_resource_obj.create_gbp_resources(tc_info)
            if not isinstance(gbp_resources_info, dict):
                tc_err_msg = gbp_resources_info
                LOG.error(tc_err_msg)
                return
            # Prepare for traffic validation.
            self.traffic_prepare_obj = TrafficPreparation(gbp_resources_info)
            traffic_info = \
                self.traffic_prepare_obj.prepare_for_traffic_validation()
            if not isinstance(traffic_info, dict):
                tc_err_msg = traffic_info
                LOG.error(tc_err_msg)
                return
            LOG.debug("Traffic info : %s" % traffic_info)

            self.traffic_obj = TrafficGenerationValidation()
            status, msg = \
                self.traffic_obj.generate_validate_traffic(traffic_info)
            LOG.debug("Traffic generation and validation status : %s, msg:%s" %
                      (status, msg))
            if not status:
                tc_err_msg += msg
                LOG.error(tc_err_msg)
                return

            # Check whether the tc has to delete and/or add new ports in ptg.
            if member_add_delete:
                result = self.validate_member_add_and_delete(
                    tc_info, gbp_resources_info, traffic_info,
                    member_add_del=member_add_delete)
                if not isinstance(result, bool):
                    tc_err_msg += result
                    LOG.error("Traffic validation with new member add "
                              "and delete is failed with reason: %s" % result)
                    return

        except Exception as err:
            LOG.exception(err)
            tc_err_msg += " Problem occurred during test case execution."

        finally:
            try:
                LOG.info("Destroying the created resources")
                # TODO
                raw_input("Press enter to Proceed for clean up.")
                raw_input("Press enter to Proceed for clean up.")
                raw_input("Press enter to Proceed for clean up.")

                # Update the cloud admin token
                self.lib_os_obj.set_cloud_admin_info(only_token=True)

                project_info["sharable"] = tc_info['shared']
                project_details_dict = self.prepare_for_cleanup(
                    project_info, tc_info['traffic_type'])

                result = ResourceCleanup(self.lib_os_obj).clean_resources(
                    project_details_dict)
                if isinstance(result, str):
                    err_msg = "Resources cleanup is failed with reason : %s" \
                              % result
                    print err_msg
                    LOG.error(err_msg)
                    tc_err_msg += err_msg
            except Exception as err:
                LOG.exception(err)
                tc_err_msg += "Problem during clean up."

            tc_status = "PASS"
            if tc_err_msg:
                tc_status = "FAIL"
            # Updating the result.
            if 'main' not in threading.currentThread().getName().lower():
                StressTestHelper().stress_test_result_update(
                                    tc_info['tc_id'], tc_status, tc_err_msg)
            else:
                self.common_lib.test_result_update(
                                tc_info['tc_id'], tc_status, tc_err_msg)

            msg = commonLibrary.get_decorated_message(
                    "Test case completed: %s" % tc_info['tc_id'], "*", 80)
            print msg
            LOG.info(msg)

    def master_testcase(self, tc_no_string):
        """
        Wrapper function to buid test-case numbers list by a regular
        expression and call gbp_master_testcase function to execute.

        params : test-case numbers string(string)
        returns : list of test-case numbers (list)
        Eg : arguments = "1,2,4,7-11"
        """
        msg = commonLibrary.get_decorated_message(
            "Starting service insertion test cases for: %s" % tc_no_string)
        print msg
        LOG.info(msg)

        tc_no_list = commonLibrary.build_testcase_no_list(tc_no_string)
        LOG.info("tc_no_list : %s" % tc_no_list)

        member_add_del = ""  # For member add and/or delete testcases.
        for tc_no in tc_no_list:
            try:
                if tc_no in gbp_config.member_add_del_tcs.keys():
                    tc_no_mad = tc_no
                    tc_no = gbp_config.member_add_del_tcs[tc_no_mad]
                    member_add_del = "member_add_delete"
                # elif tc_no in gbp_config.port_add_tcs.keys():
                #    tc_no = gbp_config.port_add_tcs[tc_no]
                #    member_add_del = "member_add"
                # Get the test case info
                tc_info = self.build_testcase_info(int(tc_no))
                if not isinstance(tc_info, dict):
                    continue
                
                # Update the tc id, if it is member add and delete testcase.
                if member_add_del:
                    tc_info['tc_id'] = tc_info['tc_id'].replace(
                        'service_insertion', member_add_del
                        ).rpartition("_")[0] + "_" + str(tc_no_mad)
                # Execute the test case.
                self.run_insertion_testcase(tc_info, member_add_del)
                # Update the tokens of the cloud admin
                if not self.lib_os_obj.set_cloud_admin_info(only_token=True):
                    LOG.error("Problem while setting cloud admin info")
                    continue
                

            except Exception as err:
                LOG.exception(err)
