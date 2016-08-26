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
Automation frame work.
This source file contains master test-case and supported functions for
update test-cases.
"""

import atf.config.gbp_config as gbp_config
import atf.config.setup_config as setup_config
from atf.lib.lib_common import commonLibrary
import atf.lib.gbp_resource_create as gbp_resource_create
import atf.lib.nvp_atf_logging as log
from atf.lib.resource_cleanup import ResourceCleanup
from atf.lib.service_trafficgen import TrafficGenerationValidation
from atf.src.traffic_preparation import TrafficPreparation
from atf.src.service_insertion import InsertionTests

LOG = log.get_atf_logger()


class UpdateTests():

    def __init__(self):
        self.os_host_ip = setup_config.setupInfo['os-controller-node'
                                                 ]['pubip']
        self.insertion_tests = InsertionTests()
        self.lib_os_obj = self.insertion_tests.lib_os_obj
        self.common_lib = commonLibrary()

    def build_update_testcase_info(self, tc_no):
        """It builds the update test case info from the test case number.
        param: tc_no: The test case no. (integer)
        Return: A dict containing the test case info.
        """
        try:
            tc_no = int(tc_no)
        except ValueError:
            err_msg = "Invalid test case no. %s" % tc_no
            LOG.error(err_msg)
            return err_msg
        try:
            # check tc_no should not exceed the max no. test cases
            if tc_no > gbp_config.MAX_UPDATE_TC_NO:
                err_msg = "The test case no: %s exceeds the maximum"\
                    " test case no for update resource." % tc_no
                print err_msg
                LOG.error(err_msg)
                return err_msg
            tc_count = 0
            value = 0
            insertion_tc = gbp_config.update_insertion_mapping_dict[tc_no]
            for resource_type in ['node', 'spec', 'action',
                                  'rule', 'prs', 'ptg']:
                value = tc_no - int(tc_count)
                tc_count += len(gbp_config.update_resources[resource_type])
                if tc_no <= int(tc_count):
                    print tc_count, value, resource_type
                    break
            if resource_type == 'node':
                resource = \
                    gbp_config.update_resources[resource_type][value - 1]
                if resource == 'lb':
                    operation = 'update'
                elif 'vpn' in resource:
                    operation = resource.split('_')[1]
                    resource = 'vpn'
                else:
                    operation = 'add_delete'
            elif resource_type == 'spec':
                operation = \
                    gbp_config.update_resources[resource_type][value - 1]
                if operation == 'add':
                    resource = 'vpn'
                else:
                    resource = 'lb'
            elif resource_type == 'action':
                resource = 'lb'
                operation = \
                    gbp_config.update_resources[resource_type][value - 1]
            elif resource_type == 'rule':
                resource = 'fw'
                operation = \
                    gbp_config.update_resources[resource_type][value - 1]
            elif resource_type == 'prs':
                resource = \
                    gbp_config.update_resources[resource_type][value - 1]
                if resource == 'lb':
                    operation = 'add'
                elif 'allow_rule' in resource:
                    operation = resource.split('_')[2]
                    resource = 'allow_rule'
                elif 'fw' in resource:
                    operation = resource.split('_')[1]
                    resource = 'fw'
            elif resource_type == 'ptg':
                resource = \
                    gbp_config.update_resources[resource_type][value - 1]
                operation = 'add'

            tc_id = "resource_update_" + resource_type + "_" + resource +\
                    "_" + operation + "_" + str(tc_no)
            update_tc_info = {'tc_id': tc_id,
                              'insertion_tc': insertion_tc,
                              'update_resource_type': resource_type,
                              'resource': resource,
                              'operation': operation}
            print "update_tc_info : %s " % update_tc_info
            LOG.info("update_tc_info : %s " % update_tc_info)
            return update_tc_info
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting details of update " \
                "tc no: %s" % tc_no

    def run_update_testcase(self, update_tc_info):
        """
        Function to run update test-cases.
        Arguments : test-case information dictionary (dict)
        """
        tc_err_msg = ''
        insertion_tc_info = {}
        gbp_resources_info = {}
        try:
            msg = commonLibrary.get_decorated_message(
                "Starting Update Test case: %s" %
                update_tc_info['tc_id'], "*", 80)
            # Get insertion test case details
            if int(update_tc_info['insertion_tc']) != 0:
                insertion_tc_info = self.insertion_tests.build_testcase_info(
                    int(update_tc_info['insertion_tc']))
            # Create project and user
            project_info = \
                self.insertion_tests.create_project_user(insertion_tc_info)
            if not isinstance(project_info, dict):
                tc_err_msg = project_info
                LOG.error(tc_err_msg)
                return

            # nw_node_ip = setup_config.setupInfo['network-node']['mgmtip']
            # nw_node_user = setup_config.setupInfo['network-node']['username']
            # nw_node_pwd = setup_config.setupInfo['network-node']['password']
            # nw_node_ssh_obj = self.common_lib.create_ssh_object(nw_node_ip,
            #                                                    nw_node_user,
            #                                                    nw_node_pwd)
            # if nw_node_ssh_obj is None:
            #    tc_err_msg = "Creation ssh object for n/w node: %s is "\
            #        "failed" % nw_node_ip
            #    LOG.error(tc_err_msg)
            #    return

            # cleaning known_hosts file in network node
            # host_cmd = "echo '' > /root/.ssh/known_hosts"
            # result = self.common_lib.run_cmd_on_server(nw_node_ssh_obj,
            #                                           host_cmd)
            self.gbp_resource_obj = gbp_resource_create.GbpResourceCreator(
                                                            self.lib_os_obj)
            self.traffic_obj = TrafficGenerationValidation()
            self.traffic_prepare_obj = TrafficPreparation(gbp_resources_info)

            if int(update_tc_info['insertion_tc']) != 0:
                # Create the resources
                gbp_resources_info = self.gbp_resource_obj.\
                    create_gbp_resources(insertion_tc_info)

                if not isinstance(gbp_resources_info, dict):
                    tc_err_msg = gbp_resources_info
                    return
                # Update 'traffic_prepare_obj' oblect with 'gbp_resources_info'
                self.traffic_prepare_obj.set_gbp_resources_info(
                                                    gbp_resources_info)

                traffic_info = self.traffic_prepare_obj.\
                    prepare_for_traffic_validation()
                if not isinstance(traffic_info, dict):
                    tc_err_msg = traffic_info
                    LOG.error(tc_err_msg)
                    return
                # Send and Validate traffic
                status, msg = self.traffic_obj.generate_validate_traffic(
                                                            traffic_info)
                LOG.debug("Traffic generation and validation"
                          " status : %s, msg: %s" % (status, msg))
                if not status:
                    tc_err_msg = msg
                    LOG.error(tc_err_msg)
            # Call update scenario and validate updation of resource
            resource_type = update_tc_info['update_resource_type']
            self.update_resource = eval("update_tests.Update" +
                                        resource_type.title() + "(\
                                                          gbp_resources_info,\
                                                              update_tc_info,\
                                                       self.gbp_resource_obj,\
                                                            self.traffic_obj,\
                                                   self.traffic_prepare_obj)")
            update_status = eval("self.update_resource.update_" +
                                 resource_type + "()")
            if update_status[0] != True:
                tc_err_msg += '.' + update_status[1]
                return
            return
        except Exception as err:
            LOG.exception(err)
            tc_err_msg += '.' + " Problem occurred during test case execution."
        finally:
            LOG.info("Destroying the created resources")
            # st = raw_input("Enter")
            try:
                # Update the cloud admin token
                self.lib_os_obj.set_cloud_admin_info(only_token=True)
                if insertion_tc_info == {}:
                    project_info["sharable"] = False
                else:
                    project_info["sharable"] = insertion_tc_info['shared']
                # Prepare dictionary with local projects details
                project_details_dict = \
                    self.insertion_tests.prepare_for_cleanup(
                        project_info, insertion_tc_info. get("traffic_type"))

                # Fill the remote project details, if any, created
                # in update test classes
                if hasattr(self, 'update_resource')\
                    and hasattr(self.update_resource, 'remote_project_info')\
                    and self.update_resource.remote_project_info.\
                        get('project_id', False):
                    project_details_dict['local_project_details'].\
                       append(self.update_resource.remote_project_info.copy())

                # To add remote project details, created by master test.
                if hasattr(self, 'gbp_resource_obj') and hasattr(
                                            self.gbp_resource_obj,
                                            "remote_project_info"):
                    project_details_dict['local_project_details'].\
                       append(self.gbp_resource_obj.remote_project_info.copy())

                result = ResourceCleanup(self.lib_os_obj).clean_resources(
                                                      project_details_dict)
                if isinstance(result, str) or isinstance(result, unicode):
                    err_msg = " Resources cleanup is failed with reason : %s" \
                              % result
                    print err_msg
                    LOG.error(err_msg)
                    tc_err_msg += err_msg
            except Exception as err:
                LOG.exception(err)

            tc_status = "PASS"
            if tc_err_msg:
                tc_status = "FAIL"
            # Updating the result Test caes.
            self.common_lib.test_result_update(update_tc_info['tc_id'],
                                               tc_status, tc_err_msg)
            msg = commonLibrary.get_decorated_message(
                    "Update Test case completed: %s"
                    % update_tc_info['tc_id'], "*", 80)
            print msg
            LOG.info(msg)

    def update_master_testcase(self, tc_no_string):
        """
        Wrapper function to buid test-case numbers list by a regular
        expression and call run_update_testcase function to execute.

        params : test-case numbers string(string)
        Eg : arguments = "1,2,4,7-11"
        """
        msg = commonLibrary.get_decorated_message(
            "Starting update test cases : %s" % tc_no_string)
        print msg
        LOG.info(msg)

        tc_no_list = commonLibrary.build_testcase_no_list(tc_no_string)
        LOG.info("tc_no_list : %s" % tc_no_list)

        for tc_no in tc_no_list:
            try:
                update_tc_info = self.build_update_testcase_info(int(tc_no))
                if not isinstance(update_tc_info, dict):
                    continue
                # Execute the test case.
                self.run_update_testcase(update_tc_info)
                # Update the tokens of the cloud admin
                if not self.lib_os_obj.set_cloud_admin_info(only_token=True):
                    LOG.error("Problem while setting cloud admin info")
                    continue
            except Exception as err:
                LOG.exception(err)
