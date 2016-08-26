"""
Automation frame work.
This module contains master test-case and supported functions for
multiple service insertions in a tenant test-cases.
"""

import atf.config.gbp_config as gbp_config
from atf.lib.lib_common import commonLibrary
import atf.lib.gbp_resource_create as gbp_resource_create
import atf.lib.nvp_atf_logging as log
from atf.lib.resource_cleanup import ResourceCleanup
from atf.lib.service_trafficgen import TrafficGenerationValidation
from atf.src.traffic_preparation import TrafficPreparation
from atf.src.service_insertion import InsertionTests

LOG = log.get_atf_logger()


class MulInsertionTests():

    def __init__(self):
        self.common_lib = commonLibrary()
        self.func_test = InsertionTests()
        self.lib_os_obj = self.func_test.lib_os_obj 

    def run_mul_insertion_testcase(self, tc_no):
        """
        Function to run GBP test-cases.
        params:
            tc_no : Multiple insertion test-case number to execute
        """
        try:
            tc_err_msg = ""
            tc_info = {}
            tc_results = {}
            projects_details = {'local_project_details': []}
            tc_id = "multiple_Insertion_" + tc_no
            msg = commonLibrary.get_decorated_message(
                  "Starting Multiple Insertion Test case: %s" % tc_id, "*", 80)

            project_info = self.func_test.create_project_user(tc_info)
            if not isinstance(project_info, dict):
                tc_err_msg = project_info
                LOG.error(tc_err_msg)
                return

            self.gbp_resource_obj = \
                 gbp_resource_create.GbpResourceCreator(self.lib_os_obj)
            self.gbp_construct_obj = self.gbp_resource_obj.gbp_res_obj

            for tc in gbp_config.mul_insertion_tcs[tc_no]:
                gbp_resources_info = {}
                tc_info = self.func_test.build_testcase_info(int(tc))
                if not isinstance(tc_info, dict):
                    tc_err_msg += tc_info
                    continue
                msg = commonLibrary.get_decorated_message(
                      "Starting Test case: %s" % tc_info['tc_id'], "*", 80)
                print msg
                LOG.info(msg)
     
                gbp_resources_info = \
                    self.gbp_resource_obj.create_gbp_resources(tc_info)

                if tc_info['traffic_type'].lower() == "n-s" and \
                  hasattr(self, 'gbp_resource_obj') and \
                  self.gbp_resource_obj.remote_project_info.get('project_id'):

                    remote_project = self.gbp_resource_obj.remote_project_info
                    remote_project['sharable'] = False
                    projects_details['local_project_details'].append(remote_project)

                if not isinstance(gbp_resources_info, dict):
                    #tc_err_msg += gbp_resources_info
                    LOG.error(gbp_resources_info)
                    tc_results[tc_info['tc_id']] = gbp_resources_info
                    continue
                    #return
                # Prepare for traffic validation.
                self.traffic_prepare_obj = TrafficPreparation(gbp_resources_info)
                traffic_info = \
                    self.traffic_prepare_obj.prepare_for_traffic_validation()
                if not isinstance(traffic_info, dict):
                    #tc_err_msg += traffic_info
                    LOG.error(traffic_info)
                    tc_results[tc_info['tc_id']] = traffic_info
                    continue
                    #return
                LOG.debug("Traffic info : %s" % traffic_info)
     
                self.traffic_obj = TrafficGenerationValidation()
                status, msg = \
                    self.traffic_obj.generate_validate_traffic(traffic_info)
                LOG.debug("Traffic generation and validation status : %s, msg:%s" %
                          (status, msg))
                if not status:
                    #tc_err_msg += msg
                    LOG.error(msg)
                    tc_results[tc_info['tc_id']] = msg
                    #return
            return
        except Exception as err:
            LOG.exception(err)
            tc_err_msg += " Problem occured during test case execution."

        finally:
            try:
                LOG.info("Destroying the created resources")
                # TODO
                #raw_input("Press enter to Proceed for clean up.")

                # Update the cloud admin token
                self.lib_os_obj.set_cloud_admin_info(only_token=True)
                # Fill the local project info.
                if project_info.get('project_id'):
                    projects_details['local_project_details'].append(
                                                         project_info)
                result = ResourceCleanup(self.lib_os_obj).clean_resources(
                                                           projects_details)
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
            if tc_err_msg or tc_results != {}:
                tc_status = "FAIL"
                tc_results['Reason'] = tc_err_msg
            # Updating the result.
            self.common_lib.test_result_update(tc_id, tc_status, tc_results)
            msg = commonLibrary.get_decorated_message("Test case completed: %s"
                                                       % tc_id, "*", 80)
            print msg
            LOG.info(msg)

    def master_testcase(self, tc_no_string):
        """
        Wrapper function calls "run_mul_insertion_testcase" to run 
        Multiple insertion test-cases.

        params : test-case numbers string(string)
        Eg : arguments = "1,2,4,7-11"
        """

        tc_no_list = commonLibrary.build_testcase_no_list(tc_no_string)
        LOG.info("tc_no_list : %s" % tc_no_list)

        for tc_no in tc_no_list:
            try:
                # Execute the test case.
                self.run_mul_insertion_testcase(tc_no)
                # Update the tokens of the cloud admin
                if not self.lib_os_obj.set_cloud_admin_info(only_token=True):
                    LOG.error("Problem while setting cloud admin info")
                    continue

            except Exception as err:
                LOG.exception(err)
