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

########################################################################
#    Project: NFP ATF                                                  #
#    ATF Revision: 2.0                                                 #
#    Team/Authors:                                                     #
#            Sireesha Mandav [sireesha.mandava@oneconvergence.com]     #
#            Kiran Zarekar [kiran.zarekar@oneconvergence.com]          #
#            Surendar Bobala [Surendar.Bobbala@oneconvergence.com]     #
#            Deekshith Patnala [deekshith.patnala@oneconvergence.com]  #
#            Dilip Kumar Nayak [dilip.nayak@oneconvergence.com]        #
########################################################################

"""This is the starting point of running the automation test scripts
for SunGard scenario.
"""


import datetime
import sys
import os

sys.path.append("../")
import atf.config.common_config as config
from atf.config import setup_config
from atf.config import gbp_config
from atf.lib.lib_common import commonLibrary
from atf.lib.lib_os import OpenStackLibrary
from atf.lib.resource_cleanup import ResourceCleanup
from atf.lib.gbp_constructs import gbp_construct
import atf.lib.nvp_atf_logging as log
from atf.src.service_insertion import InsertionTests
from atf.src.gbp_cruds import GbpCrudsValidation
from atf.src.resource_update import UpdateTests
from atf.src.multiple_insertion import MulInsertionTests
from atf.src.service_ha import ServicesHATest
from atf.src.multiple_chain import MultipleChain
from atf.src.stress import StressTests

LOG_OBJ = log.get_atf_logger()
PWD = os.path.dirname(os.path.abspath(__file__))


def create_result_file():
    """Proc to create result.csv file. This file will contain the
    test-case id and the status of its execution (PASS/FAIL) and reason of
    failure, if any.
    """
    LOG_OBJ.debug("Creating Result File ...")
    now = str(datetime.datetime.now().strftime('%Y%b%d_%Hh%Mm%Ss')).strip()
    try:
        result_dir = str(PWD) + "/results"
        if not os.path.exists(result_dir):
            os.system("mkdir -p " + result_dir)

        file_name = result_dir + "/result_" + now + ".csv"
        with open(file_name, 'w') as result_file:
            to_write = "TCID, Status, Failure Reason"
            result_file.write(to_write)
            result_file.write('\n')
            print "Result File created : ", file_name
            LOG_OBJ.debug("Result File created : %s" % file_name)

        return file_name
    except Exception as msg:
        LOG_OBJ.exception(msg)


def append_results(file_name, total_count, pass_count, fail_count):
    """Proc to append total count, fail count, pass count of
    test case execution in result file (file_name)
    """
    msg = "TCS:\n Total executed : %s \n passed : %s \n failed : %s"\
          % (total_count, pass_count, fail_count)
    print msg
    LOG_OBJ.info(msg)
    try:
        #print "Appending the result to Result file", file_name
        LOG_OBJ.debug("\nAppending the result to Result file:%s" % file_name)

        with open(file_name, 'a') as result_file:
            out = '\n' + 'Total testcases : ' + str(total_count) + '\n' + \
                'Testcases passed : ' + str(pass_count) + '\n' + \
                'Testcases failed : ' + str(fail_count) + '\n'
            result_file.write(out)

        print "\n\nResult File : %s \n" % file_name
        LOG_OBJ.info("\n\nResult File : %s" % file_name)
    except Exception as msg:
        LOG_OBJ.exception(msg)


def set_log_level(log_level):
    """It sets the log level in the logger object"""
    if log_level in ["debug", "DEBUG"]:  # Default log level is DEBUG
        return

    levels = ["notset", "info", "warn", "warning", "error", "critical",
              "NOTSET", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"]
    if log_level not in levels:
        print "Invalid log level:%s given. Use any one of: %s" % (log_level,
                                                                  levels)
        LOG_OBJ.error("Invalid log level:%s given. Use any one of: %s" %
                      (log_level, levels))
        return

    # Set the log level.
    LOG_OBJ.setLevel(log_level.upper())


def change_log_file(file_name):
    """It changes the log file for log messages.
    Note: Default nature is to use only one file for all
        the features/test-cases
    """
    if config.log_mode_for_feature not in ["one", "ONE"]:
        # Change the log file.
        log.set_log_file(file_name)


def create_domain():
    """It creates the domain for the test case."""
    lib_os_obj = OpenStackLibrary(setup_config.setupInfo[
                                                "os-controller-node"]['pubip'])

    # Check whether the domain is already created or not.
    if isinstance(lib_os_obj.get_keystone_v3_domain_id(
                                config.keystonev3_domain_name), unicode):
        return True
    # Create the domain.
    if not isinstance(lib_os_obj.create_keystone_v3_domain(
                            name=config.keystonev3_domain_name), unicode):
        err_msg = "Problem while creating the domain: %s"\
                    % config.keystonev3_domain_name
        print err_msg
        LOG_OBJ.error(err_msg)
        return False
    return True


def create_ext_segment():
    """Creates external segment if not created."""

    try:
        old_project_info = None
        lib_os_obj = OpenStackLibrary(setup_config.setupInfo[
                                        "os-controller-node"]['pubip'])

        old_project_info = lib_os_obj.set_tenant_info(
                                config.cloud_admin_project,
                                lib_os_obj.cloud_admin_info["token_domain"],
                                lib_os_obj.cloud_admin_info["token_project"],
                                lib_os_obj.cloud_admin_info["project_id"]
                                )
        if type(old_project_info) != tuple:
            err_msg = "Changing project context in libos object "\
                "failed."
            LOG_OBJ.error(err_msg)
            return False

        gbp_res_obj = gbp_construct(
                        lib_os_obj.cloud_admin_info["token_project"],
                        lib_os_obj.host_ip)

        if gbp_res_obj.list_external_segments() == []:

            net_details = lib_os_obj.get_net_details(
                                config.extnet_name)
            if not isinstance(net_details, dict):
                err_msg = "Problem while getting details of ext-net"
                LOG_OBJ.error(err_msg)
                return False
            print net_details
            subnet_details = lib_os_obj.get_subnet_details(
                                subnet_id=net_details["subnets"][0])
            if not isinstance(subnet_details, dict):
                err_msg = "Problem while getting details"\
                    " of subnet:%s" % net_details["subnets"][0]
                LOG_OBJ.error(err_msg)
                return False
            print subnet_details
            ext_net_cidr = subnet_details['cidr']
            kwargs = {"ip_version": 4,
                      "cidr": ext_net_cidr,
                      "shared": True,
                      "subnet_id": subnet_details['id']
                      }

            ext_segment_info = gbp_res_obj.create_external_segment(
                                            config.ext_segment_name, **kwargs)
            if not isinstance(ext_segment_info, dict):
                err_msg = "Failed to create external segment."
                print err_msg
                LOG_OBJ.error(err_msg)
                return False
        else:
            print "External segment is already created"
            LOG_OBJ.info("External segment is already created")
        return True
    except Exception as err:
        LOG_OBJ.exception(err)
        return False
    finally:
        pass
        # if old_project_info:
        #    lib_os_obj.set_tenant_info(*old_project_info)


def post_automation_cleanup():
    """Runs cleanup scripts post automation completion"""
    try:
        message = "Started Post Automation cleanup"
        dec_msg = commonLibrary.get_decorated_message(message, "@", 70)
        LOG_OBJ.debug("%s" % dec_msg)
        lib_os_obj = OpenStackLibrary(setup_config.setupInfo[
                                            "os-controller-node"]['pubip'])
        status = lib_os_obj.set_cloud_admin_info(only_token=True)
        LOG_OBJ.info("Status: %s" % status)
        # create resource cleanup object.
        resource_cleanup = ResourceCleanup(lib_os_obj)

        # end_project_no = commonLibrary.total_count
        resource_cleanup.master_local_project_resource_cleanup()
        resource_cleanup.master_remote_tenant_resource_cleanup()
    except Exception as err:
        LOG_OBJ.exception(err)


def run_test(test_cases_file):
    """Execute the test-cases present in the test_cases_file.

    test_cases_file: It is a test case file that contains the test-cases
    in a specified format. Ex: testABCD(1), where the testABCD is the feature
    name and the 1 is the test-case id.
    """
    try:
        now = str(datetime.datetime.now().strftime('%Y%b%d_%Hh%Mm%Ss')).strip()
        msg = commonLibrary.get_decorated_message("\nStarting automation"
                                                  " at: %s\n" % now)
        print msg
        LOG_OBJ.debug(msg)

        # Create domain if keystone api version is v3
        if config.keystone_api_version == "v3":
            if not create_domain():
                return

        if not create_ext_segment():
            return

        with open(test_cases_file, 'r') as tc_desc:
            # Get those test-cases that need to be executed.
            testcases = [testcase.strip() for testcase in tc_desc.readlines()
                         if not testcase.startswith('#')]
            LOG_OBJ.debug("Test-cases to be executed are : %s" % testcases)

            for testcase in testcases:
                if len(testcase) == 0:
                    continue
                testcase = testcase.replace(" ", "")
                tc_nos_string = testcase[testcase.index('(') + 1: -1]
                msg = commonLibrary.get_decorated_message(
                                "\nExecuting test cases for: %s\n" % testcase)
                print msg
                LOG_OBJ.debug(msg)
                # Change the log file name for each one, if required.
                change_log_file(testcase)

                # Call the master test case to handle the test-cases.
                if "gbp_cruds" in testcase.lower():
                    GbpCrudsValidation().gbp_crud_master_testcase(
                                                        tc_nos_string)
                elif "service_insertion" in testcase.lower():
                    InsertionTests().master_testcase(tc_nos_string)
                elif "resource_update" in testcase.lower():
                    UpdateTests().update_master_testcase(tc_nos_string)
                elif "multiple_insertion" in testcase.lower():
                    MulInsertionTests().master_testcase(tc_nos_string)
                elif "services_ha" in testcase.lower():
                    ServicesHATest().services_ha_master_test(tc_nos_string)
                elif "multiple_chain" in testcase.lower():
                    MultipleChain().multiple_chain_master(tc_nos_string)
                elif "stress_test" in testcase.lower():
                    StressTests().stress_master(tc_nos_string)
                    try:
                        # generate log file per thread.
                        thread_count = gbp_config.threads
                        log_dir_path = config.atf_log_path
                        thread_name_pre = gbp_config.thread_name
                        log_file_abs_path = log.get_log_file_abs_path()
                        log_file = log_file_abs_path.split('/')[
                                                -1].split('.')[0]
                        for th_no in range(thread_count):
                            thread_name = thread_name_pre + str(th_no)
                            cmd = 'grep "\[%s\]" %s > %s'\
                                % (thread_name, log_file_abs_path,
                                   log_dir_path + log_file + "_" +
                                   thread_name + ".log")
                            os.system(cmd)
                    except Exception as err:
                        LOG_OBJ.error(err)

        now = str(datetime.datetime.now().strftime('%Y%b%d_%Hh%Mm%Ss')).strip()
        msg = commonLibrary.get_decorated_message(
            "\nExecution of all test cases is done.\n\nTESTING "
            "COMPLETED AT : %s\n" % now)
        print msg
        LOG_OBJ.debug(msg)

    except Exception as msg:
        LOG_OBJ.exception(msg)


if __name__ == "__main__":
    # Set the log level, if other than DEBUG.
    set_log_level(config.log_level)

    TEST_CASES_FILE = "test_cases.txt"

    # Create the result file.
    RESULT_FILE_NAME = create_result_file()
    # Run the test-cases.
    run_test(TEST_CASES_FILE)

    # post automation cleanup.
    post_automation_cleanup()

    # Append the final results in the result file.
    append_results(RESULT_FILE_NAME, commonLibrary.total_count,
                   commonLibrary.pass_count,
                   commonLibrary.fail_count)
