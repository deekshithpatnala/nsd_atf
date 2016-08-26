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
This modules contains class & methods for validating network services HA
functionality.

  Services HA Tests Tree Structure:-

    ====================================================================
    =          Services_HA (48)                                        =
    ====================================================================
        /                                      \          \            \
     Vyos_EW(6)                              Vyos_NS(18) ASAV_EW (6)   ASAV_NS (18)
     =======                                ========     =======       ========
      |                                        |
       -> FW(HA) --> Failover_FW                -> FW(HA) --> Failover_FW
      |                                        |
       -> FW(HA)+LB --> Failover_FW             -> FW(HA)+LB --> Failover_FW
      |                                        |
       -> FW+LB(HA) --> Failover_LB             -> FW+LB(HA) --> Failover_LB
      |                                        |
       -> FW(HA)+LB(HA) ---> Failover_FW        -> FW(HA)+LB(HA) --> Failover_FW
                         |                     |                  |
                          -> Failover_LB       |                   -> Failover_LB
                         |                     |                  |
                          -> Failover_All      |                   -> Failover_All
                                               |
                                                -> REMOTE_VPN(HA)+FW(HA) ---> FailOver_VPN
                                               |
                                                -> REMOTE_VPN(HA)+FW(HA)+LB(HA) ---> FailOver_VPN
                                               |                                 |
                                               |                                  --> FailOver_LB
                                               |                                 |
                                               |                                  --> FailOver_All
                                               |
                                                -> REMOTE_VPN(HA)+FW(HA)+LB --> Failover_VPN
                                               |
                                                -> REMOTE_VPN+FW+LB(HA) --> Failover_LB
                                               |
                                                 -> S2S_VPN(HA)+FW(HA) ---> FailOver_VPN
                                               |
                                                -> S2S_VPN(HA)+FW(HA)+LB(HA) ---> FailOver_VPN
                                               |                                 |
                                               |                                  --> FailOver_LB
                                               |                                 |
                                               |                                  --> FailOver_All
                                               |
                                                -> S2S_VPN(HA)+FW(HA)+LB --> Failover_VPN
                                               |
                                                -> S2S_VPN+FW+LB(HA) --> Failover_LB
"""


import copy
import time
import threading

import atf.lib.nvp_atf_logging as log
import atf.config.gbp_config as gbp_config
import atf.config.common_config as common_config
from atf.lib.lib_common import StressTestHelper
from atf.lib.gbp_resource_create import GbpResourceCreator
from atf.lib.service_trafficgen import TrafficGenerationValidation
from atf.src.traffic_preparation import TrafficPreparation
from atf.lib.resource_cleanup import ResourceCleanup
from atf.src.service_insertion import InsertionTests

LOGOBJ = log.get_atf_logger()


class ServicesHATest(InsertionTests):
    """
    Class contains methods for running tests for services
    High Availability (HA) functionality.
    """
    def __init__(self):
        """
        instance variables:

            1. tcno2tcid_mapping: contains test case number to
                test case id mapping as well as contains extra
                information like list of services where fail
                over will be applied and list of services which
                will be launched in HA.

                e.g.

                 self.tcno2tcid_mapping = {
                     1: {
                         "tc_id": "Services_HA_VYOS_EW_FW_FailOver_FW_1",
                         "base_tc_no": 1, "fail_over": [fw, LB],
                         'services_ha': ['FW', 'LB']
                         }
                    2: {
                        "tc_id": "Services_HA_VYOS_EW_FW+LB_FailOver_FW_2",
                        "base_tc_no": 11, "fail_over": [fw],
                        'services_ha': ['FW']
                        },
                        {}, {}, .....
                    }
        """
        self.tcno2tcid_mapping = {}
        InsertionTests.__init__(self)

    def build_tcno2tcid_mapping(self):
        """
            Method builds test number to test case id mappings and
            also gathers extra information like list of services where fail
            over will be applied and list of services which
            will be launched in HA. And update tcno2tcid_mapping
            instance variable.
        """
        try:
            test = "Services_HA_"
            base_strings = ["VYOS_EW_", "VYOS_NS_", "ASAV_EW_", "ASAV_NS_"]
            chains = ["FW", "FW+LB", "REMOTE_VPN+FW", "REMOTE_VPN+FW+LB",
                      "S2S_VPN+FW", "S2S_VPN+FW+LB"
                      ]
            tc_no = 0
            for bstr in base_strings:
                for chain in chains:
                    if "_EW" in bstr and "VPN" in chain:
                        continue
                    services = []
                    if "VPN" in chain:
                        services.append("VPN")
                    if "FW" in chain:
                        services.append("FW")
                    if "LB" in chain:
                        services.append("LB")
                    # if vpn & fw services are in chain,
                    # they shares same service vm.
                    if "VPN" in chain and "FW" in chain:
                        services.remove("FW")

                    # base test no. for service chain insertion.
                    base_tc = gbp_config.services_ha_base_test_mapping[
                                                bstr.lower() + chain.lower()]

                    # To generate combination of test, where some of the
                    # services in chain will in HA mode & some will be in
                    # standalone mode and failover will be applied on service
                    # vm of service launched in ha mode.
                    if len(services) > 1:
                        for service_vm in services:
                            services_ha = []
                            tc_no += 1
                            chain_string = chain.replace(
                                        service_vm, service_vm + '(HA)')
                            services_ha.append(service_vm)
                            if service_vm == "VPN":
                                chain_string = chain_string.\
                                    replace("FW", "FW(HA)")
                                services_ha.append('FW')

                            tc_id = test + bstr + chain_string + "_FailOver_"\
                                + service_vm + "_" + str(tc_no)
                            self.tcno2tcid_mapping[tc_no] = {
                                                 "tc_id": tc_id,
                                                 "base_tc_no": base_tc,
                                                 "fail_over": [service_vm],
                                                 "services_ha": services_ha
                                                }

                    # To generate combination of test, where all the
                    # services in chain will in HA mode. And Failover
                    # will be applied on one service vm only.
                    for service_vm in services:
                        tc_no += 1
                        chain_string = '+'.join(map(lambda service: service +
                                                    '(HA)', chain.split('+')))
                        tc_id = test + bstr + chain_string + "_FailOver_" +\
                            service_vm + "_" + str(tc_no)
                        services_ha = copy.deepcopy(services)
                        if 'VPN' in services:
                            services_ha.append('FW')

                        self.tcno2tcid_mapping[tc_no] = {
                                             "tc_id": tc_id,
                                             "base_tc_no": base_tc,
                                             "fail_over": [service_vm],
                                             "services_ha": services_ha}
                    else:
                        # tests where all services in chain will be
                        # launched in HA mode and failover will be applied on
                        # all active service vms of chain one after another.
                        # and data path traffic will be verified.
                        if len(services) > 1:
                            services_ha = copy.deepcopy(services)
                            tc_no += 1
                            chain_string = '+'.join(map(
                                            lambda service: service +
                                            '(HA)', chain.split('+')))
                            tc_id = test + bstr + chain_string +\
                                "_FailOver_All_" + str(tc_no)
                            if 'VPN' in services:
                                services_ha.append('FW')
                            self.tcno2tcid_mapping[tc_no] = {
                                                 "tc_id": tc_id,
                                                 "base_tc_no": base_tc,
                                                 "fail_over": services,
                                                 "services_ha": services_ha}

        except Exception as err:
            LOGOBJ.exception(err)
            return "ATFError: Exception occurred while building test "\
                "cases numbers to test cases id mapping."

    def get_active_service_vm_id(self, service_type):
        """
            Arguments:
                service_type: FW or VPN or LB.
            Returns:
                On Success: (True, active svm id)
                on Failure: (False, string containing error message)
        """
        try:
            if service_type.lower() not in ["fw", "vpn", "lb"]:
                err = "Couldn't find active instance id for "\
                    "service: %s" % service_type
                LOGOBJ.error(err)
                return (False, err)

            services = self.traffic_dict["service_details"]
            for service in services:
                if service["service_type"].lower() == service_type.lower():
                    active_svm_id = service["vm_id"]
                    LOGOBJ.debug("Active service instance is for %s service"
                                 " is: %s" % (service_type, active_svm_id))
                    return (True, active_svm_id)

            err = "ATFError: Couldn't find active instance id for "\
                "service: %s" % service_type
            LOGOBJ.error(err)
            return (False, err)
        except Exception as err:
            LOGOBJ.exception(err)
            err = "ATFError: Exception occurred while getting active service"\
                " instance id for %s service."
            return (False, err)

    def swap_active_standby_svm_info(self, service_type):
        """
        It will swap active svm details with standby service details in
        dictionary prepared for traffic validation.
        """
        try:
            if not hasattr(self, 'traffic_dict'):
                err_msg = "ATFError: Class instance do not have attribute"\
                    " 'traffic_dict'."
                LOGOBJ.error(err_msg)
                return err_msg

            for service in self.traffic_dict["service_details"]:
                if service["service_type"].lower() == service_type.lower():
                    break

            standby_compute_ip = service["standby_compute_ip"]
            active_compute_ip = service["compute_ip"]
            active_vm_ip = service["service_vm_ip"]
            standby_vm_ip = service["standby_service_vm_ip"]
            active_port_id = service["port_id"]
            standby_port_id = service["standby_port_id"]
            active_vm_id = service["vm_id"]
            standby_vm_id = service["standby_vm_id"]

            service["port_id"] = standby_port_id
            service["standby_port_id"] = active_port_id
            service["compute_ip"] = standby_compute_ip
            service["standby_compute_ip"] = active_compute_ip
            service["service_vm_ip"] = standby_vm_ip
            service["standby_service_vm_ip"] = active_vm_ip
            service["vm_id"] = standby_vm_id
            service["standby_vm_id"] = active_vm_id

            LOGOBJ.debug("Traffic dictionary after swapping active-standby"
                         " service vm details: %s" % self.traffic_dict)
        except Exception as err:
            LOGOBJ.exception(err)
            return "ATFError: Exception occurred while switching context"\
                " of active service instance details with standby service"\
                " instance details in traffic dictionary, for traffic "\
                "validation after fail over on service vm."

    def get_test_details(self, tc_no):
        """
        Argument:
            tc_no: Services HA test case number.

        Returns: On success: test case details dictionary.

         Ex: {'policy_rule': [{'policy_classifier': {'direction': 'IN'
                                                        'protocol': 'TCP'
                                                        'port': 103},
                                'policy_action_type': 'redirect'}],
                'shared': False,
                'vpnfw_service_image': 'vyos'/'asav',
                'traffic_type': 'N-S',
                'fail_over': [FW, LB, ]
                'vpn_type': S2S, # For N-S and with vpn
                'tc_id': 'Services_HA_VYOS_EW_FW+LB_FailOver_FW_2',
                'service_chain_nodes': [{'service_type': 'FW',
                                       "service_ha": True}]}

            On failure: string containing error message.
        """
        try:
            if tc_no not in self.tcno2tcid_mapping.keys():
                err_msg = "Invalid service HA test case number: %s" % tc_no
                LOGOBJ.warn(err_msg)
                return err_msg

            base_tc_no = self.tcno2tcid_mapping[tc_no]["base_tc_no"]
            tc_id = self.tcno2tcid_mapping[tc_no]["tc_id"]
            # list of services on which faiover will be applied.
            fail_over = self.tcno2tcid_mapping[tc_no]["fail_over"]
            # Services which will launched in HA mode.
            services_ha = self.tcno2tcid_mapping[tc_no]["services_ha"]

            test_info = self.build_testcase_info(base_tc_no)
            if type(test_info) is str:
                return test_info

            test_info["tc_id"] = tc_id
            # Enabling launching service vm in HA mode.

            for node in test_info["service_chain_nodes"]:
                if node["service_type"].upper() in services_ha:
                    node["service_ha"] = True
            test_info["fail_over"] = fail_over
            return test_info
        except Exception as err:
            LOGOBJ.exception(err)
            return "ATFError: Exception occurred while building "\
                "test case details."

    def master_test(self, test_info):
        """
        Services HA master test case. It will do base service chain
        insertion & perform traffic validation through service chain.
        Apply fail over on active service instances & validates that
        functionality is affecting or not by performing traffic validation.
        And Updates test result in result file of result directory of
        automation framework.

        Arguments:
            test_info: dictionary containing test case details for service
                chain insertion.
            EX.
                {
                    'policy_rule': [{'policy_classifier': {'direction': 'IN'
                                                            'protocol': 'TCP'
                                                            'port': 103},
                                    'policy_action_type': 'redirect'
                                    }
                                ],
                    'shared': False,
                    'service_ha': True/False
                    'fail_over': [FW, LB, ..]
                    'vpnfw_service_image': 'vyos'/'asav',
                    'traffic_type': 'N-S',
                    'vpn_type': S2S, # For N-S and with vpn
                    'tc_id': 'Services_HA_VYOS_EW_FW+LB_FailOver_FW_2',
                    'service_chain_nodes': [{'service_type': 'FW',
                                'service_ha': True}]
                }
        """
        try:
            err_msg = ""
            project_info = {}
            if type(test_info) is not dict:
                LOGOBJ.error("ATFError: Argument test_info must be "
                             "dictionary. Got %s." % type(test_info))
                return "ATFError: Argument test_info must be dictionary."\
                    " Got %s." % type(test_info)

            # create test project & users.
            project_info = self.create_project_user(test_info)
            if not isinstance(project_info, dict):
                err_msg += str(project_info)
                return str(project_info)

            # create gbp resources.
            self.gbp_resource_obj = GbpResourceCreator(self.lib_os_obj)
            gbp_resource_info = self.gbp_resource_obj.\
                create_gbp_resources(test_info)
            if isinstance(gbp_resource_info, str):
                err_msg += gbp_resource_info
                return gbp_resource_info
            self.gbp_resources_info = gbp_resource_info.copy()

            # prepare for traffic validation.
            traffic_prepare_obj = TrafficPreparation(self.gbp_resources_info)
            self.traffic_dict = traffic_prepare_obj.\
                prepare_for_traffic_validation()
            if isinstance(self.traffic_dict, str):
                err_msg += self.traffic_dict
                return self.traffic_dict

            # Traffic generation & validation.
            # Before applying fail over on active service instance.
            traffic_obj = TrafficGenerationValidation()
            traffic_dict = copy.deepcopy(self.traffic_dict)
            status, msg = traffic_obj.generate_validate_traffic(
                                                    traffic_dict)
            if not status:
                err_msg += msg
                return msg
            LOGOBJ.debug("Traffic validation status: %s"
                         % traffic_obj.active_standby_status)
            # Validate if traffic went through standby service vm.
            if True in [traffic_obj.active_standby_status[service]['standby']
                        for service in traffic_obj.active_standby_status]:
                err = "Traffic seen through standby service vm, before "\
                    "applying failover on active service vms."
                LOGOBJ.error(err)
                err_msg += err
                return err

            # apply fail over active service vm.
            # And validate traffic.
            for service in test_info["fail_over"]:
                # get active service instance id.
                status, active_svm_id = self.get_active_service_vm_id(service)
                if not status:
                    err_msg += active_svm_id
                    return err_msg

                failover_type = 'stop-start'
                if gbp_config.regression_ha:
                    failover_type = 'stop'

                status = self.apply_fail_over_on_service_vm(
                                                active_svm_id,
                                                failover_type=failover_type)
                if type(status) is str or type(status) is unicode:
                    err_msg += status
                    return status
                # Swap active & standby service details in traffic
                # dictionary, after triggering fail over on initial active
                # service instance.
                status = self.swap_active_standby_svm_info(service.lower())
                if type(status) is str or type(status) is unicode:
                    err_msg += str(status)
                    return str(status)

                # if regression flag True, validate traffic
                # after stopping active service instance.
                if gbp_config.regression_ha:
                    traffic_dict = copy.deepcopy(self.traffic_dict)
                    status, msg = traffic_obj.generate_validate_traffic(
                                                            traffic_dict)
                    if not status:
                        msg = "Traffic through chain of service vms failed, "\
                            "after applying fail over on active service vm:"\
                            " %s of %s service." % (active_svm_id,
                                                    service.lower())
                        err_msg += msg
                        return msg

                    LOGOBJ.debug("Traffic validation status: %s"
                                 % traffic_obj.active_standby_status)
                    # Traffic should go through standby (i.e. new active)
                    # service vm.
                    service_key = 'FW' if service == 'VPN' else service
                    if traffic_obj.active_standby_status[
                                service_key.upper()]['active'] is not True:
                        err = "Traffic not seen through active service vm,"\
                            " after moving on %s initial active service "\
                            "instance into shutoff state." % service.lower()
                        LOGOBJ.error(err)
                        err_msg += err
                        return err

                    # start suspended service instance.
                    LOGOBJ.info("Starting suspended service instance: %s"
                                % active_svm_id)
                    print "Starting suspended service instance: %s"\
                        % active_svm_id
                    status = self.apply_fail_helper(
                                    active_svm_id, action='start',
                                    poll_for='ACTIVE')
                    if not isinstance(status, bool):
                        return status
                    print "Sleeping for 80 seconds after starting suspended "\
                        "service instance: %s" % active_svm_id
                    time.sleep(80)
                    # revert back switched context, irrespective of
                    # service image.
                    status = self.swap_active_standby_svm_info(service.lower())
                    if type(status) is str or type(status) is unicode:
                        err_msg += str(status)
                        return str(status)

                # validate traffic after fail over.
                traffic_dict = copy.deepcopy(self.traffic_dict)
                status, msg = traffic_obj.generate_validate_traffic(
                                                        traffic_dict)
                if not status:
                    msg = "Traffic through chain of service vms failed, "\
                        "after applying fail over on active service vm:"\
                        " %s of %s service." % (active_svm_id,
                                                service.lower())
                    err_msg += msg
                    return msg

                LOGOBJ.debug("Traffic validation status: %s"
                             % traffic_obj.active_standby_status)
            return True
        except Exception as err:
            LOGOBJ.exception(err)
            err_msg += "ATFError: Exception occurred in master test case."
            return "ATFError: Exception occurred in master test case."
        finally:
            # raw_input("Press ENTER to process with test execution:")
            # Start resource cleanup.
            tc_status = "PASS"
            resource_cleanup_obj = ResourceCleanup(self.lib_os_obj)
            resource_cleanup_info = self.prepare_for_cleanup(
                                    project_info, test_info["traffic_type"])
            status = resource_cleanup_obj.clean_resources(
                                                resource_cleanup_info)
            if type(status) is str:
                err_msg += status

            if err_msg:
                tc_status = "FAIL"
            # update test result.
            if "main" not in threading.currentThread().getName().lower():
                StressTestHelper().stress_test_result_update(
                                    test_info['tc_id'], tc_status, err_msg)
            else:
                self.common_lib.test_result_update(
                                    test_info["tc_id"], tc_status, err_msg)
            print "*" * 35 + " Test Case Completed " + "*" * 35
            LOGOBJ.debug("*" * 35 + " Test Case Completed " + "*" * 35)

    def apply_fail_helper(self, service_vm_id,
                          action='stop', poll_for='SHUTOFF'):
        """
        Helper function. It will stop or start service vm
        depending upon action optional argument.

        Arguments:
            1. service_vm_id: service vm id which will suspended or started.
            2. action: (stop/start).
                        if 'stop' ==> will shutoff service vm.
                        if 'start' ==> will start service vm from
                                    shutoff state.
            3. poll_for: (SHUTOFF/ACTIVE).

        Returns: True on success.
            String containing error message on failure.
        """
        try:
            old_project_info = None
            # set cloud admin tokens
            self.lib_os_obj.set_cloud_admin_info(only_token=True)
            # switch context to cloud admin project.
            old_project_info = self.lib_os_obj.set_tenant_info(
                            common_config.cloud_admin_project,
                            self.lib_os_obj.cloud_admin_info["token_domain"],
                            self.lib_os_obj.cloud_admin_info["token_project"],
                            self.lib_os_obj.cloud_admin_info["project_id"]
                            )
            if type(old_project_info) != tuple:
                err_msg = "Changing project context in lib_os_obj object "\
                    "failed."
                LOGOBJ.error(err_msg)
                return err_msg

            status = self.lib_os_obj.reboot_server(service_vm_id,
                                                   action=action)
            if not isinstance(status, bool):
                err_msg = "Failed to %s service instance: %s"\
                    % (action, service_vm_id)
                LOGOBJ.error(err_msg)
                return str(err_msg)

            # poll for service instance state.
            try:
                status = self.lib_os_obj.poll_for_active_status(
                                    service_vm_id, req_status=poll_for)
                if status.upper() != poll_for:
                    err_msg = "Service instance %s didn't went into %s state."\
                        % (service_vm_id, poll_for)
                    LOGOBJ.error(err_msg)
                    return str(err_msg)
            except Exception as err:
                LOGOBJ.exception(err)
                return "ATFError: Some problem in method: "\
                    "poll_for_active_status."
            return True
        except Exception as err:
            LOGOBJ.exception(err)
            return "ATFError: Exception occurred while applying fail over."
        finally:
            # revert back switched project context.
            if old_project_info:
                self.lib_os_obj.set_tenant_info(*old_project_info)

    def apply_fail_over_on_service_vm(self, service_vm_id,
                                      failover_type='stop-start'):
        """
        This method will used to apply fail over on active service
        vms by simply vm reboot or power off & on.

        Argument:
            service_vm_id: id of active service instance.
            failover_type: (stop-start/stop).
                           if 'stop' ==> will shut off the service vm.
                           if 'stop-start' ==> will shut off
                                           & restart service vm.

        Returns: On Success: True.
            On Failure: String containing error message.
        """
        try:
            # Apply fail over on active service instance.
            LOGOBJ.debug("Suspending active service"
                         " instance with id: %s" % service_vm_id)
            status = self.apply_fail_helper(service_vm_id, action='stop',
                                            poll_for='SHUTOFF')
            if not isinstance(status, bool):
                return status
            # sleeping for 10 seconds after suspending active service instance.
            LOGOBJ.info("Sleeping for 10 seconds after suspending active"
                        " service instance.")
            print "sleeping for 10 seconds after suspending "\
                "active service instance."
            time.sleep(10)
            if failover_type == 'stop':
                LOGOBJ.debug("Failover on service vm %s successful"
                             "." % service_vm_id)
                return True

            # start suspended service vm again.
            LOGOBJ.debug("Restarting suspended service"
                         " instance with id: %s" % service_vm_id)
            status = self.apply_fail_helper(service_vm_id, action='start',
                                            poll_for='ACTIVE')
            if not isinstance(status, bool):
                return status

            LOGOBJ.debug("Failover on service vm %s successful"
                         "." % service_vm_id)

            # sleeping for 80 seconds after applying failover.
            LOGOBJ.info("Sleeping for 80 seconds after applying failover.")
            print "sleeping for 80 seconds after applying failover."
            time.sleep(80)

            return True
        except Exception as err:
            LOGOBJ.exception(err)
            return "ATFError: Exception occurred in apply_fail_over_"\
                "on_service_vm method of %s class." % self.__class__.__name__

    def services_ha_master_test(self, tc_no_string):
        """
        Wrapper above master test method. Builds services HA test
        details to be executed  and passes to the master test method
        for execution.

        Arguments: tc_no_string
                e.g.  "1,2,4,7-11"
        """
        try:
            # build service ha tc no to tc id mapping.
            status = self.build_tcno2tcid_mapping()
            if type(status) is str:
                return status
            # convert test cases no string to test cases no list.
            test_no_list = self.common_lib.build_testcase_no_list(tc_no_string)
            print "Services HA Test Cases To Be executed: %s" % test_no_list
            LOGOBJ.debug("Services HA Test Cases To Be executed:"
                         " %s" % test_no_list)
            # execute services HA test cases.
            for tc in test_no_list:
                test_info = self.get_test_details(int(tc))
                if type(test_info) is str:
                    return test_info
                msg = "Started Executing Services HA Test:"\
                    " %s" % test_info.get("tc_id")
                msg = self.common_lib.get_decorated_message(msg, '@', 70)
                print msg
                LOGOBJ.debug(msg)
                self.master_test(test_info)
        except Exception as err:
            LOGOBJ.exception(err)
            return "ATFError: Exception occurred services ha"\
                " master test case."
