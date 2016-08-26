"""
Sungard Automation frame work.
This module contains master test-case and other supported methods
to insert multiple chains in HA/Non-HA mode and tests the related scenarios.
This also supports single chain insertion with HA/Non-HA. It enables chain with
combination of HA and non-HA services. It also supports any scenario with
repeated no. of insertion and deletion., etc.
"""

# import sys
# sys.path.append("../../")

import copy
import threading
import time

import atf.config.gbp_config as gbp_config
import atf.lib.gbp_resource_create as gbp_resource_create
from atf.lib.lib_common import commonLibrary, StressTestHelper
import atf.lib.nvp_atf_logging as log
from atf.lib.resource_cleanup import ResourceCleanup
from atf.lib.service_trafficgen import TrafficGenerationValidation
from atf.src.service_insertion import InsertionTests
from atf.src.traffic_preparation import TrafficPreparation


LOG = log.get_atf_logger()


class MultipleChain(InsertionTests):

    """A class for inserting multiple chains with/withput ha
    and validating the scenarios
    """

    def __init__(self):
        InsertionTests.__init__(self)
        self.gbp_resource_obj = None
        self.gbp_construct_obj = None
        self.traf_prep_obj = None
        self.traffic_obj = None

    @staticmethod
    def get_services_in_chain(insertion_tc_info):
        '''It returns the services in the chain in a tuple.
        :param insertion_tc_info: Insertion test case info.

        Ex: If an insertion contains fw+lb then it returns as
            ('fw', 'lb').
        '''
        return tuple(insertion_tc_info['service_chain'].split("+"))

    @staticmethod
    def get_vm_id_statistics(mul_context):
        '''It prepares a dictionary that contains statistical info of svms
        like list of service vm ids in e-w/n-s from the multiple insertions.

        :param: mul_context: A multiple chain context object.
        :return: A dict containing the vm id stats as below.
                {'fw': {'e-w': {(act_id, standby_id), ()}, 'n-s': {(ids)}},
                'lb': {'e-w': {(act_id, standby_id), ()}, 'n-s': {(ids)}},
                'vpn': {'n-s': {(act_id, standby_id), ()}}}
                }
        '''
        try:
            # The value of each traffic type is a SET of tuples.
            # Each tuple is a pair of vm ids (act, stb).
            vm_id_stats = {'lb': {'e-w': set(), 'n-s': set()},
                           'fw': {'e-w': set(), 'n-s': set()},
                           'vpn': {'n-s': set()}}

            for traffic_type, single_chain_services in \
                    zip(mul_context['traffic_types'],
                        mul_context['service_details']):
                traffic_type = traffic_type.lower()
                for service_info in single_chain_services:
                    service_type = service_info['service_type'].lower()
                    # Add the service id (pair of ids if ha) to the set of ids.
                    vm_id_stats[service_type][traffic_type].add(
                        (service_info['vm_id'],
                         service_info.get('standby_vm_id', None)))

            LOG.debug("vm_id_stats (as collected): %s", vm_id_stats)
            # Remove all the fws that are part of a vpn
            vpn_vms = vm_id_stats['vpn']['n-s']
            if vpn_vms:
                for vpn_vm in vpn_vms:
                    if vpn_vm in vm_id_stats['fw']['e-w']:
                        vm_id_stats['fw']['e-w'].remove(vpn_vm)
                    if vpn_vm in vm_id_stats['fw']['n-s']:
                        vm_id_stats['fw']['n-s'].remove(vpn_vm)

            LOG.debug("vm_id_stats (after removing fws belonging to vpn): %s",
                      vm_id_stats)
            return vm_id_stats

        # except (KeyError, TypeError) as err:
        except (KeyError, TypeError) as err:
            LOG.exception(str(err))
            return "Problem while preparing vm id statistics."

    @staticmethod
    def validate_diff_host(mul_chain_service_details):
        """It validates whether the compute hosts for active and stand by vms
        are different or not.
        :param: mul_chain_service_details: Service details of multiple chains.

        :return True on success and error message on failure.
        """
        vm_ids = []
        try:
            for single_chain_services in mul_chain_service_details:
                for service_info in single_chain_services:
                    if not service_info.get('standby_vm_id'):
                        continue
                    if service_info['vm_id'] not in vm_ids:
                        if service_info['compute_ip'] == \
                                service_info['standby_compute_ip']:
                            err_msg = ("The Active and Standby svms of type: "
                                       "%s are launched in same compute host!"
                                       % service_info['service_type'])
                            LOG.error(err_msg)
                            return err_msg
                    else:
                        vm_ids.append(service_info['vm_id'])

            LOG.info(commonLibrary.get_decorated_message(
                "The Active and Standby SVMs are launched in different hosts"))
            return True
        except KeyError as err:
            LOG.exception("KeyError" + str(err))
            return "Problem while validating different hosts of svms."

    @staticmethod
    def validate_multi_chain_insertion(vm_id_stats, mul_context,
                                       service_vendor="vyos"):
        '''It validates the multiple chain insertion as per design spec.
        Ex: If 2 chains with fw inserted then the FW should be shared.

        1. Validates the actual no. of service vms of each type
        2. Validates the no. of new vms if interface quota of a vm exceeds.

        It follows the following rules.
        ======
        RULES:
        ======
            Default
            =======
            1. vpn: Launch a new vpn vm for every vpn in chain.
            2. lb: Launch one LB vm irrespective of traffic.
            3. fw: Launch only one fw vm for any traffic, if no vpn is there.

            Max chain exceeding case
            ======================
            For any vm, if it exceeds its max interface capacity then a new vm
            is launched.

            1. The vyos (vpn/fw) supports 10 interfaces => 4 chains.
            2. The asav (vpn/fw) supports 6 interfaces => 2 chains.
            3. The haproxy (lb) supports 10 interfaces => 9 chains.

        :param vm_id_stats: A dict as returned by get_vm_id_statistics.
        :param mul_context: Multiple chain context object.
        :param service_vendor: Fw image vendor (vyos/asav)

        :return True on success, error message on failure.
        '''
        try:
            LOG.debug(commonLibrary.get_decorated_message(
                "Validating service sharing for multiple insertions"))
            err_msg = ""
            # {svc_type: [the no. of times the service appears in e-w, n-s,
            # no. of such actual vms launched for all chains]
            svc_counts = {'lb': [0, 0, 0], 'fw': [0, 0, 0], 'vpn': [0, 0, 0]}
            # svc_vendor = service_vendor.lower()
            seq_fw_svcs = 0
            fw_vm_count = 0
            vpn_consume_fw_count = 0    # A vpn vm can consume max_sup fws.
            has_vpn_consumed = False
            # Get the total count of the vms in all chains as per defined rules
            for traffic_type, services_in_single_chain in \
                    zip(mul_context['traffic_types'],
                        mul_context['services_in_chains']):
                traffic_type = traffic_type.lower()
                index = 0 if traffic_type == "e-w" else 1
                for svc_type in services_in_single_chain:
                    svc_type = svc_type.lower()
                    svc_vendor = service_vendor.lower() \
                        if svc_type != 'lb' else "lb"
                    max_sup = gbp_config.max_chain_support[svc_vendor]
                    # Increment the no. of appearance of this svc in chains
                    svc_counts[svc_type][index] += 1
                    # svc_cnt = svc_counts[svc_type][index]

                    # Increment vm count as per default launch rules and
                    # max chain exceeding rule.
                    if svc_type == "vpn":
                        svc_counts['vpn'][2] += 1
                        vpn_consume_fw_count += max_sup
                    elif svc_type == "lb":
                        # if svc_cnt == 1 or (svc_cnt % max_sup == 1):
                        #    svc_counts[svc_type][2] += 1
                        total_lbs = svc_counts['lb'][0] + svc_counts['lb'][1]
                        if not svc_counts['lb'][2] or \
                                (total_lbs % max_sup == 1):
                            svc_counts['lb'][2] += 1
                    elif svc_type == "fw":
                        # Increment the fws that appear in continuous chains
                        # without vpn, whose total count becomes max_sup
                        seq_fw_svcs += 1
                        if not vpn_consume_fw_count:
                            # Increase the fw count if it appears continuously
                            # in the chains until the max_sup or a new fw just
                            # has come after the vpn has just consumed the
                            # previous fws with all its capacity (max_sup).
                            if seq_fw_svcs == max_sup or has_vpn_consumed:
                                fw_vm_count += 1
                                seq_fw_svcs = 0
                                has_vpn_consumed = False
                        else:
                            vpn_consume_fw_count -= seq_fw_svcs
                            if not vpn_consume_fw_count:
                                has_vpn_consumed = True
                            seq_fw_svcs = 0

            # total_fws = svc_counts['fw'][0] + svc_counts['fw'][1]
            # Update no. of fw vms, if any fw is not consumed by vpn.
            if seq_fw_svcs:
                svc_counts['fw'][2] = 1
            # Update the no. of FW service vms, if continuous fws upto max_sup
            if fw_vm_count:
                svc_counts['fw'][2] += fw_vm_count
            # No vpn but few fws are there
            # elif not svc_counts['vpn'][2] and total_fws:
            #    svc_counts['fw'][2] = 1

            LOG.debug("VM stats as per rule: %s. Actual VM stats "
                      "collected: %s", svc_counts, vm_id_stats)

            # Validate the actual vms launched is as per the rule.
            for svc_type, temp in vm_id_stats.iteritems():
                ew_vms = temp.get('e-w', set())  # Set of tuples
                ns_vms = temp['n-s']
                act_vm_cnt = len(ew_vms.union(ns_vms))
                # Continue if this service is not in any chain.
                if (svc_counts[svc_type][0] + svc_counts[svc_type][1]) == 0:
                    continue
                # Check that the no. of vms launched are as per the rule.
                if svc_counts[svc_type][2] != act_vm_cnt:
                    err_msg = ("No. of %s SVM launched is NOT as expected."
                               "Expected: %s, Launched: %s" %
                               (svc_type, svc_counts[svc_type][2], act_vm_cnt))
                    break
                # LOG.debug("Check for no. of %s SVM(s) in multiple chain"
                #          " is passed.", svc_type)

                # NOTE: There could be multiple vms in fw and lb due to RULE-2.
                # We can also check pair of active and stand by vm ids.
                if svc_type == "lb":
                    # if ns_vms - ew_vms != ns_vms:
                    #     err_msg = "For LB the N-S and E-W vms are same!"
                    #     break
                    # if len(ns_vms) and len(ew_vms):
                    #     msg = "different vms launched for all E-W and N-S"
                    # elif len(ew_vms):
                    #     msg = "one vm launched for all E-W"
                    # elif len(ns_vms):
                    #     msg = "one vm launched for all N-S"
                    # LOG.debug("For LB " + msg + " chains.")
                    LOG.debug("LB: Validaion of no.of VMs launched for chains"
                              " inserted is successful.")
                # For FW, the e-w and n-s vms, if any, should be same.
                elif svc_type == "fw":
                    # if ns_vms - ew_vms == ns_vms:
                    #    err_msg = ("For FW there are 2 different vms launched"
                    #               " in N-S and E-W.")
                    #    break
                    LOG.debug("FW: Validaion of no.of VMs launched for chains"
                              " inserted is successful.")
                # FOR VPN, a new vpn vm for every chain.
                elif svc_type == "vpn":
                    LOG.debug("VPN: Different vms launched for every chain.")

            if err_msg:
                LOG.error(err_msg)
                return err_msg

            LOG.debug(commonLibrary.get_decorated_message(
                "Validation of service sharing for multiple insertions"
                " is completed."))
            # return (True, svc_counts)
        except Exception as err:
            LOG.exception(err)
            err_msg = "Problem while validating insertion in multiple chains."

        finally:
            if err_msg:
                LOG.error(err_msg)
                return (False, err_msg)
            return (True, svc_counts)

    @staticmethod
    def validate_single_chain_deletion(mul_chain_context,
                                       svc_counts, service_vendor="vyos"):
        '''
        It validates the chain deletion. It decides whether the chain deletion
        should delete a vm(s) or not.

        NOTE: It always deletes the chain in the head of the list. It updates
        the inputs inplace. Hence changes will be reflected in original.

        :param mul_chain_context:
        :param svc_counts:
        :param service_vendor:

        # TODO: (Dilip): This is an INCOMPLETE method.
        '''
        try:
            delete_vms = [False, False, False]  # VPN, FW, LB
            # Get the single chain info.
            try:
                traffic_type = mul_chain_context['traffic_types'][0]
            except IndexError as err:
                LOG.exception(err)
                return "There is no chain available to validate chain delete."

            # Delete this traffic, as its respective chain was deleted.
            del mul_chain_context['traffic_types'][0]

            index = 0 if traffic_type.lower() == "e-w" else 1
            services_in_single_chain = \
                mul_chain_context['services_in_chains'][0]
            del mul_chain_context['services_in_chains'][0]

            for svc_type in services_in_single_chain:
                svc_type = svc_type.lower()
                svc_count = svc_counts[svc_type][index]
                # svm_count = svc_counts[svc_type][2]
                # Update the svc count in a specific traffic type.
                svc_counts[svc_type][index] -= 1
                opp_index = 0 if index else 1

                svc_vendor = "lb" if svc_type == "lb" else service_vendor
                max_sup = gbp_config.max_chain_support[svc_vendor]
                if svc_type == "lb" and (svc_count % max_sup == 1):
                    # Update the vm count.
                    svc_counts[svc_type][2] -= 1
                    delete_vms[2] = True
                # Check if fw and no vpn svc is there in any chains.
                elif svc_type == "fw" and not svc_counts['vpn'][1]:
                    if ((svc_count + svc_counts['fw'][opp_index]) %
                            max_sup == 1):
                        # Update the vm count.
                        svc_counts[svc_type][2] -= 1
                        delete_vms[1] = True
                elif svc_type == "vpn":
                    no_fw_svcs = svc_counts['fw'][0] + svc_counts['fw'][1]
                    if no_fw_svcs % max_sup == 1:
                        # Update the vm count.
                        svc_counts[svc_type][2] -= 1
                        delete_vms[0] = True

        except Exception as err:
            LOG.exception(err)
            return "Problem while validating chain deletion."

    @staticmethod
    def get_vm_info_for_failover(fail_over_vm,
                                 mul_chain_service_details):
        '''
        It returns the details of the svm on which fail-over will be tested.

        :param fail_over_vm: The name of the vm to be failed.
        :param mul_chain_service_details: A list of list where each list
            corresponds to the details of all service vms in a chain.
        :return A dict containing the vm details (active and standby).
        '''
        try:
            # NOTE: In this case we assume that the vm to be failed is actually
            # shared across multiple chains. If there are more than one such
            # vms then we have to identify which particular vm to be failed.
            # NOTE: We can use the chain no. to tell that the vm in this chain
            # will be selected to test fail-over. So, right now to resolve the
            # issue we take the vm from the chain which comes early.

            for single_chain_services in mul_chain_service_details:
                for service_detail in single_chain_services:
                    if service_detail['service_type'].lower() == \
                            fail_over_vm.lower():
                        return service_detail

            LOG.error("There is NO service found to test fail over!")
            return "There is NO service found to test fail over!"
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting fail over vms details."

    @staticmethod
    def enable_ha(ins_tc_info, services_in_ha):
        """It adds the service_ha key in the given input test case info
        dict INPLACE. If services_in_ha is empty, we assume that all services
        in HA mode else enable the services as per services_in_ha.

        :param ins_tc_info: test case info dict.
        :param services_in_ha: List of services in HA mode.
        """
        try:
            service_chain_nodes = ins_tc_info['service_chain_nodes']
            for chain_node in service_chain_nodes:
                chain_node['service_ha'] = True \
                    if ((not services_in_ha) or
                        (chain_node['service_type'].lower() in
                         services_in_ha) or (chain_node['service_type'].upper()
                                             in services_in_ha)) else False

        except Exception as err:
            LOG.exception(err)

    @staticmethod
    def delete_chains_from_context(mul_context, from_ch_no=1, to_ch_no=1,
                                   operation="del", **kwargs):
        """This basically deletes the chain details
        from_ch_no upto to_chain_no. Both no.s are inclusive.

        :param mul_context: The multiple chain context object.
        """
        try:
            for index in range(from_ch_no - 1, to_ch_no):
                LOG.debug("Removing chain:%s info from context.", index + 1)
                if operation.lower() == "del":
                    del mul_context['services_in_chains'][0]
                    del mul_context['traffic_types'][0]
                    del mul_context['service_details'][0]
                    del mul_context['traffic_info'][0]
                    del mul_context['provider_details'][0]
            return True
        except Exception as err:
            LOG.exception(err)
            return "Problem while updating context."

    def validate_vms_deletion(self, vm_id_stats):
        '''It validates whether all vms (in the input: vm_id_stats)
        got deleted or not.

        :param vm_id_stats: A dict as returned by the get_vm_id_statistics

        :return True on success, string on failure.
        '''
        try:
            vm_ids = []
            LOG.debug(commonLibrary.get_decorated_message(
                "Validating SVM deletion after all chain deletion."))
            err_msg = "The %s service vm: %s launched in %s is NOT deleted "
            for vm_type, temp in vm_id_stats.iteritems():
                for traf_type, vm_id_pairs in temp.iteritems():
                    for vm_id_pair in vm_id_pairs:
                        # vm_id_pair: (Active, Stand_by vm)
                        for index, vm_id in enumerate(vm_id_pair):
                            if vm_id is None or vm_id in vm_ids:
                                continue
                            # Check whether the vm got deleted or not.
                            _type = "ACTIVE" if not index else "STANDBY"
                            status = self.lib_os_obj.poll_on_server_to_delete(
                                vm_id, monitor_time=20)
                            if not isinstance(status, bool):
                                err_msg = err_msg % (_type, vm_type, traf_type)
                                LOG.error(err_msg)
                                return err_msg
                            vm_ids.append(vm_id)
                            LOG.debug("%s %s SVM: %s deleted successfully.",
                                      _type, vm_type, vm_id)
            return True
        except Exception as err:
            LOG.exception(err)
            return "Problem while validating vm deletion."

    def validate_traffic_for_mul_chain(self, mul_chain_traffic_info,
                                       services_in_mul_chains=None,
                                       services_in_ha=None,
                                       failover_vm="",
                                       suf_str="",
                                       action_on_vm=""):
        '''
        It validates the traffic for every chain.
        :param mul_chain_traffic_info: A list of list, where each list
                                corresponds to traffic info of a chain
                                received from prepare traffic.

        :Optional: Required when Services are in HA mode.
            :param services_in_mul_chains: A list of tuples, each tuple
                contains the services (vpn, fw, lb) of a chain.
            :param services_in_ha: A list of services in HA
            :param failover_vm: The fail over vm name (lb/fw/vpn) [for HA].
                   specialcase: For HA, to check traffic for 1st time, before
                   triggering any failover, pass the value as "NO_FAIL".
            :param suf_str: A string that will be added in LOG message.
            :param action_on_vm: Action (dtop/start) that had taken on SVM.

        :return Tuple containing the (status, message)
        '''
        try:
            traf_fail_msg = ""
            chain_index = 0
            # _failover_vm_ = failover_vm.lower()

            for chain_index, single_chain_traf_info in \
                    enumerate(mul_chain_traffic_info):
                LOG.debug(commonLibrary.get_decorated_message(
                    "Validating traffic for %s chain: %s" %
                    (suf_str, (chain_index + 1))))
                # NOTE: The traffic validation library modifies this given
                # input info, hence pass it a copy.
                single_chain_traf_info = copy.deepcopy(single_chain_traf_info)
                status, msg = self.traffic_obj.\
                    generate_validate_traffic(single_chain_traf_info)
                LOG.debug("Traffic generation and validation status: "
                          "%s, msg: %s", status, msg)
                if not status:
                    msg += " in %s chain: %s." % (suf_str, chain_index + 1)
                    traf_fail_msg += msg
                    LOG.error(msg)
                    # Continue for next chain traffic
                    continue
                    # return (False, msg, chain_index)
                # if not _failover_vm_:

                # For NO HA scenario, just continue with next chain.
                if not services_in_ha:  # and not failover_vm:
                    continue
                # if _failover_vm_ in ["fw", "vpn"]:
                #    _failover_vm_ = "fw"
                LOG.debug("Received active_standby_status: %s",
                          self.traffic_obj.active_standby_status)
                services_in_single_chain = services_in_mul_chains[chain_index]

                err_msg = ""
                for service in services_in_single_chain:
                    service = service.upper()
                    if service in ['FW', 'VPN']:
                        service = "FW"
                    traffic_status_info = \
                        self.traffic_obj.active_standby_status[service]
                    # When HA is there and no service failure then verify
                    # that all the active svms get the traffic.
                    if failover_vm == "NO_FAIL":
                        if not traffic_status_info['active']:
                            err_msg += "Observed traffic on standby svm: %s " \
                                "without any failover." % service
                    # Validate whether traffic is coming on the current-active
                    # vm after fail over. And also verify that the trafic is
                    # not coming on the stand by vms of the non-failure vms.
                    else:
                        if service == failover_vm.upper() or \
                                ((service in ["FW", "VPN"]) and
                                 (failover_vm.upper() in ["FW", "VPN"])):
                            if action_on_vm.lower() == "stop" and \
                                    not traffic_status_info['standby']:
                                err_msg += "Current Active VM: %s didn't get" \
                                    " any traffic after Active vm is failed." \
                                    % failover_vm
                        elif ((service in services_in_ha) or
                              (service.swapcase() in services_in_ha)) and \
                                traffic_status_info['standby']:
                            err_msg += "The standby %s svm is getting " \
                                "traffic after %s svm is failed." % \
                                (service, failover_vm)

                if err_msg:
                    msg = " in %s chain: %s." % (suf_str, chain_index + 1)
                    err_msg += msg
                    LOG.error(commonLibrary.get_decorated_message(err_msg))
                    traf_fail_msg += err_msg
                    continue

                LOG.debug("Traffic verified successfully on HA service vms"
                          " for chain: %s" % (chain_index + 1))

#                 # Validate traffic if any failover happened.
#                 # NOTE: For vyos, lb case, if the active vm is down for few
#                 # seconds, the standby vm has to get few packets.
#                 # But in ASAV case the Active once becomes down then the
#                 # standby will become new active and receives all traffic.
#
#                 if _failover_vm_ in ["fw", "vpn"]:
#                     _failover_vm_ = "fw"
#
#                 traffic_status_info = \
#                     self.traffic_obj.active_standby_status[failover_vm.upper()]
#
#                 msg = ("STANDBY %s didn't get any traffic"
#                        " after ACTIVE %s became down for few seconds.")
#                 err_msg = ""
#
#                 # NOTE: if non-failed vm is also in ha then also validate
#                 # its stand by vm is not getting traffic.
#                 # Also decide how to check the traffic, do we continuously
#                 # send traffic (ping) or other tcp. If tcp then at what point
#                 # the failure happened and at what point the traffic is sent.
#
#                 if _failover_vm_ == "lb":
#                     if not traffic_status_info[1]:  # Standby VM status
#                         err_msg = msg % (_failover_vm_, _failover_vm_)
#                 elif _failover_vm_ in ["fw", "vpn"]:
#                     if fw_service_vendor.lower() == "vyos" and \
#                             not traffic_status_info[1]:  # Standby VM status
#                         err_msg = msg % (failover_vm, failover_vm)
#                     elif fw_service_vendor.lower() == "asav" and \
#                             traffic_status_info[0]:  # Active VM status
#                         err_msg = "The ACTIVE asav % is still receiving "\
#                             "traffic even it is down" % failover_vm
#                 if err_msg:
#                     LOG.error(err_msg)
#                     err_msg += " in %s chain: %s."%(suf_str, chain_index + 1)
#                     traf_fail_msg += err_msg
#                     continue
#                     # return (False, err_msg, chain_index)

            return (True, "") if not traf_fail_msg else (False, traf_fail_msg)
        except Exception as err:
            LOG.exception(err)
            return (False,
                    "Problem while validating traffic for multiple chain")

    def change_svm_state(self, svm_id, vm_type, action="stop", wait_time=10):
        """ It applies fail over (changes state to SHUTOFF) to the service vm
        and also brings it up when needed.

        :param svm_id: The vm id of the servie vm.
        :param vm_type: The service vm type (fw/lb/vpn).
        :param action: Type of action to be applied (stop/reboot/start).
        :param wait_time: The no. of secs to wait after applying the action.
        """
        try:
            old_project_info = None
            LOG.debug(commonLibrary.get_decorated_message(
                "%sing the %s svm : %s" % (action, vm_type, svm_id)))
            actions = [action]

            # Change context to admin. NOTE: Better use context manager.
            admin_token = self.lib_os_obj.cloud_admin_info['token_project']
            old_project_info = self.lib_os_obj.set_tenant_info(
                self.lib_os_obj.cloud_admin_info["project_name"],
                admin_token, admin_token,
                self.lib_os_obj.cloud_admin_info['project_id'])

            # If regression is not enabled then start the vm.
            if not gbp_config.regression_ha and action.lower() == "stop":
                actions.append("start")

            for action in actions:
                # Fail over the vm.
                status = self.lib_os_obj.reboot_server(svm_id, action=action)
                if not isinstance(status, bool):
                    err_msg = ("Problem while %sing the %s svm: %s" %
                               (action, vm_type, svm_id))
                    return str(err_msg)
                req_state = "SHUTOFF" if action.lower() == "stop" else "ACTIVE"
                # Poll for REQUIRED state of SVM.
                status = self.lib_os_obj.poll_for_active_status(
                    svm_id, req_status=req_state)
                if not status:
                    err_msg = "Problem while %sing svm %s" % (action, svm_id)
                    LOG.error(err_msg)
                    return str(err_msg)
                if status.upper() != req_state:
                    err_msg = ("SVM didn't move to expected status: %s."
                               "Current status: %s" % (req_state, status))
                    LOG.error(err_msg)
                    return err_msg
                LOG.debug("The %s svm: %s is successfully %sed",
                          vm_type, svm_id, action)

                time.sleep(wait_time)

            return True
        except Exception as err:
            LOG.exception(err)
            return "Proble while failing the svm: %s" % vm_type
        finally:
            # Unset the context, if changed at all.
            if old_project_info:
                self.lib_os_obj.set_tenant_info(*old_project_info)

    def validate_traffic_and_failover(self, mul_context,
                                      fail_vm="", vm_info=None):
        '''This will do following operations.
        1. Validate the traffic on all chains.
        2. a. Do fail over (active vm), if ha is there. Shutdown it.
           b. Restart it, if regression is not enabled.
        3. Validate traffic on all chains.
        4. Start the shut down vm, if ha is there and regression is not there.
        5. Validate traffic on all chains.

        NOTE: a. When HA is there and regression is not there then we stop the
              active vm and start it back. In this case we can't know which vm
              is active now, as different image vendor behaves differently.
              So we simply validate whether traffic is coming to any of the SVM

             b. When HA is there and regression is also enabled then we stop
                the active vm and validate that traffic is coming to current
                active & then we bring back the stopped vm and validate as (a).

        :param mul_context: Multiple chain context object.
        :Optional (Required if fail-over is tested)
            :param fail_vm: The svm name (lb/fw/vpn) to be failed [for HA].
            :param vm_info: The svm info that will be failed.

        :return True on success, string on failure.
        '''

        try:
            err_msg = ""
            sequences = [""]  # if not fail_vm else ["active"]
            # IF ha is there then also fail the vms and validate the traffic.
            if fail_vm and gbp_config.regression_ha:
                # When regresion is True, after stopping the active vm, we have
                # to check traffic on current-active.
                sequences = ["stop", "start"]

            for seq in sequences:
                failover_vm = ""
                action = ""
                if seq:
                    # id_pat = "vm_id" if seq == "active" else "standby_vm_id"
                    vm_id = vm_info["vm_id"]
                    action = seq
                    wait_time = 10 if action == "stop" else 90
                    failover_vm = fail_vm  # if action == "stop" else ""
                    # Fail over the svm.
                    status = self.change_svm_state(vm_id, fail_vm,
                                                   action, wait_time)
                    if not isinstance(status, bool):
                        return status
                    LOG.debug(commonLibrary.get_decorated_message(
                        "SVM:%s %sed successfully" % (fail_vm, action)))

                msg = "(after %s vm %s)." % (fail_vm, action) if action else ""
                # Special case. For HA without any failure.
                # Basically, for 1st time validation of HA traffic.
                if not seq and mul_context['services_in_ha']:
                    failover_vm = "NO_FAIL"
                    msg = "(without service vm failover)"

                LOG.debug(commonLibrary.get_decorated_message(
                    "Validating traffic %s" % msg))

                # Validate the traffic for multiple chains.
                out = self.validate_traffic_for_mul_chain(
                    mul_context['traffic_info'],
                    mul_context['services_in_chains'],
                    services_in_ha=mul_context['services_in_ha'],
                    failover_vm=failover_vm, action_on_vm=action)
                if not out[0]:
                    err_msg += out[1] + msg
                    continue
                    # err_msg = (out[1] + msg + " Chain: %s: %s" %
                    #    ((out[2] + 1), str(services_in_mul_chains[out[2]])))
                    # return err_msg

            if not err_msg:
                LOG.debug(commonLibrary.get_decorated_message(
                    "Traffic validation is successful on all chains %s" % msg))

            return True if not err_msg else err_msg
        except Exception as err:
            LOG.exception(err)
            return "Problem while validating traffic."

    def delete_chain_validate_traffic(self, mul_chain_context, vm_id_stats,
                                      del_chains="all", del_chain_no=None,
                                      validate_traffic=True):
        '''It does the following operations.

        1. Delete the chain one by one.
        2. Validate the multi-chain after one chain is deleted.
        2. Validate the traffic in remaining chain(s).
        3. Delete the last chain and make sure that the svms get deleted.

        NOTE: This will change the above input parameters inplace.

        :param mul_chain_context: A multiple chain contect object.
        :param vm_id_stats: Statistics info returned by get_vm_id_stats.

        :Optional
            :param del_chains: How many chains to be deleted. Default is All.
                If any chain no (in str) passed then it will delete them from
                1st upto the specified chains.
            :param del_chain_no: The particular chain no. to be deleted.
                    Chain no.s start with 1

            NOTE: If both del_chain_no and del_chains passed at same time then
                del_chain_no will be prioritised.

        :return True on success, string on failure.
        '''
        try:
            err_msg = ""
            mul_chain_traffic_info_bk = \
                copy.deepcopy(mul_chain_context.get('traffic_info'))

            for chain_index, out in \
                    enumerate(zip(mul_chain_context.get('provider_details'),
                                  mul_chain_context.get('traffic_info'))):
                # Check if a particular chain is to be deleted.
                if del_chain_no:
                    if chain_index + 1 != del_chain_no:
                        continue

                # Check how many chains to be deleted.
                if del_chains.isdigit() and \
                        (int(del_chains) < chain_index + 1):
                    LOG.debug("%s no. of chains are deleted." % del_chains)
                    return True

                provider_info, single_chain_traffic_info = out
                provider_id = provider_info['ptg_details']['id']
                LOG.debug("Deleting the chain corresponding to Provider PTG"
                          " ID: %s", provider_id)

                # Delete the policy targets belonging to this provider.
                for pt_info in provider_info["policy_targets"]:
                    if not isinstance(self.gbp_construct_obj.
                                      delete_policy_target(pt_info["id"]),
                                      bool):
                        err_msg += "Problem while deleting policy target %s " \
                            "of provider: %s in chain: %s" % \
                            (pt_info['id'], provider_id, (chain_index + 1))
                        LOG.error(err_msg)
                        return ("Problem while deleting pt in provider"
                                " in chain: %s" % (chain_index + 1))
                LOG.info("\nAll PTs of provider: %s in chain: %s are deleted"
                         " fine.", provider_id, chain_index + 1)
                # Delete the provider
                if not isinstance(self.gbp_construct_obj.
                                  delete_policy_target_group(provider_id),
                                  bool):
                    err_msg += "Problem in deleting provider group: %s of " \
                               "chain %s" % (provider_id, chain_index + 1)
                    LOG.error(err_msg)
                    return str(err_msg)
                LOG.info("Provider PTG: %s in chain : %s is deleted fine.",
                         provider_id, chain_index + 1)
                LOG.debug(commonLibrary.get_decorated_message(
                    "Chain:%s is deleted successfully." % (chain_index + 1)))

                # Erase the traffic info of the deleted chain.
                mul_chain_traffic_info_bk.remove(single_chain_traffic_info)

                # Validate deletion at every chain deletion.
                # status = self.validate_single_chain_deletion(
                #    mul_chain_context, vm_id_stats, svc_counts,
                #    service_vendor)
                # if not isinstance(status, bool):
                #    return status

                # Check if this is the last chain. If yes then check that
                # the service(s) got deleted or not.
                if not mul_chain_traffic_info_bk:
                    status = self.validate_vms_deletion(vm_id_stats)
                    if not isinstance(status, bool):
                        return err_msg + " " + status + \
                                " after all chains are deleted."
                    LOG.debug(commonLibrary.get_decorated_message(
                        "All svms in all chains are deleted successfully."))
                    return True

                # Validate traffic in multiple chains.
                if validate_traffic:
                    time.sleep(2)
                    out = self.validate_traffic_for_mul_chain(
                        mul_chain_traffic_info_bk, suf_str="NEW")
                    if not out[0]:
                        msg = " after chain:%s deleted." % (chain_index + 1)
                        err_msg += out[1] + msg
                        continue
                    LOG.debug(commonLibrary.get_decorated_message(
                        "Traffic validation after chain:%s deletion is"
                        " successful." % (chain_index + 1)))

            return True if not err_msg else str(err_msg)
        except Exception as err:
            LOG.exception(err)
            return "Problem during validating traffic and deleting chain."

    def update_mul_context(self, mul_context, ins_tc_info,
                           services_in_chain, gbp_resources_info):
        """It appends the required resources in the multiple context object."""
        try:
            # Store the service types in a chain.
            mul_context['services_in_chains'].append(services_in_chain)
            # Store the traffic types of a chain.
            mul_context['traffic_types'].append(ins_tc_info['traffic_type'])

            # Prepare for traffic validation.
            self.traf_prep_obj.set_gbp_resources_info(gbp_resources_info)
            traffic_info = self.traf_prep_obj.prepare_for_traffic_validation()
            if not isinstance(traffic_info, dict):
                return str(traffic_info)
            LOG.debug("Traffic info : %s", traffic_info)

            # Store the traffic info.
            mul_context['traffic_info'].append(traffic_info)
            # Store the service details separately.
            mul_context['service_details'].append(
                traffic_info['service_details'])
            # Store the Provider details of a chain.
            provider_details = gbp_resources_info['ptg_info']['provider']
            mul_context['provider_details'].append(provider_details)

            return True
        except Exception as err:
            LOG.exception(err)
            return "Problem while preparing multiple chain context object."

    def insert_chain(self, ins_tc_info, chain_no, project_list, **kwargs):
        """This inserts a service chain based on the tc info"""
        try:
            err_msg = ""
            msg = kwargs.get("msg", "")
            services_in_chain = self.get_services_in_chain(ins_tc_info)
            no_of_members = 1
            if 'LB' in services_in_chain:
                no_of_members = 2

            gbp_resources_info = \
                self.gbp_resource_obj.create_gbp_resources(
                    ins_tc_info, no_of_provider_members=no_of_members)
            if not isinstance(gbp_resources_info, dict):
                err_msg += ("Problem while inserting %s chain:%s(%s). " %
                            (msg, chain_no, ins_tc_info['service_chain']) +
                            gbp_resources_info)
            # Check whether the remote project is there or not.
            if ins_tc_info['traffic_type'].lower() == "n-s" and \
                    self.gbp_resource_obj.\
                    remote_project_info.get('project_id'):
                project_list.append(self.gbp_resource_obj.remote_project_info)

            if err_msg:
                return (False, str(err_msg), "")

            LOG.debug(commonLibrary.get_decorated_message(
                "%s Chain:%s (%s) is inserted successfully." %
                (msg, chain_no, ins_tc_info['tc_id'])))

            return (True, gbp_resources_info, services_in_chain)
        except Exception as err:
            LOG.exception(err)
            return (False, "Problem while inserting %s chain: %s" %
                    (msg, chain_no), "")

    def insert_validate_traf_del_chain(self, mul_context, vm_id_stats,
                                       project_list, ins_tc_info,
                                       repeat_ins_del_no):
        """This basically does the following things.
        1. Insert a new chain (as per tc-info) in the existing services chain.
        2. Validate the traffic.
        3. Delete the new chain.
        4. Validate the traffic.
        5. Repeat 1-4 for a specified no. of times (say, 1).
        6. Deleet all the chains.

        :param mul_context: Multiple chain context object.
        :param project_list: project list, to append any remote project.
        :param ins_tc_info: Insertion tc info.
        :param repeat_ins_del_no: How many times the insertion and deletion
                of the chains to be repeated.

        :return A tuple. On success (True, "").
            On failure: (False, error message,
                        operation_name(insert/validate/delete))
        """
        try:
            err_msg = ""
            chain_no = len(mul_context['services_in_chains'])
            LOG.debug(commonLibrary.get_decorated_message(
                "Entering into %s no. of repeated insertion & deletion with "
                "traffic validation. Currently no. of existing chains:%s" %
                (repeat_ins_del_no, chain_no)))
            # NOTE: We expect atleast 1 chain should be inserted before this.
            if chain_no < 1:
                return "To proceed with repeated insertion & deletion we " \
                    "expect atleast 1 chain inserted before."

            chain_no += 1
            for count in range(1, repeat_ins_del_no + 1):
                # Insert a new chain as 2nd chain.
                out = self.insert_chain(ins_tc_info, chain_no,
                                        project_list, msg="NEW")
                if not out[0]:
                    return (False, out[1], "insert")
                gbp_resources_info = out[1]
                services_in_chain = out[2]
                # update context with the new chain.
                status = self.update_mul_context(
                    mul_context, ins_tc_info,
                    services_in_chain, gbp_resources_info)
                if not isinstance(status, bool):
                    return (False, str(status))
                # Validate traffic. Do a plain traffic validation,
                # irrespective of HA/Non-HA
                out = self.validate_traffic_for_mul_chain(
                    mul_context['traffic_info'])
                if not out[0]:
                    err_msg += out[1] + " after inserting chain: %s at " \
                        "repeation no.%s of %s," % \
                        (chain_no, count, repeat_ins_del_no)
                    # continue
                # Delete the 2nd chain and validate traffic.
                status = self.delete_chain_validate_traffic(
                    mul_context, vm_id_stats, del_chain_no=chain_no)
                if not isinstance(status, bool):
                    err_msg += str(status) + " after deleting chain: %s at " \
                        "repeation no.%s of %s," % \
                        (chain_no, count, repeat_ins_del_no)

            # NOW delete all chain and validate deletion
            status = self.delete_chain_validate_traffic(
                    mul_context, vm_id_stats, validate_traffic=False)
            if not isinstance(status, bool):
                err_msg += str(status)

            if err_msg:
                return (False, err_msg)

            return (True, "")
        except Exception as err:
            LOG.exception(err)
            return (False, "Problem while inserting and deleting chain "
                    "multiple times.")

    def run_multiple_chain_testcase(self, mul_chain_tc_info):
        """
        This will run testcase corresponding to multiple chains
        with/without ha.
        For every multiple chain scenarios it tests the followings.

        1. Insert the multiple chains with ha enabled, if any, as per
            the scenarios specified by the user.
        2.i Validate the multiple chain insertion. [As per design spec]
        2.ii Validate the traffic in multiple chains.
        3. Do a failover on the vm, if any, as specified by user.
            [Takes care of Asav and vyos case]
        4. Validate traffic on all chains after failover.
        5. Do a failover on the current active vm.
        6. Validate traffic on all chains after failover.
        7. Delete chain one by one and validate traffic.
        8. Ensure that there remains no service vm after all chains deleted.

        params:
            mul_chain_tc_info: test-case information dictionary (dict)
                                for multiple chain scenarios.
            NOTE: For plain multiple chain with out ha, the flag failover_vm
                    will not be there.
            Ex: mul_chain_tc_info for test case no. 1
                {tc_id: "multiple_chain_insertion_ha_1",
                service_chains: [11, 11], failover_vm: lb}
        """
        try:
            tc_err_msg = ""
            gbp_resources_info = {}

            msg = commonLibrary.get_decorated_message(
                "Starting Test case: %s" % mul_chain_tc_info['tc_id'], "*", 80)
            print msg
            LOG.info(msg)
            LOG.debug("Multiple Insertion Scenario: :%s", mul_chain_tc_info)

            # NOTE: It would be better to store the project from config.
            project_list = []
            # Create user and Project.
            project_info = self.create_project_user(mul_chain_tc_info)
            if not isinstance(project_info, dict):
                tc_err_msg = project_info
                # LOG.error(tc_err_msg)
                return

            # Store the project details for clean up.
            project_list.append(project_info)

            # Instantiate the GBP Resource Creator.
            self.gbp_resource_obj = \
                gbp_resource_create.GbpResourceCreator(self.lib_os_obj)
            self.gbp_construct_obj = self.gbp_resource_obj.gbp_res_obj
            # Instantiate the Traffic preparation
            self.traf_prep_obj = TrafficPreparation({})

            fw_service_vendor = ""
            failover_vms = mul_chain_tc_info.get('failover_vms')
            services_in_ha = mul_chain_tc_info.get('services_in_ha', [])
            repeat_ins_del_no = mul_chain_tc_info.get('repeat', 0)

            # NOTE: mul_context: A multiple chain context object.
            # services_in_ha: A list of services in HA
            # failover_vms: A list of services upon which failover to be tested
            # services_in_chains: A list of tuples. A tuple contains the
            #        services (vpn, fw, etc) in a particular chain.
            # traffic_types: A list containing the traffic types (E-W/N-S)
            #        in all chains.
            # service_details: A list of list. Each inner list contains the
            #        services details (dict) in a chain.
            # traffic_info: A list of list. Each inner list contains the
            #        traffic info for a chain. A traffic info is a dict used
            #        for validating traffic in a chain.
            # provider_details: A list of dicts. Each dict contains a provider
            #         ptg details and its members of a service chain.

            # Define a single multiple chain context.
            mul_context = {'services_in_ha': services_in_ha,
                           'failover_vms': failover_vms,
                           'services_in_chains': [],
                           'traffic_types': [],
                           'service_details': [],
                           'traffic_info': [],
                           'provider_details': []
                           }

            first_ins_tc_info = None
            # Insert the multiple chains.
            for chain_index, ins_tc_no in enumerate(
                    mul_chain_tc_info['service_chains']):
                # Get the details of the insertion test case no.
                ins_tc_info = self.build_testcase_info(ins_tc_no)
                if not isinstance(ins_tc_info, dict):
                    tc_err_msg = ("Problem while getting details of "
                                  "insertion tc no: %s", ins_tc_no)
                    return

                # Get the fw service vendor. Hybrid type is not allowed.
                service_vendor = ins_tc_info['vpnfw_service_image']
                if not fw_service_vendor:
                    fw_service_vendor = service_vendor
                elif fw_service_vendor != service_vendor:
                    tc_err_msg = "HYBRID service vendor is NOT allowed!"
                    return
                # Does this test case belong to shared one?
                if ins_tc_info['shared']:
                    project_info['sharable'] = True

                # Enable HA to the specified services, if failover_vms=True
                if services_in_ha or failover_vms:
                    # If services_in_ha is empty, we assume all in ha mode.
                    # if not services_in_ha:
                    #    services_in_ha = list(services_in_chain)
                    self.enable_ha(ins_tc_info, services_in_ha)

                # Insert the service chain.
                out = self.insert_chain(
                    ins_tc_info, chain_index + 1, project_list)
                if not out[0]:
                    tc_err_msg += str(out[1])
                    return
                (status, gbp_resources_info, services_in_chain) = out

                # Save the first insertion info.
                if not first_ins_tc_info:
                    first_ins_tc_info = ins_tc_info

                # Give some breathing time to APIC, b4 proceeding 4 next chain!
                time.sleep(5)
                status = self.update_mul_context(
                    mul_context, ins_tc_info,
                    services_in_chain, gbp_resources_info)
                if not isinstance(status, bool):
                    tc_err_msg += str(status)
                    return

            # If HA is there, and user has not specified any services_in_ha
            # then this means all services in all insertion are in HA mode.
            if failover_vms and not services_in_ha:
                for svcs_in_chain in mul_context['services_in_chains']:
                    services_in_ha.extend(list(svcs_in_chain))
                mul_context['services_in_ha'] = list(set(services_in_ha))

            LOG.debug("mul_context: %s", mul_context)
            # Prepare service vm id statistics.
            vm_id_stats = self.get_vm_id_statistics(mul_context)
            if not isinstance(vm_id_stats, dict):
                tc_err_msg += str(vm_id_stats)
                return

            # If HA, validate the service vms launched in 2 diff. computes.
            if mul_context['services_in_ha']:
                status = self.validate_diff_host(
                    mul_context['service_details'])
                if not isinstance(status, bool):
                    tc_err_msg += str(status)
                    # return

            # Validate the multiple chain insertion
            out = self.validate_multi_chain_insertion(
                vm_id_stats, mul_context, service_vendor)
            if not out[0]:
                tc_err_msg += str(out[1])
                return

            # Instantiate the traffic generation and validation.
            self.traffic_obj = TrafficGenerationValidation()

            fail_vms = [""]
            # If ha is there then also validate traffic after each failover.
            if failover_vms:
                fail_vms.extend(failover_vms)

            for fail_vm in fail_vms:
                vm_info = None
                if fail_vm:
                    # Update the cloud admin token, as multichain traffic
                    # validation for HA may take more time in some scenarios.
                    self.lib_os_obj.set_cloud_admin_info(only_token=True)

                    # Get the vm details (active and standby) on whom
                    # fail-over will be experimented.
                    # _fail_vm = mul_chain_tc_info['failover_vm']
                    # Check the svm to be failed is in ha mode.
                    if not ((fail_vm.lower() in services_in_chain) or
                            (fail_vm.upper() in services_in_chain)):
                        tc_err_msg += "Failover can't be tested on NON-HA " \
                            "SVM: %s. Check the scenario." % fail_vm
                        return
                    vm_info = self.get_vm_info_for_failover(
                        fail_vm, mul_context['service_details'])
                    if not isinstance(vm_info, dict):
                        tc_err_msg += str(vm_info)
                        return

                LOG.debug(commonLibrary.get_decorated_message(
                    "Validating traffic on all service chains."))
                # Validating traffic on all service chains and testing failures
                status = self.validate_traffic_and_failover(
                    mul_context, fail_vm, vm_info)
                if not isinstance(status, bool):
                    tc_err_msg += str(status)
                    # return

            # NOTE: We will reinsert the 1st chain after deleting all
            # chains but the last
            del_chains = "all"
            if repeat_ins_del_no:
                del_chains = len(mul_context['services_in_chains'])
                if del_chains > 1:
                    del_chains -= 1

            # Validate the chain deletion in multiple chains.
            LOG.debug(commonLibrary.get_decorated_message(
                "Validating traffic after deleting %s chains one by one." %
                str(del_chains)))
            status = self.delete_chain_validate_traffic(
                mul_context, vm_id_stats, del_chains=str(del_chains))
            if not isinstance(status, bool):
                tc_err_msg += str(status)
                return

            # Repeat: Insert chain, validate traffic, delete chain.
            if repeat_ins_del_no:
                # Update the cloud admin token.
                self.lib_os_obj.set_cloud_admin_info(only_token=True)

                # Update the context object by deleting those chain details
                # which were deleted previously.
                status = self.delete_chains_from_context(
                    mul_context, to_ch_no=del_chains)
                if not isinstance(status, bool):
                    tc_err_msg += status
                    return
                # Insert, validate, delete chains
                out = self.insert_validate_traf_del_chain(
                    mul_context, vm_id_stats, project_list,
                    first_ins_tc_info, repeat_ins_del_no)
                if not out[0]:
                    tc_err_msg += out[1]
                    if len(out) == 3 and out[2].lower() == "insert":
                        return

            msg = commonLibrary.get_decorated_message(
                "Testcase %s execution is done successfully." %
                mul_chain_tc_info['tc_id'])
            print msg
            LOG.debug(msg)

        except Exception as err:
            LOG.exception(err)
            tc_err_msg += " Problem occurred during multiple chain execution."

        finally:
            try:
                LOG.info("Destroying the created resources")
                raw_input("Press enter to Proceed for clean up.")
                tc_err_msg = str(tc_err_msg)
                # Update the cloud admin token
                self.lib_os_obj.set_cloud_admin_info(only_token=True)

                result = ResourceCleanup(self.lib_os_obj).clean_resources(
                    {"local_project_details": project_list})
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
                LOG.error(tc_err_msg)

            # Updating the result.
            if "main" not in threading.currentThread().getName().lower():
                StressTestHelper().stress_test_result_update(
                        mul_chain_tc_info["tc_id"], tc_status, tc_err_msg)
            else:
                self.common_lib.test_result_update(mul_chain_tc_info['tc_id'],
                                                   tc_status, tc_err_msg)
            msg = commonLibrary.get_decorated_message(
                "Test case completed: %s" % mul_chain_tc_info['tc_id'])
            print msg
            LOG.info(msg)

    def multiple_chain_master(self, tc_no_string):
        """This is the master function that executes multiple chain
        insertion scenarios. It reads the scenario details from the config.

        params : test-case numbers string(string)
        Eg : arguments = "1,2,4,7-11"
        """
        msg = commonLibrary.get_decorated_message(
            "Starting multiple chain with/out HA insertion test cases for:%s" %
            tc_no_string)
        print msg
        LOG.info(msg)

        mul_chain_tc_list = commonLibrary.build_testcase_no_list(tc_no_string)
        LOG.info("mul_chain_tc_list : %s", mul_chain_tc_list)

        for mul_chain_tc_no in mul_chain_tc_list:
            try:
                mul_chain_tc_no = int(mul_chain_tc_no)
                # Check if it falls under multiple service chain insertion
                # with HA test range or not.
                if mul_chain_tc_no not in gbp_config.multiple_chain_tcs.keys():
                    LOG.error(commonLibrary.get_decorated_message(
                        "The test case no.: %s doesn't fall in multiple chain"
                        "insertion with HA test case range" % mul_chain_tc_no))
                    continue
                # Get the corresponding test case info by the tc no.
                tc_info = gbp_config.multiple_chain_tcs[mul_chain_tc_no]
                tc_info['tc_id'] = "Multiple_Insertion_" + tc_info['id'] + \
                    "_" + str(mul_chain_tc_no)
                # Execute the test case.
                self.run_multiple_chain_testcase(tc_info)
                # Update the tokens of the cloud admin
                if not self.lib_os_obj.set_cloud_admin_info(only_token=True):
                    LOG.error("Problem while setting cloud admin info")
                    continue

            except Exception as err:
                LOG.exception(err)
