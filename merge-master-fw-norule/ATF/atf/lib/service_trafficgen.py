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
# This is to generate diff file
"""
Library to generate and validate the traffic
"""
import sys
import traceback
import time
sys.path.append("../../")
from atf.lib.lib_common import commonLibrary
import atf.config.gbp_config as gbp_config
import atf.config.common_config as common_config
import atf.config.setup_config as setup_config
from atf.lib.trafficgen import Traffic
import atf.lib.nvp_atf_logging as logObj

commonLib = commonLibrary()


#class traffic_generation_validation():
class TrafficGenerationValidation():
    """class having methods to generate and validate traffic"""
    def __init__(self):
        self.log_obj = logObj.get_atf_logger()
        self.traffic_obj = Traffic()
        self.obj_computes = {}
        self.obj_consumers = {}
        self.dump_file_list = []
        # active_standby_status is dictionary provides info about
        # service vms (fw/lb) are active/standby.
        self.active_standby_status = {"FW": {"active": False,
                                             "standby": False},
                                      "LB": {"active": False,
                                             "standby": False},
                                      "VPN": {"active": False,
                                              "standby": False}}

    def generate_validate_traffic(self, traffic_info):
        """
        Generates traffic from consumers to providers, Captures traffic on
        service vms and provider vms and validates the traffic
        Arguments:
            traffic_info: Dictionary contains all the services
                                   information
        Return value: Tuple
            On success: (True, "")
            On failure: (False, "error message")
        """
        vip_ip = ""
        vip_details = {}
        generate_result = ""
        num_conns = 1
        weight = 0
        times = 2

        try:
            self.log_obj.info("traffic_info: %s" % traffic_info)
            print "traffic_info: %s" % traffic_info
            # Filling "obj_computes" dictionary with compute ssh objects
            for compute in setup_config.setupInfo["compute-node"]:
                ssh_obj_compute = commonLib.create_ssh_object(
                                                            compute["mgmtip"],
                                                          compute["username"],
                                                          compute["password"])
                if ssh_obj_compute is None:
                    err_msg = "Creation of ssh object for compute-node: %s "\
                                 "is failed" % compute["mgmtip"]
                    self.log_obj.error(err_msg)
                    return (False, err_msg)
                self.obj_computes[compute["mgmtip"]] = ssh_obj_compute

            provider_pt_details = traffic_info['provider_pt_details']
            for service in traffic_info['service_details']:
                if service['service_type'].lower() == "lb":
                    vip_details = service['vip_details']
                    if vip_details.get('floating_ip', '') != '':
                        vip_ip = vip_details['floating_ip']
                    else:
                        vip_ip = vip_details['pt_ip']
                    for provider_port in provider_pt_details:
                        weight += int(provider_port['weight'])
                    num_conns = weight * times
                    provider_pt_details = [traffic_info[
                                                  'provider_pt_details'][0]]
                    break
            # Create ssh objects to consumers to login
            for consumer_port in traffic_info['consumer_pt_details']:
                print "\nconsumer_port: %s \n" % consumer_port
                ssh_obj_consumer = commonLib.create_ssh_object(
                                         consumer_port['floating_ip'],
                                             common_config.image_user,
                                             common_config.image_pass)
                if ssh_obj_consumer is None:
                    err_msg = "Unable to reach floating ip of consumer"
                    self.log_obj.error(err_msg)
                    return (False, err_msg)
                self.obj_consumers[consumer_port['floating_ip']] = \
                                                              ssh_obj_consumer
            positive_traffic = []
            # loop for number of classifiers
            for classifier in traffic_info['classifiers']:
                self.log_obj.info("\nclassifier : %s \n" % classifier)
                print "\nclassifier : %s \n" % classifier
                #traffic = classifier['protocol'].lower()
                if not classifier.get('protocol'):
                    traffic = classifier.get('protocol')
                else:
                    traffic = classifier.get('protocol').lower()

                positive_traffic.append(traffic)
                # To generalize the code for ports, adding value to the
                # ports list in case of Icmp protocol
                #if classifier['protocol'].lower() == "icmp":
                if traffic == "icmp":
                    ports = ['NA']
                # If range of ports
                elif not classifier.get('protocol'):
                    ports = ['NA']
                elif ":" in classifier.get('port'):
                    ports = classifier.get('port').split(":")
                    ports = [str(port) for port in range(int(ports[0]),
                                                         int(ports[1])+1)]
                else:
                    ports = [classifier.get('port')]
                self.log_obj.info("\nports: %s \n" % ports)
                print "\nports: %s \n" % ports
                # Loop for port range for classifier
                for port in ports:
                    self.log_obj.info("\nport: %s \n" % port)
                    print "\nport: %s \n" % port
                    # Loop for number for consumers to send traffic
                    for consumer_port in traffic_info[
                                              'consumer_pt_details']:
                        self.log_obj.info("\nconsumer_port: %s \n" %
                                                      consumer_port)
                        print "\nconsumer_port: %s \n" % consumer_port
                        # Loop for number of providers to send traffic
                        for provider_port in provider_pt_details:
                            self.log_obj.info("\nprovider_port: %s \n" %
                                          provider_port)
                            print "\nprovider_port: %s \n" % provider_port
                            result = self.send_traffic(traffic_info,
                                                       traffic,
                                                       consumer_port,
                                                       provider_port,
                                                       num_conns,
                                                       positive_traffic,
                                                       vip_ip,
                                                       vip_details, port)
                            if result is not None:
                                generate_result += result

            if common_config.regression is True:
                traffic_list = ['icmp', 'http', 'https', 'dns', 'smtp', 'ftp',
                                'tcp', 'udp']
                neg_traffic = list(set.difference(set(traffic_list),
                                                  set(positive_traffic)))
            else:
                traffic_list = ['tcp', 'udp', 'icmp']
                neg_traffic = list(set.difference(set(traffic_list),
                                                  set(positive_traffic)))
            self.log_obj.info("negative traffic ------- %s" % neg_traffic)
            print "negative traffic ------- %s" % neg_traffic
            num_conns = 1
            # Loop for number for consumers to send negative traffic
            for consumer_port in traffic_info['consumer_pt_details']:
                self.log_obj.info("\nconsumer_port: %s \n" % consumer_port)
                print "\nconsumer_port: %s \n" % consumer_port
                # Loop for number of providers to send traffic
                for provider_port in provider_pt_details:
                    self.log_obj.info("\nprovider_port: %s \n" % provider_port)
                    print "\nprovider_port: %s \n" % provider_port
                    for traffic in neg_traffic:
                        result = self.send_traffic(traffic_info,
                                                   traffic,
                                                   consumer_port,
                                                   provider_port, num_conns,
                                                   positive_traffic, vip_ip,
                                                   vip_details)
                        if result is not None:
                            generate_result += result
            self.log_obj.info("generate_result ..... %s" % generate_result)
            print "generate_result ..... %s" % generate_result
            if generate_result != "":
                return (False, generate_result)
            return (True, "")
        except Exception as err:
            err_msg = "Exception occurred in generate_validate_traffic:"\
                " %s, error: %s" % (traceback.format_exc(), err)
            self.log_obj.error(err_msg)
            print err_msg
            return (False, "ERROR: Exception occurred in validate_traffic")

    def send_traffic(self, traffic_info, traffic, consumer_port,
                     provider_port, num_conns, positive_traffic,
                     vip_ip, vip_details, port=''):
        """
        It calls 'capture_traffic' method to caputure the traffic on tap
        interface of the service vm
        Intiates the traffic from consumer to provider
        Calls 'validate_traffic' method to validate the captured traffic
        """
        try:
            err_msg = ""
            traffic_fail = ""
            if port == '':
                port = gbp_config.protocol_port_details[traffic].split(':')[0]
            self.log_obj.info("\n sending traffic : %s \n" % traffic)
            print "\n sending traffic : %s \n" % traffic
            consumer_ip = consumer_port['pt_ip']
            provider_ip = provider_port['pt_ip']
            # For FW N-S case
            if provider_port.get('floating_ip', '') != '':
                consumer_ip = consumer_port['floating_ip']
                provider_ip = provider_port['floating_ip']
            # if LB is in chain
            if vip_ip:
                provider_ip = vip_ip
                # Capture on all members
                provider_details = traffic_info['provider_pt_details']
            else:
                # Capture on particular provider where sending traffic
                provider_details = [provider_port]
            # For FW+LB N-S case
            if vip_details.get('floating_ip', '') != '':
                consumer_ip = consumer_port['floating_ip']
            # Capture traffic
            if common_config.nfp_model == 'advanced':
                service_details = traffic_info['service_details']
            else: # For base model no need to capture on service vms
                service_details = None
            result = self.capture_traffic(service_details, provider_details)
            time.sleep(10)
            if type(result) == str:
                err_msg = "Capture traffic failed with "\
                                   "reason: %s " % result
                print err_msg
                self.log_obj.error(err_msg)
                return err_msg
            self.log_obj.info("Starting traffic from %s to %s " %
                          (consumer_ip, provider_ip))
            print "Starting traffic from %s to %s " % \
                (consumer_ip, provider_ip)
            # If LB, sending TCP traffic using curl
            if vip_ip and traffic == 'tcp' and traffic in positive_traffic:
                result = self.traffic_obj.send_traffic_curl(
                             self.obj_consumers[consumer_port['floating_ip']],
                                    consumer_ip, provider_ip, port, num_conns)
            elif traffic == 'tcp' or traffic == 'udp':
                result = eval("self.traffic_obj.send_traffic_" + traffic +
                         "(self.obj_consumers[consumer_port['floating_ip']],\
                                            consumer_ip, provider_ip, port)")
            elif traffic in ['http', 'https', 'dns', 'smtp', 'ftp']:
                result = eval("self.traffic_obj.send_traffic_" + traffic +
                         "(self.obj_consumers[consumer_port['floating_ip']],\
                                       consumer_ip, provider_ip, num_conns)")
            elif traffic in ['icmp']:
                result = self.traffic_obj.send_traffic_icmp(
                             self.obj_consumers[consumer_port['floating_ip']],
                                                     consumer_ip, provider_ip)
            time.sleep(10)
            # Test if traffic sending failed for classifier traffic
            if result is not True and traffic in positive_traffic:
                err_msg = "Fail: %s traffic sending failed on port: %s." % (
                                                              traffic, port)
                print err_msg
                self.log_obj.error(err_msg)
                traffic_fail = "fail"
            # Test if traffic sending failed for negative traffic
            if result is not True and traffic not in positive_traffic:
                msg = "Success: " + str(result) + " on port: %s " % port
                print msg
                self.log_obj.info(msg)
                return
            # For FW N-S case
            if provider_port.get('floating_ip', '') != '':
                provider_ip = provider_port['pt_ip']
            # For FW+LB N-S case
            if vip_details.get('floating_ip', '') != '':
                provider_ip = vip_details['pt_ip']
            # For remote vpn tests. tcpdump output will have
            # tunnel interface ip of remote vpn client.
            if consumer_port.get("tun_iface_ip"):
                consumer_ip = consumer_port.get("tun_iface_ip")
            # Validate traffic
            if common_config.nfp_model == "advanced":
                result = self.validate_traffic(traffic, consumer_ip,
                                        provider_ip,
                                        port,
                                        traffic_info['service_details'],
                                        positive_traffic,
                                        traffic_info['provider_pt_details'],
                                        traffic_fail)
                err_msg += result
            if vip_ip:
                for service in traffic_info['service_details']:
                    if service['service_type'].lower() == "lb":
                        # For base model source ip of packet is vip-ip of lb
                        consumer_ip = service.get('service_vm_ip',
                                                  vip_details['pt_ip'])
            result = self.validate_provider_traffic(traffic, consumer_ip,
                                               provider_ip, port,
                                               positive_traffic,
                                               provider_details,
                                               traffic_fail, vip_ip)
            err_msg += result
            return err_msg
        except Exception as err:
            err_msg = "Exception occurred in send_validate_traffic:"\
                " %s, error: %s. " % (traceback.format_exc(), err)
            self.log_obj.error(err_msg)
            print err_msg
            return "ERROR: Exception occurred in send_validate_traffic. "
        finally:
            result = self.clean_compute()
            if result is not True:
                err_msg = "cleaning dump files failed on compute node : %s. "\
                                                                     % result
                self.log_obj.error(err_msg)
            self.dump_file_list = []
    def capture_traffic(self, service_details=None, provider_details=None):
        """
        Captures the traffic on all the service(active/standby) and provider
        vms by running tcpdump on tap interface.

        Arguments:
            service_details: List contains all the service vms information
            provider_details: List contains all the provider vms information
        Return value:
            On success: True
            On failure: error string
        """
        try:
            if service_details is not None:
                for service_vm in service_details:
                    active_result = self._capture_traffic_helper(
                                    service_vm['port_id'],
                                    service_vm['compute_ip'])
                    if active_result[0] == False:
                        return active_result[1]
                    if ('standby_port_id' in service_vm) and \
                       (service_vm['standby_port_id'] is not None):
                        standby_result = self._capture_traffic_helper(
                                            service_vm['standby_port_id'],
                                            service_vm['standby_compute_ip'])
                        if standby_result[0] == False:
                            return standby_result[1]
            if provider_details is not None:
                for provider_port in provider_details:
                    result = self._capture_traffic_helper(
                                    provider_port['port_id'],
                                    provider_port['compute_ip'])
                    if result[0] == False:
                        return result[1]

            return True

        except Exception as err:
            err_msg = "Exception occurred in capture_traffic:"\
                "%s" % err
            self.log_obj.error(err_msg)
            print err_msg
            return "Exception occurred in capture_traffic"

    def _capture_traffic_helper(self, port_id, compute_ip):
        """ This captures traffic on tap interface based on
        provided port_id and compute_ip"""
        try:
            tap_interface = 'tap' + str(port_id)[:11]
            self.log_obj.info("\nCapturing the traffic on node: %s , "
                          "interface: %s " % (compute_ip, tap_interface))
            print "\nCapturing the traffic on node: %s , interface: %s "\
                % (compute_ip, tap_interface)

            dump_file = 'dump_' + tap_interface
            #prepare of dump files list for cleanup
            self.dump_file_list.append(dump_file)

            cmd_tcpdump = "sudo tcpdump -leni " + tap_interface\
                + " > " + dump_file + " 2>&1 &"
            ssh_obj_compute = self.obj_computes[compute_ip]
            result = commonLib.run_command(ssh_obj_compute, cmd_tcpdump)
            return result
        except Exception as err:
            err_msg = "Exception occurred in capture_traffic_helper:"\
                "%s" % err
            self.log_obj.error(err_msg)
            print err_msg
            return "Exception occurred in capture_traffic_helper"

    def clean_compute(self, empty_flag=0):
        """Cleans dump files in compute-nodes"""
        list_of_dumpfiles = self.dump_file_list
        for compute in self.obj_computes:

            for dumpfile in list_of_dumpfiles:

                interface = dumpfile[5:]
                command = "ps -elf | grep %s | awk '{print $4}' | sudo xargs "\
                                                          "kill -9" % interface
                result = commonLib.run_command(self.obj_computes[compute],
                                               command)
                if result[0] == False:
                    return result[1]

                if empty_flag != 0:
                    command = "echo \"\" > %s" % dumpfile
                else:
                    command = "rm -rf %s" % dumpfile
                result = commonLib.run_command(self.obj_computes[compute],
                                               command)
                if result[0] == False:
                    return result[1]
        return True

    def validate_traffic(self, traffic, consumer_ip, provider_ip,
                         port, service_details, positive_traffic,
                         provider_pt_details, traffic_fail):
        """
        Validates the traffic using dump file

        Arguments:
            traffic: traffic that is sent
            consumer_ip: consumer ip address
            provider_ip: provider ip address
            port: port on which traffic send
            service_details: dictionary containing services details
            positive_traffic: List of classifier traffic
            provider_pt_details: provider vm details
            traffic_fail: null (default value)
                          fail (If traffic sending failed)

        Return value:
            On success: null value
            On failure: error string
        """
        # To filter packets of specific traffic on tap interface of service vm
        active_result = "NotNone"
        standby_result = "NotNone"
        err_msg = ""

        try:
            for service_vm in service_details:
                print "\n Validating Traffic on service : %s " %\
                                       service_vm['service_type']
                self.log_obj.debug("\n Validating Traffic on service : %s "
                                    % service_vm['service_type'])
                tap_interface = 'tap' + str(service_vm['port_id'])[:11]
                dump_file = 'dump_' + tap_interface

                service_vm_details = \
                    {'service_type': service_vm['service_type'],
                     'compute_ip': service_vm['compute_ip'],
                     'service_vm_ip': service_vm['service_vm_ip']}
                active_result = \
                    self._validate_traffic_helper(traffic,
                                                  consumer_ip, provider_ip,
                                                  port,
                                                  positive_traffic,
                                                  provider_pt_details,
                                                  dump_file,
                                                  service_vm_details,
                                                  traffic_fail)

                if ('standby_port_id' in service_vm) and \
                   (service_vm['standby_port_id'] is not None):
                    tap_interface = 'tap' + \
                        str(service_vm['standby_port_id'])[:11]
                    dump_file = 'dump_' + tap_interface
                    service_vm_details = \
                        {'service_type': service_vm['service_type'],
                         'compute_ip': service_vm['standby_compute_ip'],
                         'service_vm_ip': service_vm['standby_service_vm_ip']}

                    standby_result = \
                        self._validate_traffic_helper(traffic,
                                                      consumer_ip, provider_ip,
                                                      port,
                                                      positive_traffic,
                                                      provider_pt_details,
                                                      dump_file,
                                                      service_vm_details,
                                                      traffic_fail)

                #if service_vm['service_type'].lower() == "vpn":
                #    service_vm['service_type'] = "FW"

                if traffic in positive_traffic:
                    if active_result == "":
                        self.active_standby_status[
                                service_vm['service_type']]["active"] = True
                        self.log_obj.debug("if active +ve traffic is success: "
                                       "active_standby_status = %s" %
                                       self.active_standby_status)
                    else:
                        self.active_standby_status[
                                service_vm['service_type']]["active"] = False
                        self.log_obj.debug("if active +vetraffic is failure: "
                                       "active_standby_status = %s" %
                                       self.active_standby_status)
                    if standby_result == "":
                        self.active_standby_status[
                                service_vm['service_type']]["standby"] = True
                        self.log_obj.debug("if standby +vetraffic is success:"
                                       "active_standby_status = %s" %
                                       self.active_standby_status)
                    else:
                        self.active_standby_status[
                                service_vm['service_type']]["standby"] = False
                        self.log_obj.debug("if standby +vetraffic is failure:"
                                       "active_standby_status = %s" %
                                       self.active_standby_status)

            if (active_result == "") and (traffic in positive_traffic):
                return active_result
            elif (standby_result == "") and (traffic in positive_traffic):
                return standby_result
            else:
                if standby_result == "NotNone":
                    # No services ha
                    return active_result
                return active_result + standby_result

        except Exception as err:
            err_msg = "Exception occurred in validation_analyze_traffic:"\
                "%s, error: %s. " % (traceback.format_exc(), err)
            self.log_obj.error(err_msg)
            print err_msg
            return "Exception occurred in validation_analyze_traffic. "

    def _validate_traffic_helper(self, traffic, consumer_ip, provider_ip, port,
                                 positive_traffic, provider_pt_details,
                                 dump_file, service_vm, traffic_fail):
        """Helper function for validate traffic"""
        try:
            validate_result = ''
            service_ip = service_vm['service_vm_ip']
            ssh_obj_compute = self.obj_computes[service_vm['compute_ip']]

            results, err_msg = self.build_traffic_dict(traffic, consumer_ip,
                                   provider_ip, port, dump_file, service_vm)
            #if  :
            #    return result

            # If negative traffic
            if traffic not in positive_traffic:
                if traffic == "udp":
                    pass
                if 'True' in results.values():
                    print "ERROR : result dict - %s" % results
                    err_msg = "ERROR: %s traffic on port : %s is allowed"\
                              " in service: %s, ip: %s. " % \
                              (traffic, port, service_vm['service_type'],
                               service_ip)
                    print err_msg
                    validate_result += err_msg
                    self.log_obj.error(err_msg)
            else:
                if traffic == 'udp':
                    check = 'udp'
                else:
                    check = 'in'
                # If traffic sending failed check for packets in service vm
                if traffic_fail:
                    if results == gbp_config.traffic_config[check]:
                        self.log_obj.info("Packets observed in service:"
                                              " %s, %s "
                                      % (service_vm['service_type'], results))
                        validate_result += "Traffic observed in service: "\
                                         " %s. " % service_vm['service_type']
                    elif 'True' in results.values():
                        self.log_obj.info("Request packets are observed in "
                                       "service: %s "
                                       % service_vm['service_type'])
                        validate_result += "Traffic observed in service: "\
                            " %s. " % service_vm['service_type']
                    else:
                        self.log_obj.info("Traffic not observed in service: "
                                          "%s\n " % service_vm['service_type'])
                        validate_result += "Traffic not observed in "\
                                           "service: %s. "\
                                           % service_vm['service_type']
                # If traffic sent, check for packets in service vm
                elif results != gbp_config.traffic_config[check]:
                    err_msg = "Error: %s traffic not allowed on port : "\
                              "%s, service: %s, ip: %s. " % \
                              (traffic, port, service_vm['service_type'],
                               service_ip)
                    print err_msg
                    validate_result += err_msg
                    self.log_obj.error(err_msg)
                # If load balancer Verify round robin functionality
                elif service_vm['service_type'].lower() == "lb" and \
                                    traffic in positive_traffic:
                    weights = 0
                    times = 2
                    if traffic == 'https':
                        member_port = "443"
                        member_traffic = traffic
                    else:
                        member_port = gbp_config.lb_member_port
                        member_traffic = 'http'
                    address = provider_pt_details[0]['pt_ip']
                    # Ex: 2.0.0 of 2.0.0.2
                    pattern = address[:address.rindex('.')]
                    # Find sum of all the weights of loadbalancer members
                    for provider_port in provider_pt_details:
                        weights += int(provider_port['weight'])
                    weights *= times
                    command_fin = " grep -o '%s.* > %s.* \[F.' %s " % \
                        (service_ip, pattern, dump_file)
                    result = commonLib.run_command(ssh_obj_compute,
                                                   command_fin)
                    if result[0] == False:
                        err_msg = "validate dump_file failed to check"\
                                  " round robin: %s for service: %s, "\
                                  "ip: %s, protocol: %s, port: %s. " % (
                                   result, service_vm['service_type'],
                                   service_ip, traffic, port)
                        print err_msg
                        self.log_obj.error(err_msg)
                        validate_result += err_msg

                    elif len(result[1].split('\n')) >= weights:
                        for provider_port in provider_pt_details:
                            # Check for packets coming with port or
                            # port-name (ex: 80-ubuntu, http-rhel)
                            format1 = " > %s.%s" % (
                                     provider_port['pt_ip'], member_port)
                            format2 = " > %s.%s" % (
                                     provider_port['pt_ip'], member_traffic)
                            conn_received = result[1].count(format1) +\
                                             result[1].count(format2)
                            if conn_received == int(
                                         provider_port['weight'])*times:
                                self.log_obj.info("round robin worked for "
                                              "member %s " %
                                              provider_port['pt_ip'])
                                print "round robin worked for member %s "\
                                      % provider_port['pt_ip']
                            else:
                                err_msg = "round robin not worked for "\
                                          "member: %s, connections "\
                                          "sent: %s, connections "\
                                          "received: %s. " % (
                                           provider_port['pt_ip'],
                                           int(provider_port['weight']) *
                                           times, conn_received)
                                self.log_obj.error(err_msg)
                                print err_msg
                                validate_result += err_msg
                    else:
                        err_msg = "Unable to check round robin "\
                            "functionality: No. of requests received by lb "\
                            "vm are less than the connections send. "
                        self.log_obj.error(err_msg)
                        print err_msg
                        validate_result += err_msg
            return validate_result
        except Exception as err:
            err_msg = "Exception occurred in validation_analyze_traffic:"\
                "%s, error: %s. " % (traceback.format_exc(), err)
            self.log_obj.error(err_msg)
            print err_msg
            return "Exception occurred in validation_analyze_traffic. "

    def build_traffic_dict(self, traffic, consumer_ip, provider_ip, port,
                           dump_file, vm_details, vip_ip=None):
        """
        It builds a dictionary by checking request and response packets in
        dump files
        Arguments:
            traffic: traffic that is sent
            consumer_ip: consumer ip address
            provider_ip: provider ip address
            port: port on which traffic send
            dump_file: dump file name
            vm_details: service/provider vm details
            vip_ip: vip ip if LB in service chain

        Return value:
            {'request': 'True/False', 'response': 'True/False'}
        """
        err_msg = ''
        grep_port = ''
        fin_packet = ''

        if traffic in ['tcp', 'udp']:
            grep_port = port
        elif traffic == 'dns':
            grep_port = 'domain'
        else: # for traffic http, https, ftp, smtp
            grep_port = traffic
 
        try:
            if vip_ip:
                fin_packet = " Flags \[F.\]"
            ssh_obj_compute = self.obj_computes[vm_details['compute_ip']]
            if traffic == "icmp":
                # Commands to check ICMP traffic from consumer to provider
                req_cmd = "grep -c '%s > %s: ICMP echo request' %s" % (
                             consumer_ip, provider_ip, dump_file)
                rep_cmd = "grep -c '%s > %s: ICMP echo reply' %s" % (
                                 provider_ip, consumer_ip, dump_file)
            else:
                # Commands to check consumer to provider traffic
                req_cmd1 = "\'%s.* > %s.%s:%s\'" % (consumer_ip, provider_ip,
                                                 grep_port, fin_packet)
                req_cmd2 = "\'%s.* > %s.%s:%s\'" % (consumer_ip, provider_ip,
                                                 port, fin_packet)
                req_cmd = "grep -c -e %s -e %s %s" % (req_cmd1, req_cmd2,
                                                                 dump_file)

                # GET reply packets on the client.
                rep_cmd1 = "\'%s.%s > %s.*%s\'" % (provider_ip, grep_port,
                                                   consumer_ip, fin_packet)
                rep_cmd2 = "\'%s.%s > %s.*%s\'" % (provider_ip, port,
                                                   consumer_ip, fin_packet)
                rep_cmd = "grep -c -e %s -e %s %s" % (rep_cmd1, rep_cmd2,
                                                                 dump_file)

            commands = {'request': req_cmd, 'response': rep_cmd}
            results = {'request': '', 'response': ''}
            # Before search packets in dump-file kill tcpdump on
            # compute node
            command = "ps -elf | grep %s | awk '{print $4}' | sudo xargs "\
                                                "kill -9" % dump_file[5:]
            result = commonLib.run_command(ssh_obj_compute, command)
            if result[0] == False:
                err_msg = "Unable to run command: %s on compute: %s" % (
                            command, vm_details['compute_ip'])
                print err_msg
                self.log_obj.error(err_msg)
            # Building result dictionary
            for value in results.keys():
                self.log_obj.info("\n value is---- %s" % value)
                print "\n value is---- %s" % value
                result = commonLib.run_command(ssh_obj_compute,
                                               commands[value])
                if result[0] == False:
                    err_msg = "validate dump_file failed: %s , "\
                              "on compute: %s." % \
                              (result, vm_details['compute_ip'])
                    print err_msg
                    results[value] = "None"
                elif result[1] and int(result[1]) > 0:
                    results[value] = "True"
                else:
                    results[value] = "False"
            self.log_obj.info("dictionary - %s " % results)
            print "dictionary ---", results
            return (results, err_msg)

        except Exception as err:
            err_msg = "Exception occurred in building traffic dict:"\
                "%s, error: %s. " % (traceback.format_exc(), err)
            self.log_obj.error(err_msg)
            print err_msg
            return "Exception occurred in building traffic dict. "

    def validate_provider_traffic(self, traffic, consumer_ip, provider_ip,
                                  port, positive_traffic, provider_details,
                                  traffic_fail, vip_ip=None):
        """
        Validates the traffic on provider vms using dump file

        Arguments:
            traffic: traffic that is sent
            consumer_ip: consumer ip address
            provider_ip: provider ip address
            port: port on which traffic send
            positive_traffic: List of classifier traffic
            provider_details: provider vm details
            traffic_fail: null (default value)
                          fail (If traffic sending failed)
            vip_ip: vip ip if LB in service chain
        Return value:
            On success: null value
            On failure: error string
        """

        try:
            validate_result = ""
            traffic_val = traffic
            for provider_port in provider_details:
                if vip_ip:
                    provider_ip = provider_port['pt_ip']
                    if traffic == 'tcp' and traffic in positive_traffic:
                        traffic_val = 'http'
                        port = gbp_config.lb_member_port
                print "\n***Validating Traffic on provider vm : %s \n"\
                                      % provider_ip
                self.log_obj.debug("\n Validating Traffic on provider vm : "\
                                   "%s \n" % provider_ip)
                tap_interface = 'tap' + str(provider_port['port_id'])[:11]
                dump_file = 'dump_' + tap_interface
                results, err_msg = self.build_traffic_dict(traffic_val, consumer_ip,
                                     provider_ip, port, dump_file,
                                     provider_port, vip_ip)
                #if  :
                #    return result
                if traffic not in positive_traffic:
                    if traffic == "udp":
                        pass
                    if 'True' in results.values():
                        print "ERROR : result dict - %s" % results
                        err_msg = "ERROR: %s traffic on port : %s is allowed"\
                                  " in vm: %s. " % \
                                  (traffic, port, provider_ip)
                        print err_msg
                        validate_result += err_msg
                        self.log_obj.error(err_msg)
                else:
                    if traffic == 'udp':
                        check = 'udp'
                    else:
                        check = 'in'
                    # If traffic sending failed check for packets in
                    # provider vm
                    if traffic_fail:
                        if results == gbp_config.traffic_config[check]:
                            self.log_obj.info("Packets observed in provider "
                                              "vm: %s, %s "
                                            % (provider_ip, results))
                            validate_result += "Traffic observed in "\
                                           "provider vm: %s. " % provider_ip
                        elif 'True' in results.values():
                            self.log_obj.info("Request packets are observed in "
                                           "provider vm: %s " % provider_ip)
                            validate_result += "Traffic observed in "\
                                           "provider vm: %s. " % provider_ip
                        else:
                            self.log_obj.info("Traffic not observed in "
                                            "provider vm: %s\n" % provider_ip)
                            validate_result += "Traffic not observed in "\
                                            "provider vm: %s. " % provider_ip

                    # If traffic sent, check for packets in provider vm
                    elif results != gbp_config.traffic_config[check]:
                        err_msg = " %s traffic on port: %s is not allowed "\
                                  "on provider vm: %s. "\
                                  % (traffic, port, provider_ip)
                        print err_msg
                        validate_result += err_msg
                        self.log_obj.error(err_msg)
            return validate_result
        except Exception as err:
            err_msg = "Exception occurred in validate_provider_traffic:"\
                "%s, error: %s. " % (traceback.format_exc(), err)
            self.log_obj.error(err_msg)
            print err_msg
            return "Exception occurred in validate_provider_traffic. "
