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
This module contains functions which are common
for most of test cases and will be called as they needed.
"""

import os
# import sys
import json
import time
import pexpect
import commands
import paramiko
import threading
import subprocess
from collections import OrderedDict

# sys.path.append("../../")
import atf.lib.nvp_atf_logging as log
import atf.config.setup_config as setup_config
from atf.config import gbp_config

PWD = os.getcwd()[:-4]

LOG = log.get_atf_logger()


class commonLibrary():

    """class contains utility functions such as checking reachability of an IP,
        getting ssh object, running a command etc.
    """
    total_count = 0
    pass_count = 0
    fail_count = 0

    def __init__(self):

        self.cmd_namespace = "ip netns exec %s  "
        self.cmd_sshpass = self.cmd_namespace + \
            " sshpass -p %s ssh -o StrictHostKeyChecking=no %s@%s \" %s\""

        self.errors = ["Cannot open network namespace",
                       "'sshpass' is currently not installed",
                       "Permission denied",
                       "No route to host",
                       "Connection refused",
                       "Connection timed out"]

    @staticmethod
    def get_decorated_message(message, dec_char="#", length=70):
        """This returns the decorated message"""
        if 'main' not in threading.currentThread().getName().lower():
            return message.replace('\n', ' ')
        return "\n" + length * dec_char + "\n" + message + "\n" + \
            length * dec_char + "\n"

    @staticmethod
    def build_testcase_no_list(tc_no_string):
        """
        Function to build the test-cases numbers list from given string.
        Arguments : test-case numbers string(string)
        Returns : list of test-case numbers (list)
        Eg: arguments = "1, 2, 4, 7-11"
            returns = [1, 2, 4, 7, 8, 9, 10, 11]
        """
        try:
            tc_no_list = []
            tc_no_string = tc_no_string.replace(" ", "")

            for tc_no in tc_no_string.strip().split(","):
                if '-' in tc_no:
                    tc_nos = tc_no.split('-')
                    start_no = tc_nos[0]
                    end_no = tc_nos[1]
                    if not start_no.isdigit() or not end_no.isdigit():
                        continue
                    for _no in range(int(start_no), int(end_no) + 1):
                        tc_no_list.append(str(_no))
                else:
                    if not tc_no.isdigit():
                        continue
                    tc_no_list.append(tc_no)

            print "tc_no_list : %s" % tc_no_list
            LOG.info("tc_no_list : %s" % tc_no_list)
            return tc_no_list

        except Exception as err:
            LOG.exception(err)
            return tc_no_list

    @staticmethod
    def get_compute_node_ip(host_name):
        """It returns the compute node ip (in unicode) corresponding to
        the host_name"""
        try:
            for host in setup_config.setupInfo["compute-node"]:
                if host_name == host['hostname']:
                    return unicode(host["mgmtip"])
            else:
                return "There is NO host: %s in this set up." % str(host_name)
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting compute node ip."

    def test_result_update(self, tcid, tc_status, tc_reason, clean="True"):
        """This function will append result(Fail/Pass) of test execution
            in result file.
        params:
            1. tcid   (test cases id.)
            2. tc_status (pass/fail)
            3. tc_reason (if test cases fails then reason for failure.)
            4. clean   (Optional argument. default value True. If false
                        resources created by test case will not be cleaned)
        """
        try:
            result = {}
            result[tcid] = {"tcstatus": tc_status, "tcreason": tc_reason}
            msg = self.get_decorated_message(
                "Updating the result of testcase: %s" % tcid +
                "\nTest Case Status: %s" % tc_status +
                "\nResult : %s" % tc_reason)
            print msg
            LOG.info(msg)
            commonLibrary.total_count += 1
            if result[tcid]["tcstatus"].lower() == 'pass':
                commonLibrary.pass_count += 1
            else:
                commonLibrary.fail_count += 1

            # appending the testcase's result to result.csv file
            proc = subprocess.\
                Popen(["ls -t " + PWD +
                       "/atf/results/ | grep result | head -1 "],
                      shell=True, stdout=subprocess.PIPE)
            file_name = proc.stdout.read()
            file_name = file_name.rstrip("\n")
            print "Result file name: %s" % file_name
            LOG.debug("Result file name: %s" % file_name)

            with open(PWD + "/atf/results/" + file_name, 'a') as result_file:
                output = tcid + ", " + result[tcid]['tcstatus'].upper() + \
                    ", " + result[tcid]['tcreason'] + '\n'
                result_file.write(output)

            LOG.debug(
                self.get_decorated_message(
                    "TEST(no:%s):%s Completed" %
                    (commonLibrary.total_count, tcid)))
        except Exception as err:
            LOG.exception(err)
            return "Exception occurred while updating result file."

    @staticmethod
    def ping_send(dst_ip):
        """It sends the ping request to the given IP"""

        command = "ping " + dst_ip + " -c 10"
        print command + " Sending Ping Packets..."
        LOG.debug(command + " Sending Ping Packets...")
        status, output = commands.getstatusoutput(command)
        print "status = %s\n%s" % (status, output)
        LOG.debug("status = %s\n%s" % (status, output))

        if "100% packet loss" in output:
            return False
        return True

    # Creates SSH object for remote login

    def create_ssh_object(self, host_ip, user, passwd):
        """It creates the ssh object for the host_ip given.
        params:
            host_ip: IP of the host.
            user: User name of the host.
            passwd: Password of the above user.
        return:
            ssh object on success and None on failure.
        """
        try:
            # ping the host_ip before creating the sshObj for it.
            for attempt in range(1, 5):
                result = self.ping_send(host_ip)
                print "result: %s" % result
                LOG.debug("result: %s" % result)

                if result:
                    print "Ping to ip: %s is successful." % host_ip
                    LOG.debug("Ping to ip: %s is successful." % host_ip)
                    break
                else:
                    time.sleep(15)
            else:  # This is else part of for loop.
                err_msg = "Several times ping to the host_ip: %s failed. "\
                    "So exiting" % host_ip
                print err_msg
                LOG.error(err_msg)
                return
            for attempt in range(0, 5):
                try:
                    print "Trying for %s' attempt" % attempt
                    LOG.debug("Trying for %s' attempt" % attempt)
                    ssh = paramiko.SSHClient()
                    print ("In create_ssh_object function : %s, %s ,%s, %s" %
                           (host_ip, user, passwd, ssh))
                    LOG.debug("In create ssh_object function %s %s %s %s" %
                              (host_ip, user, passwd, ssh))
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host_ip, username=user, password=passwd,
                                timeout=60)
                    return ssh
                except Exception as err:
                    time.sleep(5)
                    LOG.exception(err)

        except Exception as err:
            LOG.exception(err)

    # Runs system commands on remote machine
    @staticmethod
    def run_cmd_on_server(ssh_obj, command):
        """It runs the command on the server whose ssh_obj is given.
        params:
            ssh_obj: ssh object of the server.
            command: Command to be run on the server.
        return:
            string containing the success message or error message.
        """
        print "Executing command : %s" % command
        LOG.info("Executing command : %s" % command)

        stdin, stdout, stderr = ssh_obj.exec_command(command)
        stdin.flush()
        out_data = stdout.read()
        err_data = stderr.read()
        print "stdout: <<%s>>, stderr: <<%s>>" % (out_data, err_data)
        LOG.debug("stdout: <<%s>>, stderr: <<%s>>" % (out_data, err_data))

        data = out_data.rstrip(os.linesep)

        # patch for vms belonging to vyos image.
        err_data = err_data.replace("Welcome to VyOS", '')
        data = data.replace("Welcome to VyOS", '')

        if (err_data and "warning" not in err_data.lower()) or\
                ("warning" in err_data.lower() and
                 len(err_data.strip().split('\n')) > 1):
            data += err_data.rstrip(os.linesep)

        return data

    def get_namespace(self, ssh_obj_nw, resource_id):
        """
        This will return the namespace. The name space could be health monitor
        name space or the router namespace or dhcp namespace etc..
        params:
            ssh_obj_nw: ssh object of nw node.
            resource_id: ID of the resource (ex: tenant/router/dhcp).

        Returns: Tuple containing the status and string.
                On success: (True, "namespace string")
                On failure: (False, "error string")
        """
        try:
            if not hasattr(self, 'namespaces_cache'):
                self.namespaces_cache = {}
            if resource_id in self.namespaces_cache:
                return (True, self.namespaces_cache[resource_id])

            command = "ip netns | grep " + str(resource_id)[:8]
            command_result = self.run_cmd_on_server(ssh_obj_nw, command)
            if not command_result:
                err_msg = "Unable to get the namespace for: %s" % resource_id
                print err_msg
                LOG.error(err_msg)
                return (False, err_msg)
            # Store in the cache
            self.namespaces_cache[resource_id] = command_result

            return (True, command_result)
        except Exception as err:
            LOG.exception(err)
            print err
            return (False, "Problem occurred while getting namespace for: %s"
                    % resource_id)

    @staticmethod
    def clean_known_hosts(ssh_obj, ip_list):
        """
        It will removes the keys of hosts (in 'ip_list') from known_hosts file
        on a node
        params:
             ssh_obj: ssh object of the node
             ip_list: list of ip's (wants to remove keys from known_hosts file)

        Return:
            On success: empty string
            On failure: error string
        """
        try:
            err_msg = ''
            for ip in ip_list:
                command = 'ssh-keygen -f ""/root/.ssh/known_hosts"" -R ' + ip
                result = commonLibrary.run_cmd_on_server(ssh_obj, command)
                if "known_hosts updated" not in result:
                    err_msg += ". failed to clean %s key from "\
                               "known_hosts file" % ip
            return err_msg
        except Exception as err:
            LOG.exception(err)
            print err
            return "Exception in cleaning known_hosts file"

    def run_command(self, ssh_obj, command, **kwargs):
        """
        It will run the command either on a node, name space or in side the vm
        through namespace. It also cleans the known host file.

        params:
            ssh_obj: ssh object of the node,
            command: string [Command to be run]
        optional params:
            (a) run_on: String. ['node', 'namespace', 'vm']
                        Default is 'node'
                NOTE:
                    When run_on is "namespace" then (b) or (c) is required.
                    When run_on is  "vm" then (d) is required in addition
                                    to (b) or (c),

            (b) namespace_id: ID of the namespace.
                [Required when run_on is other than 'node']

            (c) ns_resource_id. ID of the resource whose namespace is
                    retrieved [Required when run_on is other than 'node']
                    NOTE: Ignore this if (b) is given.

            (d) vm_ip, vm_user, vm_password [Required when run_on='vm'],

            (e) clean_known_host_file: bool [To clean the known_hosts.
                                        Default is False]
            (f) retry: Integer [How many times u want the command to be
                    retried, if any problem occurs. Default is 3].

        return: A tuple with status(bool) and o/p (string).
                Ex: On success (True, "actual output").
        """
        try:
            if kwargs.get('clean_known_host_file', False):
                cmd_clean_known_host = "echo '' > /root/.ssh/known_hosts "
                result = self.run_cmd_on_server(ssh_obj,
                                                cmd_clean_known_host)
                print "Result of cleaning the known hosts: %s" % result
                LOG.debug("Result of cleaning the known hosts"
                          ":%s" % result)
                if not command:
                    return result
            if kwargs.get('run_on', "node").lower() != "node":
                # Check if namespace is given or NOT.
                namespace_id = kwargs.get('namespace_id', "")
                # Get the namespace ID for resource_id
                if not namespace_id:
                    result = self.get_namespace(ssh_obj,
                                                kwargs.get('ns_resource_id'))
                    if not result[0]:
                        return result
                    namespace_id = result[1]
                if kwargs.get('run_on').lower() == "namespace":
                    command = self.cmd_namespace % namespace_id + command
                else:
                    command = self.cmd_sshpass % (namespace_id,
                                                  kwargs.get('vm_password'),
                                                  kwargs.get('vm_user'),
                                                  kwargs.get('vm_ip'), command)
            retry = kwargs.get('retry', 3)
            while retry:
                result = self.run_cmd_on_server(ssh_obj, command)
                print "Result of command: %s is \n%s" % (command, result)
                LOG.debug("Result of command: %s is \n%s" %
                          (command, result))
                if self.errors[0] in result or self.errors[1] in result or\
                        self.errors[2] in result:
                    return (False, result)
                elif self.errors[3] in result or self.errors[4] in result or\
                        self.errors[5] in result:
                    time.sleep(10)
                    retry -= 1
                    if not retry:
                        return (False, result)
                else:
                    return (True, result)

        except Exception as err:
            LOG.exception(err)
            print err
            return (False, "Problem while running cmd: %s" % command)

    # For SCP operation to a remote machine
    @staticmethod
    def scp_operation(user_name, password, ip_address,
                      source, destination=""):
        """It does scp operation.
        """
        try:
            scp_newkey = 'Are you sure you want to continue connecting'
            if destination == "":
                scp_cmd = "scp -r " + source + " " + \
                    user_name + "@" + ip_address + ":/home/."
            else:
                scp_cmd = "scp -r " + source + " " + user_name + \
                    "@" + ip_address + ":" + destination + "."
            print scp_cmd
            LOG.debug(scp_cmd)

            child = pexpect.spawn(scp_cmd)
            index = child.expect([scp_newkey, 'password:', pexpect.EOF],
                                 timeout=200)
            if index == 0:
                child.sendline('yes')
                time.sleep(5)
                index = child.expect([scp_newkey, 'password:', pexpect.EOF],
                                     timeout=200)
            if index == 1:
                child.sendline(password)
                time.sleep(5)
                child.expect(pexpect.EOF)
            elif index == 2:
                pass
            return child.before

        except Exception as err:
            LOG.exception(err)


class StressTestHelper(commonLibrary):
    """StressTestHelper class have methods for thread synchronization."""

    # __current_test_no: This class variable have context of current stress
    # test case number under execution.
    __current_test_no = 1
    # __stress_tests_result_dict: This global dictionary, will have
    # stress test result in below format:
    # {'StressTest_1': {'thread0': {'status': '', 'reason': '', 'tc_id': ''},
    #                  'thread1': {'status': '', 'reason': '', 'tc_id': ''},
    #                    ....
    #                    .....
    #                   'threadn': {'status': '', 'reason': '', 'tc_id': ''}
    #                  },
    # 'StressTest_2': {},
    # .......
    # 'StressTest_n': {}
    # }
    __stress_tests_result_dict = {}
    # __result_updated: This class variable is counter. It will be incremented
    # by every thread, once they update test result in class variable
    # __stress_tests_result_dict.
    __result_updated = 0
    # __result_file_updated: This class variable ensures, that only one
    # thread will write stress test result in result file.
    __result_file_updated = False
    __lock = threading.Lock()
    __event = threading.Event()
    # Holds context, stress test case status (Fail/pass)
    __tc_status = "PASS"
    # Holds thread count, can be updated using instance
    # method set_thread_count()
    __no_of_threads = gbp_config.threads
    # __exec_done: It is counter, it will be incremented
    # when thread completes all test assigned to it.
    # This class variable is used to avoid race condition
    # among threads, when tests are not distributed evenly
    # among threads. (i.e. no_of_tests%no_of_threads != 0)
    __exec_done = 0

    def __init__(self):
        commonLibrary.__init__(self)

    def __reset_class_variables(self):
        """Resets some of class variables."""
        StressTestHelper.__result_updated = 0
        StressTestHelper.__tc_status = "PASS"
        StressTestHelper.__result_file_updated = False

    def get_thread_count(self):
        """Returns thread count"""
        return StressTestHelper.__no_of_threads

    def advance_counter_exec_done(self):
        """Advance counter __exec_done by one"""
        with StressTestHelper.__lock:
            StressTestHelper.__exec_done += 1

    def __block_unblock_threads(self):
        """Blocks threads, unless & until all threads update test result."""
        try:
            # Block threads unless all threads don't update respective test
            # result, which they were executing.
            LOG.info("Thread blocked ...")
            while(StressTestHelper.__result_updated != self.__no_of_threads):
                # To avoid race condition among threads
                # when tests are not distributed evenly
                # among the threads.
                if StressTestHelper.__exec_done:
                    LOG.info("Hits a special case where tests are not"
                             " distributed evenly among all threads")
                    while((StressTestHelper.__result_updated +
                           StressTestHelper.__exec_done) !=
                          self.__no_of_threads):
                        LOG.info("Waiting for all threads to "
                                 "update test result...")
                        StressTestHelper.__event.wait(2)
                    else:
                        break
                LOG.info("Waiting for all threads to "
                         "update test result...")
                StressTestHelper.__event.wait(2)

            LOG.info("Thread unblocked ...")
            # update result file.
            with StressTestHelper.__lock:
                if not StressTestHelper.__result_file_updated:
                    LOG.info("Updating stress test result...")
                    # stress test case id.
                    stress_tc_id = "StressTest_" +\
                        str(StressTestHelper.__current_test_no)
                    tc_res_per_thread = StressTestHelper.\
                        __stress_tests_result_dict[stress_tc_id]
                    # stress test case status.
                    tc_status = StressTestHelper.__tc_status
                    # stress test reason per thread.
                    tc_reason = json.dumps(OrderedDict(
                        sorted(tc_res_per_thread.items(), key=lambda x: x[0])))

                    self.test_result_update(
                        stress_tc_id, tc_status, tc_reason)
                    LOG.info("Stress test result updated...")

                    # increment stress test no.
                    StressTestHelper.__current_test_no += 1
                    StressTestHelper.__result_file_updated = True
                    # waiting for 3 seconds,
                    # to let other threads to unblock.
                    time.sleep(3)

        except Exception as err:
            LOG.exception(err)

    def stress_test_result_update(self, tc_id, tc_status, tc_reason):
        """Updates stress result dictionary with tests results
        returned by master test. returns Nothing

        Arguments:
            :param string tc_id: test case id
            :param string tc_status: test case status (fail/pass)
            :param string tc_reason: test case reason.
        """
        stress_tc_id = "StressTest_" + str(StressTestHelper.__current_test_no)
        with StressTestHelper.__lock:
            if stress_tc_id not in StressTestHelper.\
                    __stress_tests_result_dict.keys():
                StressTestHelper.__stress_tests_result_dict[
                                        stress_tc_id] = {}
                LOG.info("Resetting class variables.....")
                # StressTestHelper.__current_test_no += 1
                self.__reset_class_variables()

        current_test_res_dict = StressTestHelper.\
            __stress_tests_result_dict[stress_tc_id]
        thread = threading.currentThread().getName()
        current_test_res_dict[thread] = OrderedDict()
        current_test_res_dict[thread]['tc_id'] = tc_id
        current_test_res_dict[thread]['status'] = tc_status
        current_test_res_dict[thread]['reason'] = tc_reason

        with StressTestHelper.__lock:
            StressTestHelper.__result_updated += 1
            if tc_reason:
                StressTestHelper.__tc_status = "FAIL"
        self.__block_unblock_threads()
