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
""" This script is to generate various traffic between two machines"""
import traceback
# sys.path.append("../../")
from atf.lib.lib_common import commonLibrary
import atf.lib.nvp_atf_logging as logObj
import atf.config.common_config as com_config


class Traffic(object):
    """Generates (tcp/udp/http/https/icmp/smtp/ftp/dns) traffic b/n two vms"""
    def __init__(self):
        self.log = logObj.get_atf_logger()
        self.comlib = commonLibrary()
        self.com_config = com_config

    def send_traffic_icmp(self, src_ssh_obj, src_ip,  dst_ip):
        """
        Initiates icmp traffic between two machines.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        1. src_ip: source ip address
        3. dst_ip: destination ip address
        """
        try:
            self.log.debug("Initiating ICMP traffic between %s and %s" %
                           (src_ip, dst_ip))
            command = "ping -c 10 " + dst_ip
            command_result = self.comlib.run_command(src_ssh_obj, command)
            if command_result[0] is not True:
                return command_result[1]

            if ("100% packet loss" in command_result[1]) or \
               (command_result[1] is None) or (len(command_result[1]) == 0):
                err_string = "ICMP traffic from %s to %s failed" % (src_ip,
                                                                    dst_ip)
                print err_string
                self.log.error("%s" % err_string)
                return err_string
            else:
                self.log.debug("ICMP traffic from %s to %s passed" % (src_ip,
                                                                      dst_ip))
                return True
        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_http(self, src_ssh_obj, src_ip, dst_ip, num_conns=1):
        """
        Initiates http traffic between two machines.
        This assumes httpd service already running on destination node.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        4. num_conns: Number of times to send traffic
        """
        try:
            self.log.debug("Initiating http traffic between %s and %s" %
                           (src_ip, dst_ip))
            command = "curl -0 -Il http://" + dst_ip
            while num_conns != 0:
                command_result = self.comlib.run_command(
                                        src_ssh_obj, command)
                if command_result[0] is not True:
                    return command_result[1]
                if "Content-Length" not in command_result[1]:
                    self.log.error("HTTP traffic from %s to %s failed " %
                                   (src_ip, dst_ip))
                    return command_result[1]
                num_conns = num_conns - 1
            self.log.debug("HTTP traffic from %s to %s passed" %
                           (src_ip, dst_ip))
            return True

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_ftp(self, src_ssh_obj, src_ip, dst_ip, num_conns=1):
        """
        Initiates ftp traffic between two machines.
        This assumes vsftpd service already running on destination node.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        4. num_conns: Number of times to send traffic from src.
        """
        try:
            self.log.debug("Initiating ftp traffic between %s and %s" %
                           (src_ip, dst_ip))
            command = "curl ftp://%s --user %s:%s " \
                      % (dst_ip, self.com_config.ftpuser,
                          self.com_config.ftppasswd)
            while num_conns != 0:
                command_result = self.comlib.run_command(
                                    src_ssh_obj, command)
                if command_result[0] is not True:
                    return command_result[1]
                if ("Failed" in command_result[1]) or \
                   ("couldn't" in command_result[1]) or \
                   ("denied" in command_result[1]):
                    return command_result[1]
                num_conns = num_conns - 1

            self.log.debug("FTP traffic from %s to %s passed" %
                           (src_ip, dst_ip))
            return True

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_dns(self, src_ssh_obj, src_ip, dst_ip, num_conns=1):
        """
        Initiates dns traffic between two machines.
        This assumes named service already running on destination node.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        4. num_conns: Number of times to send traffic
        """
        try:
            self.log.debug("Initiating dns traffic between %s and %s" %
                           (src_ip, dst_ip))
            # changing resolv.conf in src.
            command = "sed -i.bak \'/nameserver/d\' /etc/resolv.conf;sed -i " \
                      "\'$ a\\nameserver %s\' /etc/resolv.conf" % (dst_ip)
            command_result = self.comlib.run_command(src_ssh_obj, command)

            if command_result[0] is not True:
                return command_result[1]

            while num_conns != 0:
                result = self.start_dns_client(src_ssh_obj, src_ip,
                                               dst_ip)
                if result is not True:
                    clean_var = self.cleanup_dns_client(src_ssh_obj,
                                                        src_ip)
                    if clean_var is not True:
                        self.log.error("cleanup failed in dns client machine")
                    else:
                        self.log.info("cleanup success in dns client machine")
                    return result
                num_conns = num_conns - 1

            clean_var = self.cleanup_dns_client(src_ssh_obj,
                                                src_ip)
            if clean_var is not True:
                self.log.error("cleanup failed in dns client machine")
            else:
                self.log.info("cleanup success in dns client machine")
            return True

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def start_dns_client(self, src_ssh_obj, src_ip, dst_ip):
        """
        Configures /etc/resolv.conf and starts dns client.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        """
        try:
            self.log.debug("Starts dns client on %s" % (src_ip))

            command = "nslookup mydns.com"
            command_result = self.comlib.run_command(src_ssh_obj, command)

            if command_result[0] is not True:
                return command_result[1]

            if dst_ip not in command_result[1]:
                err_string = "Failed to start dns traffic from %s to %s " % \
                             (src_ip, dst_ip)
                return err_string
            else:
                self.log.debug("Sending dns traffic from %s to %s : success" %
                               (src_ip, dst_ip))
                return True
        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def cleanup_dns_client(self, src_ssh_obj, src_ip):
        """
        Restores all changes back on configuration file /etc/resolv.conf.
        Arguments:
        1.src_ssh_obj : src pt ssh object from where traffic gets
        initiated.
        2.src_ip: source ip address
        """
        try:
            self.log.debug("Cleanup on %s" % (src_ip))
            command = "rm -f /etc/resolv.conf; mv /etc/resolv.conf.bak "\
                      + "/etc/resolv.conf; " + " chmod 777 /etc/resolv.conf "
            command_result = self.comlib.run_command(src_ssh_obj, command)
            if command_result[0] is not True:
                return command_result[1]
            else:
                self.log.debug("cleanup on dns client %s : success" % (src_ip))
                return True
        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_tcp(self, src_ssh_obj, src_ip, dst_ip, port,
                         num_conn=1):
        """
        Initiates tcp traffic between two machines.
        This assumes netcat already installed on both source and destination.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. src_ns: source namespace
        4. dst_ip: destination ip address
        5. dst_ns: destination namespace
        6. port : port number
        7. num_conn: number of connections ie, number of clients to start.
        """
        try:
            self.log.debug("starts tcp traffic between %s and %s port: %s" %
                           (src_ip, dst_ip, port))

            while num_conn != 0:
                client_result = self.start_tcp_client(src_ssh_obj, src_ip,
                                                      dst_ip, port)
                # print "Tcp Client result : %s" % client_result
                # self.log.debug("Tcp Client result : %s" % client_result)
                if "succeeded!" not in client_result:
                    err_string = "netcat tcp traffic from %s to %s failed "\
                        % (src_ip, dst_ip)
                    self.log.error("%s" % err_string)
                    return err_string
                else:
                    self.log.debug("netcat tcp traffic from %s to %s success" %
                                   (src_ip, dst_ip))
                num_conn = num_conn - 1

            return True
        except Exception as except_err:
            error_msg = "Exception raised due to %s, %s" % (
                         traceback.format_exc(), except_err)
            self.log.error(error_msg)
            return error_msg

    def start_tcp_client(self, src_ssh_obj, src_ip, dst_ip, port):
        """
        Start netcat tcp client on source.
        Arguments:
        1. src_ip: source ip address
        2. src_ns: source namespace
        3. dst_ip: destination ip address
        4. port : port number
        """
        try:
            self.log.debug("Starting netcat tcp client on %s" % src_ip)
            command = "pgrep -x nc | xargs kill -9 > /dev/null 2>&1;" \
                      "rm -rf netcat_client.txt;nc -zv " + dst_ip + \
                      " " + port + " > netcat_client.txt 2>&1 &"
            command_result = self.comlib.run_command(src_ssh_obj, command)

            if command_result[0] is not True:
                return command_result[1]

            command = "sleep 3;cat netcat_client.txt"
            client_result = self.comlib.run_command(src_ssh_obj, command)
            return client_result[1]

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_curl(self, src_ssh_obj, src_ip, dst_ip, port,
                          num_conns=1):
        """
        Initiates tcp traffic between two machines.
        This assumes netcat already installed on both source and destination.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        4. port: port number
        Optional Arguments:
        1. num_conns: number of connections ie, number of clients to start.
        """
        try:
            self.log.debug("starts tcp traffic between %s and %s port: %s" %
                           (src_ip, dst_ip, port))
            command = "curl -0 -Il http://" + dst_ip + ":" + port
            while num_conns != 0:
                command_result = self.comlib.run_command(src_ssh_obj,
                                                         command)
                if "Content-Length" not in command_result[1]:
                    self.log.error("Tcp traffic from %s to %s failed " %
                                   (src_ip, dst_ip))
                    return command_result[1]
                num_conns = num_conns - 1
            # self.log.debug("Tcp traffic from %s to %s passed" %
            #                (src_ip, dst_ip))
            return True

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_udp(self, src_ssh_obj, src_ip, dst_ip, port):
        """
        Initiates udp traffic between two machines.
        This assumes netcat installed on both source and destination.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        4. port: port number
        """
        try:
            client_result = self.start_udp_client(src_ssh_obj, src_ip, dst_ip,
                                                  port)
            if "ERROR" in client_result:
                self.log.debug("Client result : %s" % client_result)
                return client_result
            if "succeeded!" not in client_result:
                err_string = "netcat udp traffic from %s to %s failed "\
                    % (src_ip, dst_ip)
                self.log.error("%s" % err_string)
                return err_string
            return True
        except Exception as except_err:
            error_msg = "Exception raised due to %s, %s" % (
                        traceback.format_exc(), except_err)
            self.log.error(error_msg)
            return error_msg

    def start_udp_client(self, src_ssh_obj, src_ip, dst_ip, port):
        """
        Start netcat udp client on source.
        Arguments:
        1. src_ip: source ip address
        2. src_ns: source namespace
        3. dst_ip: destination ip address
        4. port: port number
        """
        try:
            self.log.debug("Starting netcat udp client on %s" % src_ip)
            command = "pgrep -x nc | xargs kill -9 > /dev/null 2>&1;" \
                      + "rm -rf netcat_client.txt;nc -zv " + dst_ip + \
                      " -u " + port + " > netcat_client.txt 2>&1 &"
            command_result = self.comlib.run_command(src_ssh_obj, command)

            if command_result[0] is not True:
                return command_result[1]

            command = "sleep 5;cat netcat_client.txt"
            client_result = self.comlib.run_command(src_ssh_obj, command)
            return client_result[1]
        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_smtp(self, src_ssh_obj, src_ip, dst_ip, num_conns=1):
        """
        This initiates smtp traffic between two machines.
        This assumes sendmail installed on both source and destination.
        This assumes source machine's home directory has "smtp_telnet.py" file.
        Arguments:
        1. src_ip: source ip address
        2. src_ns: source namespace
        3. dst_ip: destination ip address
        4. dst_ns: destination namespace
        5. num_conns: Number of times to send traffic
        """
        try:
            self.log.debug("Starting smtp traffic between %s and %s"
                           % (src_ip, dst_ip))
            command = "python /root/smtp_telnet.py %s" % (dst_ip)
            command2 = "sleep 3; cat /root/smtp_telnet_log.txt "
            while num_conns != 0:
                command_result = self.comlib.run_command(src_ssh_obj, command)
                if command_result[0] is not True:
                    return command_result[1]

                if ("Connection timed out" in command_result[1]) or \
                   ("TIMEOUT" in command_result[1]):
                    return "Failed to send smtp traffic"
                command_result = self.comlib.run_command(src_ssh_obj, command2)
                if command_result[0] is not True:
                    return command_result[1]

                if "Connection timed out" in command_result[1]:
                    return command_result[1]
                if ("refused" in command_result[1]) or \
                   (len(command_result[1]) == 0):
                    err_string = "Failed to start smtp packets from %s to %s" \
                                  % (src_ip, dst_ip)
                    return err_string
                num_conns = num_conns - 1
            # self.log.debug("command result of smtp %s" %
            #                command_result[1])
            return True

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg

    def send_traffic_https(self, src_ssh_obj, src_ip, dst_ip, num_conns=1):
        """
        Initiates http traffic between two machines.
        This assumes httpd service already running on destination node.
        Arguments:
        1. src_ssh_obj: src pt ssh object from where traffic gets
        initiated.
        2. src_ip: source ip address
        3. dst_ip: destination ip address
        4. num_conns: Number of times to send traffic
        """
        try:
            self.log.debug("Initiating http traffic between %s and %s" %
                           (src_ip, dst_ip))
            command = "curl -k https://" + dst_ip
            while num_conns != 0:
                command_result = self.comlib.run_command(
                                        src_ssh_obj, command)
                if command_result[0] is not True:
                    return command_result[1]
                if ("html" not in command_result[1]):
                    self.log.error("HTTPS traffic from %s to %s failed " %
                                   (src_ip, dst_ip))
                    return command_result[1]
                num_conns = num_conns - 1
            # self.log.debug("HTTPS traffic from %s to %s passed" %
            #               (src_ip, dst_ip))
            return True

        except Exception as except_err:
            error_msg = "Exception raised due to %s" % except_err
            self.log.error(error_msg)
            return error_msg
