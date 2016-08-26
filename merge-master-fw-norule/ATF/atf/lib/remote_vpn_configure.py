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


"""Module contains functions which will be used for remote
   vpn client configuration.
"""


import os
import sys
import time
import commands
from atf.lib.lib_common import commonLibrary
import atf.lib.nvp_atf_logging as log
import atf.config.gbp_config as gbp_config
import atf.config.common_config as common_config

sys.path.append("../../")

LOG_OBJ = log.get_atf_logger()


class RemoteVpnClientConfigure(commonLibrary):
    """Class Contains methods for remote
       vpn client configuration.
    """
    def __init__(self):
        commonLibrary.__init__(self)
        self.ssh_obj = ""

    @staticmethod
    def get_auth_certificate_file_content():
        cwd = os.getcwd()[:-4] + "/atf/config/%s" % gbp_config.auth_crt_file
        return commands.getoutput("cat %s" % cwd)

    @staticmethod
    def get_iface_ip_address(ipa_out, iface):
        """
        It will parse the output of 'ip a' command executed on remote
        server & will return ip  assigned to the given interface.

        Argu:
            ipa_out: output of the ip a command executed on remote server.
            iface: interface name.

        Return: On success returns (True, ip of given interface)
            On failure returns (False, error string)
        """
        if iface not in ipa_out:
            err_msg = "There isn't any interface with name %s." % iface
            LOG_OBJ.error(err_msg)
            return (False, err_msg)

        address_line = ""
        for line in ipa_out.split('\n'):
            if iface in line and 'inet' in line:
                address_line = line
                break

        if address_line:
            return (True, address_line.split()[1].split('/')[0])

        err_msg = "Interface %s isn't assigned with any ip address." % iface
        LOG_OBJ.error(err_msg)
        return (False, err_msg)

    def set_ssh_object(self, server_credentials):
        """
            Returns paramiko ssh object given server credentials.

        Arguments:
            server_credentials: dictionary.
                {
                    "user_name": root,
                    "password": secret,
                    "ip_address": 13.13.13.2
                }
        Return: On success returns True.
            On failure returns error message.
        """
        try:
            ssh_obj = self.create_ssh_object(server_credentials["ip_address"],
                                             server_credentials["user_name"],
                                             server_credentials["password"])
            if ssh_obj is None:
                err_msg = "Failed to create paramiko ssh object"\
                    " for %s ." % server_credentials["ip_address"]
                LOG_OBJ.error(err_msg)
                return err_msg

            self.ssh_obj = ssh_obj
            return True
        except Exception as err:
            LOG_OBJ.error(err)
            return "Exception occurred while creating paramiko ssh "\
                "object to login into remote client vm."

    def copy_crt_file2remote_vpn_client(self):
        """ copy content of certificate file in ca.crt
            on remote client vm.

        Returns: True on success.
            string containing error message on failure.
        """
        try:
            # get content of ca.crt file.
            crt_content = self.get_auth_certificate_file_content()
            command = "echo -e '%s' > /etc/openvpn/ca.crt" % crt_content
            status = self.run_cmd_on_server(self.ssh_obj, command)
            if status:
                err_msg = "Problem occurred while copying auth certificate "\
                    "file to the remote client vm."
                LOG_OBJ.error(err_msg)
                return err_msg
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Exception occurred while coping certificate file"\
                " in remote vpn client."

    def remote_vpn_config_master(self, remote_vpn_client_credentials,
                                 vpn_cred_details,
                                 stitching_floatingip,
                                 vpn_service_image):
        """
        Master method for remote vpn scenario.
        It will perform necessary configuration for remote vpn scenario
        and it will start vpn client service on remote vm.

        Arguments:
            1. remote_vpn_client_credentials (dict)
                e.g.
                        {
                            "user_name": root,
                            "password": secret,
                            "ip_address": 13.13.13.2,
                            "remote_gw": "13.13.13.1"
                        }
            2. vpn_cred_details (dict)
                e.g.
                    {
                        "vpn_user": "vpn_user",
                        "vpn_passwd": "vpn_passwd",
                        ""
                    }
            3. stitching_floatingip (str) stitching floating ip.
            4. vpn_service_image: asav/vyos.

        Return: On success returns (True, tun iface ip.).
            On failure returns (False, err_msg).
        """
        try:
            # ssh to the remote vpn client.
            status = self.set_ssh_object(remote_vpn_client_credentials)
            if type(status) is str:
                return (False, status)

            # start vpn client service on remote vpn client vm.
            if vpn_service_image.lower() == "vyos":
                status = self.start_openvpn(
                        remote_vpn_client_credentials, vpn_cred_details,
                        stitching_floatingip)
                return status
            elif vpn_service_image.lower() == "asav":
                status = self.start_openconnect(
                            remote_vpn_client_credentials, vpn_cred_details,
                            stitching_floatingip)
                return status
            return (False, "ATFError: Invalid vpn service "
                    "image %s" % vpn_service_image)
        except Exception as err:
            err_msg = "Some problem occurred while performing "\
                "configuration for remote vpn scenario."
            LOG_OBJ.exception(err)
            return (False, err_msg)

    def remote_vpn_client_config(self, vpn_service_floatingip):
        """ Method will add configuration in remote vpn client vm.
            Used in case if vpn service is created using vyos image.

            Arguments:
                1. vpn_service_floatingip (stitching port floatingip)

            Returns:On success returns true.
                On any failure returns string containing error message.
        """
        try:
            print "Started Configuring remote vpn client"
            LOG_OBJ.debug("Started Configuring remote vpn client")
            # add vpn service stitching floating ip in client.conf
            # on remote vpn client.
            command = "sed -i 's/^remote .*$/remote %s/g' /etc/openvpn/"\
                "client.conf" % vpn_service_floatingip

            status = self.run_cmd_on_server(self.ssh_obj, command)
            if status:
                err_msg = "Problem occurred while configuring vpn service"\
                    " floating ip in remote vpn client vm."
                LOG_OBJ.error(err_msg)
                return err_msg

            # copy auth certificate remote vpn client.
            status = self.copy_crt_file2remote_vpn_client()
            if type(status) is str:
                return status
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "ATFError: Exception occurred while configuring "\
                "remote vpn client."

    def start_openvpn(self, remote_vpn_client_credentials, vpn_cred_details,
                      stitching_port_floatingip):
        """
        It will start vpn client on remote vpn client vm, so that
        tunnel will be established between remote vpn
        client & vpn service vm. Used in case if vpn service created
        using vyos image.

        Arguments:
            1. remote_vpn_client_credentials (dictionary).
                e.g. {
                        "ip_address": "34.4.4.3",
                        "user_name": "root",
                        "password": "root#123"
                        "remote_gw": "34.4.4.1"
                    }
            2. vpn_cred_details (dictionary containing vpn credentials details)
                e.g.
                    {
                        "vpn_user": "vpn_user",
                        "vpn_passwd": "vpn_passwd",
                        ""
                    }
            3. stitching_port_floatingip

        Return: On success returns (True, tunnel interface ip).
            On Failure return (False, error message).
        """
        try:
            ip_address = remote_vpn_client_credentials["ip_address"]
            # configure remote vpn client vm.
            status = self.remote_vpn_client_config(stitching_port_floatingip)
            if type(status) == str:
                return (False, status)

            print "Starting vpn client service on remote "\
                "vpn client: %s" % ip_address
            LOG_OBJ.debug("Starting vpn client service on remote "
                          "vpn client: %s" % ip_address)
            # check stitching port floating ip reachability.
            command = "ping -c 10 %s" % stitching_port_floatingip
            status = self.run_cmd_on_server(self.ssh_obj, command)
            if "100% packet loss" in status:
                err_msg = "Stitching port floating ip %s is not reachable"\
                    " from remote vpn client %s"\
                    % (stitching_port_floatingip, ip_address)
                LOG_OBJ.error(err_msg)
                return (False, err_msg)

            # create vpn credentials file on remote vpn client vm.
            # and configure this file in client.conf.
            command = "cd /etc/openvpn/;echo -e '%s\\n%s' > %s; sed "\
                "-i 's/auth-user-pass/auth-user-pass %s/g' client.conf"\
                % (vpn_cred_details["vpn_user"],
                   vpn_cred_details["vpn_passwd"], gbp_config.vpn_cred_file,
                   gbp_config.vpn_cred_file)
            status = self.run_cmd_on_server(self.ssh_obj, command)
            LOG_OBJ.debug("Vpn credentials file %s created on remote"
                          " vpn client vm %s." % (gbp_config.vpn_cred_file,
                                                  ip_address))

            # start vpn client service on remote vpn client vm.
            command = "cd /etc/openvpn/;openvpn --config client.conf >"\
                " vpn_start_dump &"
            status = self.run_cmd_on_server(self.ssh_obj, command)
            time.sleep(30)
            return self.validate_tunnel_establishment()
        except Exception as err:
            err_msg = "Some problem occurred while starting vpn client "\
                "service on remote vpn client."
            LOG_OBJ.exception(err)
            return (False, err_msg)

    def validate_tunnel_establishment(self):
        """
        Method will validate if tunnel is established between
        remote vpn client vm & vpn service. Also returns
        tunnel interface ip address.

        Returns: On Success: (True, "tun_iface_ip")
            On Failure: (False, string containing error message)
        """
        try:
            # validate if tunnel is established between remote
            # vpn client & vpn service vm.
            command = "ip a"
            status = self.run_cmd_on_server(self.ssh_obj, command)
            if "tun0" not in status:
                err_msg = "Failed to establish tunnel between remote vpn"\
                    " client vm & vpn servcie vm."
                LOG_OBJ.error(err_msg)
                return (False, err_msg)

            # get ip of tunnel interface on remote client vm.
            tunnel_iface_ip = self.get_iface_ip_address(status, "tun0")
            if type(tunnel_iface_ip) is tuple and tunnel_iface_ip[0]:
                LOG_OBJ.debug("Tunnel established between remote vpn client "
                              "and vpn service vm.")
                return tunnel_iface_ip

            return (False, "Failed to establish tunnel between remote "
                    "vpn client & vpn server.")
        except Exception as err:
            LOG_OBJ.exception(err)
            err = "ATFError: Exception occurred while validating"\
                " tunnel establishment."
            return (False, err)

    def start_openconnect(self, remote_vpn_client_credentials,
                          vpn_cred_details, stitching_port_floatingip):
        """
        It will start openconnect on remote vpn client vm, to establish
        tunnel between remote client & vpn server. Used in case of
        asav vpn service.

        Arguments:
            1. remote_vpn_client_credentials (dictionary).
                e.g. {
                        "ip_address": "34.4.4.3",
                        "user_name": "root",
                        "password": "root#123",
                        "remote_gw": "34.4.4.1"
                    }
            2. vpn_cred_details (dictionary containing vpn credentials details)
                e.g.
                    {
                        "vpn_user": "vpn_user",
                        "vpn_passwd": "vpn_passwd",
                        ""
                    }
            3. stitching_port_floatingip

        Returns: On Success: (True, "").
            On Failure: (False, string containing error message.)
        """
        try:
            # Adding explicit route in remote vpn client vm
            # so that all traffic to ATF NODE of remote client
            # will be redirected to gateway in remote tenant.
            # By doing this connectivity to remote client vm,
            # will not be lost after tunnel establishment.
            ip_address = remote_vpn_client_credentials["ip_address"]
            gateway = remote_vpn_client_credentials["remote_gw"]
            # NOTE: Assumed interface will be eth0 always.
            cmd = "ip route add %s via %s dev eth0"\
                % (common_config.test_execution_node_ip,
                   gateway)
            status = self.run_cmd_on_server(self.ssh_obj, cmd)
            if status:
                err = "Some problen occurred while adding explicit "\
                    "route entry before starting vpn client."
                LOG_OBJ.error(err)
                return (False, err)

            # check stitching port floating ip reachability.
            command = "ping -c 10 %s" % stitching_port_floatingip
            status = self.run_cmd_on_server(self.ssh_obj, command)
            if "100% packet loss" in status:
                err_msg = "Stitching port floating ip %s is not reachable"\
                    " from remote vpn client %s"\
                    % (stitching_port_floatingip, ip_address)
                LOG_OBJ.error(err_msg)
                return (False, err_msg)

            # start vpn client using openconnect.
            """
            cmd = "echo \"echo -n %s | openconnect https://%s:444/ --"\
                "no-cert-check "\
                "--authgroup=remote_ssl_alias --no-dtls -u "\
                "%s --passwd-on-stdin\" > vpn_run.sh"\
                % (vpn_cred_details["vpn_passwd"], stitching_port_floatingip,
                   vpn_cred_details["vpn_user"])
            """
            # create python script on remote client, this
            # script will start vpn client on remote vm.
            # This script internally uses pexpect.
            cmd = "echo -e \"import pexpect\nimport time\ncmd = \\\"openco"\
                "nnect https://%s:444/ --no-cert-check --authgroup=remote_"\
                "ssl_alias --no-dtls -u %s\\\"\nchild = pexpect.spawn(cmd)"\
                "\nchild.expect('Password:', timeout=200)\nchild."\
                "sendline('%s')\ntime.sleep(86400)\" > vpn_run.py"\
                % (stitching_port_floatingip, vpn_cred_details["vpn_user"],
                   vpn_cred_details["vpn_passwd"])
            self.run_cmd_on_server(self.ssh_obj, cmd)
            # start script created above.
            cmd = "python vpn_run.py > /dev/null 2>&1 &"
            self.run_cmd_on_server(self.ssh_obj, cmd)
            time.sleep(10)
            return self.validate_tunnel_establishment()
        except Exception as err:
            LOG_OBJ.exception(err)
            err_msg = "ATFError: Exception occurred while staring vpn "\
                "client on remote client using openconnect."
            return (False, err_msg)
