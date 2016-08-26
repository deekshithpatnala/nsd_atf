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
This is a core library for creating Openstack resources.
"""

import time
import json
# import sys
# sys.path.append("../../")

import atf.config.common_config as config
from atf.lib.request import OCRequest
import atf.lib.nvp_atf_logging as log

LOG_OBJ = log.get_atf_logger()


class OpenStackLibrary(OCRequest):

    """
    This is a core library that provides APIs to use the services of Neutron,
    Nova, Glance, Keystone. This library basically contains core functions
    for CRUD operation and also some additional functions to have advanced
    operation.
    """
    cloud_admin_info = {"project_name": "",
                        "project_id": "",
                        "token_domain": "",
                        "token_project": ""}

    def __init__(self, os_pub_ip="127.0.0.1"):
        """
        os_pub_ip: Public IP of the OpenStack node.
        """
        OCRequest.__init__(self)
        self.host_ip = os_pub_ip
        # To be filled by create_tenent/create_project/from outside.
        self.project_info = {"project_name": "",
                             "project_id": "",
                             "token_domain": "",
                             "token_project": ""}

        # Update cloud admin's info.
        if not self.cloud_admin_info["project_name"]:
            self.set_cloud_admin_info()

    def set_cloud_admin_info(self, only_token=False):
        """It will initialize the cloud admin.
        """
        try:
            self.cloud_admin_info["project_name"] = config.cloud_admin_project
            if config.keystone_api_version == 'v3':
                token_domain = self.get_keystone_v3_token(
                                        config.cloud_admin_project,
                                        config.cloud_admin_domain,
                                        config.cloud_admin_user,
                                        config.cloud_admin_passwd,
                                        scope="domain"
                                        )
                token_project = self.get_keystone_v3_token(
                                        config.cloud_admin_project,
                                        config.cloud_admin_domain,
                                        config.cloud_admin_user,
                                        config.cloud_admin_passwd,
                                        scope="project")

                self.cloud_admin_info["token_domain"] = token_domain
                self.cloud_admin_info["token_project"] = token_project

                if not only_token:
                    project_id = self.get_keystone_v3_project_id(
                                                    config.cloud_admin_project)
                    if not isinstance(project_id, unicode):
                        return False
                    self.cloud_admin_info["project_id"] = project_id
            else:
                token_project = self.get_token(
                                        config.cloud_admin_project,
                                        config.cloud_admin_user,
                                        config.cloud_admin_passwd)
                token_domain = token_project
                self.cloud_admin_info["token_domain"] = token_domain
                self.cloud_admin_info["token_project"] = token_project
                if not only_token:
                    project_id = self.get_tenant_id(config.cloud_admin_project)
                    if not isinstance(project_id, unicode):
                        return False
                    self.cloud_admin_info["project_id"] = project_id

            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return False

    def set_tenant_info(self, project_name, token_domain,
                        token_project, project_id=None):
        """
        It sets the project info into the object and gives back the old project
        info like project id and tokens (domain specific & project specific).
        params:
            project_name: project name of new project.
            token_domain: domain specific token.
            token_project: project specific token.
        Return: Tuple containing  the old project's info such as project id,
            domain specific token & project specific token.
        """
        old_project_info = (self.project_info["project_name"],
                            self.project_info["token_domain"],
                            self.project_info["token_project"],
                            self.project_info['project_id'])
        # Set the new project info.
        self.project_info['project_name'] = project_name
        self.project_info["token_domain"] = token_domain
        self.project_info["token_project"] = token_project
        if not project_id:
            if config.keystone_api_version == "v3":
                project_id = self.get_keystone_v3_project_id(project_name)
            else:
                project_id = self.get_tenant_id(project_name)
        self.project_info["project_id"] = project_id

        LOG_OBJ.debug("Successfully set the project info for project: %s" %
                      project_name)
        return old_project_info

    def create_tenant_user_wrapper(self, tenant_name, user_name, password,
                                   domain_name=None, roles=[]):
        """Its wrapper method depending upon keystone api version calls
        keystone rest api's to create keystone resources

        :param string tenant_name: tenant (or project) name.
        :param string user_name: user name
        :param string password: tenant password.
        :param string domain_name: domain name. Required in case
                keystone v3(optional)
        :param list roles: user roles. (optional)

        :Returns: On success returns project id.
            On Failure returns string containing error message.
        """
        try:
            project_info = {"project_name": tenant_name,
                            "user_name": user_name,
                            "password": password,
                            "roles": roles}

            if config.keystone_api_version == 'v3':
                # check if domain is created or not.
                if not domain_name:
                    domain_name = config.keystonev3_domain_name
                domain_id = self.get_keystone_v3_domain_id(domain_name)
                if not isinstance(domain_id, unicode):
                    err_msg = ("Get domain id failed with reason"
                               " %s" % domain_id)
                    LOG_OBJ.error(err_msg)
                    return err_msg
                # Create project and users
                domain_role = config.domain_member_role_name
                project_id = self.create_keystone_v3_project_user(
                                    domain_name, domain_role, project_info)
                if not isinstance(project_id, unicode):
                    err_msg = "Failed to create project using keystone v3 api."
                    LOG_OBJ.error(err_msg)
                    return err_msg
                return project_id
            else:
                if not project_info["roles"]:
                    project_info["roles"] = config.\
                        remote_project_info[0]["roles"]
                tenant_id = self.create_tenant(project_info)
                if not tenant_id:
                    err_msg = "Failed to create tenant using keystone v2 api."
                    LOG_OBJ.error(err_msg)
                    return err_msg
                return tenant_id
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while creating "\
                "keystone resources."

    def get_image_id(self, image_name):
        """
        Get the image ID based on the image name.
        param: image_name: Name of the image.
        Return: ID (Unicode) of the image, on success.
        """
        _url = "http://" + self.host_ip + ":8774/v2/" +\
            self.cloud_admin_info["project_id"] + "/images/detail"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info["token_project"]}
        _body = None

        _result = self.request("GET", _url, _headers, _body)
        if _result is None:
            LOG_OBJ.error("No response from server while getting images.")
            return
        if _result.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get image ID Failed with status %s " %
                          _result.status)
            return _result.status

        _output = json.loads(_result.data)
        for _images in _output['images']:
            if _images['name'].lower() == image_name.lower():
                LOG_OBJ.info("Image Name: %s, Image ID : %s " %
                             (image_name, _images['id']))
                return _images['id']
        LOG_OBJ.error("The image: %s is NOT found" % image_name)

    def get_flavor_id(self, flavor_name):
        """
        Gets the image flavor.
        param: Get the images's flavor ID.
        Return: ID (Unicode) of the flavor, on success.
        """
        _url = "http://" + self.host_ip + ":8774/v2/" +\
            self.cloud_admin_info["project_id"] + \
            "/flavors/detail"
        _headers = {'x-auth-token': self.cloud_admin_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server while getting flavors.")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get flavor ID Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)

        for flavors in output['flavors']:
            if flavors['name'].lower() == flavor_name.lower():
                LOG_OBJ.debug("Flavor Name: %s, ID: %s" % (flavor_name,
                                                           flavors['id']))
                return flavors['id']

        LOG_OBJ.error("Flavor:%s is NOT found" % flavor_name)

    def create_server(self, image_name, flavor_name, net_name,
                      server_name, **kwargs):
        """
        It launches the vm.
        NOTE:
            It allows to create the vm
            (a) by passing net_name,
            (b) by passing net_id,
            (c) in multiple networks [by passing network ids],
            (d) using port(s) in network(s).
                [by passing port id(s) and network id(s)]
        params:
            image_name: Name of the image using which the vm will be booted up.
            flavor_name: Name of the falvor.
            net_name: Network name on which the vm will be launched.
            server_name: Name of the server.
        Optional params:
            host_name: Name of the compute host.
            port_ids: (list) Ids of the port using which the vm will
                        be launched.
            poll_on_status: Whether to  wait on the Active/Error status of vm.
                            Default is True
            net_ids: (List) Id(s) of network(s)
            return_details: Whether to return the details of the server
                            or simply send it's ID. Default is False

        Note: When net_id is passed, we can give any dummy name or empty string
            for netName.
            This is made as generic to work with the existing ATF as well as
            new ATF which requires to create the vm with multiple interfaces.

        returns:
            server id unicode (if return_details=Fale)
            dict containing the details of the server if return_details=True
        """

        LOG_OBJ.debug("Launching server...")

        net_ids = kwargs.get("net_ids", [])
        if not net_ids:
            net_id = self.get_net_id(net_name)
            if not isinstance(net_id, unicode):
                LOG_OBJ.error("Problem while getting net_id corresponding"
                              " to net:%s" % net_name)
                return
            net_ids.append(net_id)

        if not isinstance(net_ids, list):
            net_ids = [net_ids]
        LOG_OBJ.debug("Net Name: %s or NetID: %s" % (net_name, net_ids))

        host = kwargs.get('host_name', "")
        if host != "":
            host = "nova:" + host

        port_ids = kwargs.get('port_ids', [])
        if not port_ids:
            for net_id in net_ids:
                port_name = server_name + "_" + str(net_id)[:5] + "_port"
                port_id = self.create_port(net_name, port_name,
                                           net_id=net_id)
                LOG_OBJ.debug("portId is %s" % port_id)
                if not isinstance(port_id, unicode):
                    return
                port_ids.append(port_id)

        if not isinstance(port_ids, list):
            port_ids = [port_ids]

        boot_nic = []
        for port_id, net_id in zip(port_ids, net_ids):
            boot_nic.append({"uuid": net_id, "port": port_id})

        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/servers"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        # Get the image id.
        image_id = self.get_image_id(image_name)
        if not isinstance(image_id, unicode):
            LOG_OBJ.error("Problem while getting image_id corresponding"
                          " to imageName:%s" % image_name)
            return
        # GEt the flavor id
        flavor_id = self.get_flavor_id(flavor_name)
        if not isinstance(flavor_id, unicode):
            LOG_OBJ.error("Problem while getting flavor_id corresponding"
                          " to flavorName:%s" % flavor_name)
            return

        _server_info = {"server": {
            "name": server_name,
            "imageRef": image_id,
            "flavorRef": flavor_id,
            "max_count": 1,
            # "availability_zone": host,
            "min_count": 1,
            "networks": boot_nic
        }}

        if host:
            _server_info['server']['availability_zone'] = host

        _body = json.dumps(_server_info)
        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(
                "Unable to get the response from server while creating VM")
            return

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create Server Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)
        LOG_OBJ.info("Server details : %s " % output)

        server_id = output['server']['id']
        LOG_OBJ.debug("Server Details: %s" % output['server'])
        # Default is poll on the server status.
        if kwargs.get('poll_on_status', True):
            out = self.poll_on_server_boot_up(server_id)
            LOG_OBJ.info("-> Out: %s, type= %s" % (out, type(out)))
            if not isinstance(out, unicode):
                return out
        # Default is "do not return the details"
        if kwargs.get('return_details', False):
            return output['server']

        return server_id

    def list_servers(self, all_tenants=False):
        """
        This lists the server in a tenant.
        params:
            -
        Optional params:
            all_tenants: To enable searching the vm in all the tenants.
        Return:
            Dict containing the list of the servers, on success.
        """
        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/servers/detail"
        if all_tenants:
            _url = "http://" + self.host_ip + ":8774/v2/" + self.project_info[
                "project_id"] + "/servers/detail?all_tenants=1"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server while listing servers.")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("List servers Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Servers List :%s " % output)
        return output["servers"]

    def show_server(self, server_id):
        """
        It gives the details of the server.
        params:
            server_id: ID of the server.
        Return:
            Dict containing the details of the server, on success.
        """
        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/servers/" + server_id
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]
                    }
        _body = None
        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server while showing the vms")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Show server failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Instance Detail : %s " % output)

        return output["server"]

    def delete_server(self, server_id):
        """
        It Deletes server.
        Arguments:
            server_id: uuid of the server
        Returns: True on successful deletion of server.
        """
        LOG_OBJ.info("Deleting server : %s" % server_id)

        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/servers/" + server_id
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server while deleting vm.")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get instance Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Deleted server : %s " % server_id)
        return True

    def poll_for_active_status(self, server_id, req_status="ACTIVE"):
        """
        It polls on the Active/given optional status of the server.
        Note:
            Polling finishes when the server is Active/required state or goes
            to error state.
        params:
            server_id: Id of the server.
        optional params:
            req_status: Status of server, need to be polled.
        Return: Status (String)
        """
        status = "BUILDING"
        iteration = 30
        while status.upper() != req_status.upper() \
                or status.upper() != "ERROR":
            server_info = self.show_server(server_id)
            if not isinstance(server_info, dict):
                return
            status = server_info['status']
            LOG_OBJ.debug("Server status : %s" % status)
            if status.upper() in [req_status.upper(), 'ERROR']:
                break
            LOG_OBJ.debug("Waiting till server goes to %s state..."
                          % req_status)
            time.sleep(20)
            iteration -= 1
            if not iteration:
                err_msg = "The server:%s is NOT in %s state" \
                     "within 10 minutes" % (server_id, status)
                LOG_OBJ.error(err_msg)
                return "POLL_TIME_EXCEEDED"

        LOG_OBJ.debug("Server becomes %s" % status)

        return status

    def list_server_interfaces(self, server_id):
        """Returns server (instance) interfaces list.

        :param string server_id: instance uuid.
        """
        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/servers/" +\
            server_id + "/os-interface"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server. Nova interface"
                          " list failed.")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Nova interfaces list failed with status %s " %
                          response.status)
            return None
        output = json.loads(response.data)
        LOG_OBJ.debug("Nova Interfaces List: %s" % output)
        return output['interfaceAttachments']

    def get_server_ip_mac(self, server_id):
        """
        It gets the server's port info like IP and MAC.
        Note: This corresponds to neutron port corresponding to the server.

        server_id: ID of the server.
        """
        port_list = self.list_port()
        if not isinstance(port_list, list):
            return
        interface_list = []
        for port in port_list:
            if port["device_id"] == server_id:
                port_info = {}
                port_info['mac'] = port['mac_address']
                port_info['ip_address'] = port['fixed_ips'][0]['ip_address']
                interface_list.append(port_info)

        LOG_OBJ.info("VM Interface Info : %s " % interface_list)
        return interface_list

    def get_server_ip(self, server_id):
        """
        It gets the server ip based on the server ID.
        params:
            server_id: ID of the server.
        Return:
            Server's IP(s) (list), on success.
        """
        interface_list = self.get_server_ip_mac(server_id)
        if not isinstance(interface_list, list):
            return

        LOG_OBJ.debug("interface_list:%s" % interface_list)
        ip_addresses = []
        for interface in interface_list:
            ip_addresses.append(interface['ip_address'])

        LOG_OBJ.debug("ip_addresses for server %s is %s" % (server_id,
                                                            ip_addresses))
        return ip_addresses

    def get_server_details_by_name(self, server_name, all_tenants=False,
                                   server_alternate_names=None):
        """
        This returns the server details based on the name of the server.
        params:
            server_name: Name of the server.
            tenant_id: Tenant ID
        Optional params:
            all_tenants: To enable searching the vm in all the tenants.
            server_alternate_names: A list of alternate names.
        Return:
            Dict containing the details of the server, on success.
        """
        servers = self.list_servers(all_tenants)
        if not isinstance(servers, list):
            return

        if not server_alternate_names:
            server_alternate_names = [server_name]
        else:
            server_alternate_names.append(server_name)
        for server in servers:
            if server['name'] in server_alternate_names:
                LOG_OBJ.debug("Server details: %s" % server)
                return server

        LOG_OBJ.error("There is NO server with name: %s in tenant: %s" %
                      (server_name, self.project_info["project_id"]))

    def get_server_console_log(self, server_id, length=1):
        """
        It returns the console log of the server. The length tells how many
        lines we want to TAIL the console log.
        params:
            server_id: ID of the server.
            length: Length of the log that to be tailed.
        Return:
            String, on success.
        """
        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/servers/" + \
            server_id + "/action"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]
                    }
        console_output = {'os-getConsoleOutput': {'length': length}}

        _body = json.dumps(console_output)
        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server while"
                          " getting the console log of the server.")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Error while getting the console log of the "
                          "server: %s. Response status= %s" %
                          (server_id, response.status))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Server's console log tailed with length: %d is %s"
                     % (length, output['output']))
        return output['output']

    def poll_on_server_boot_up(self, server_id, server_ip="",
                               monitor_duration_s=600):
        """
        It polls on the server to check whether it booted up completely or not.
        Using this we can also know whether the vm got the ip_addr or not.
        Arguments:
            server_id: The server ID
        Optional params:
            server_ip: the ip_addr of the vm [Optional]
            monitor_duration: how long it polls on the server to boot up.
        Return: On Success.
                    IP in Unicode form: On successful boot up and the
                    vm gets the ip_addr
                On Failure:
                    String: message containing the respective reason.
        """
        host = "host-"
        try:
            vm_status = self.poll_for_active_status(server_id)
            if not vm_status:
                err_msg = "Error while doing show server: %s" % str(server_id)
                LOG_OBJ.error(err_msg)
                return err_msg

            if vm_status.lower() == "error":
                err_msg = "VM: %s LAUNCHED WITH ERROR STATE" % str(server_id)
                LOG_OBJ.error(err_msg)
                return err_msg

            start_time = time.time()
            print "Poll on the server started at: %s" % time.ctime()
            LOG_OBJ.info("Poll on the server started at: %s" %
                         time.ctime())
            if server_ip != "":
                host += server_ip.replace(".", "-")

            while True:
                # Get the server's console output.
                console_output = self.get_server_console_log(server_id)
                if not isinstance(console_output, unicode):
                    LOG_OBJ.error("Problem while getting vm console.")
                    return "Problem while getting vm console."

                LOG_OBJ.info("Output of the console log: %s" % console_output)
                if ("localhost" in console_output or
                        host in console_output) and "login" in console_output:

                    print "The Server; %s booted up successfully." % server_id
                    LOG_OBJ.info("The Server; %s booted up successfully."
                                 % server_id)
                    if "localhost" in console_output:
                        # msg = "The server %s could not get the ip address" \
                        # % str(server_id)
                        # print 70 * "*" + "\n" + msg + "\n" + 70 * "*"
                        # LOG_OBJ.info(
                        #    70 * "*" + "\n" + msg + "\n" + 70 * "*")
                        # TODO: Made local fix for CISCO
                        # return msg
                        return unicode("dummy ip")
                    else:
                        ip_addr = None
                        try:
                            ip_addr = console_output.split()[0][5:].replace(
                                "-", ".")
                            msg = "The server: %s got the ip_addr: %s" % \
                                (str(server_id), str(ip_addr))
                            print msg
                            LOG_OBJ.info(msg)
                        except Exception as err:
                            LOG_OBJ.exception(err)
                            return "problem while getting ip from vm console."

                        return unicode(ip_addr)

                print "Waiting for 20 secs for the server to come up .."
                LOG_OBJ.info("Waiting for 20 secs for the server to come up..")

                time.sleep(20)
                now_time = time.time()
                if (now_time - start_time) > monitor_duration_s:
                    msg = "The server couldn't boot up within %s seconds." % \
                        monitor_duration_s
                    print msg
                    LOG_OBJ.info(msg)
                    return msg

        except Exception as err:
            LOG_OBJ.exception(err)
            return "Problem while polling on the server to boot up"

    def list_security_groups(self):
        """ List security groups. """
        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.project_info["project_id"] + "/os-security-groups"
        _headers = {'x-auth-token': self.project_info["token_project"]}
        _body = None
        # parent_group_id = None
        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(
                "No response from Server while getting security"
                " groups for tenant: %s" %
                self.project_info["project_id"])
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get Group Info Failed with status %s " %
                          response.status)
            return
        output = json.loads(response.data)
        return output["security_groups"]

    def create_security_group_rule(self, sg_id, protocol='', cidr='0.0.0.0/0',
                                   from_port='', to_port='',
                                   direction="ingress"):
        """Adds Security Group Rule To Security Group.

        :param string sg_id: Security Group uuid.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/security"\
            "-group-rules.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _tenant_sec_data = {"security_group_rule":
                            {"security_group_id": sg_id,
                             "remote_ip_prefix": cidr,
                             "direction": direction
                             }
                            }
        if protocol:
            _tenant_sec_data["security_group_rule"]['protocol'] = protocol
        if from_port and to_port:
            _tenant_sec_data["security_group_rule"][
                                "port_range_min"] = from_port
            _tenant_sec_data["security_group_rule"]["port_range_max"] = to_port

        _body = json.dumps(_tenant_sec_data)
        response = self.request("POST", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating"
                          "security groups for tenant: %s"
                          % self.project_info["project_id"])
            return

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Adding Security Group Rule failed"
                          " with status %s " % response.status)
            return

        LOG_OBJ.debug("Created Security Group Rule.")
        return True

    def add_security_group_rules(self, protocol, cidr='0.0.0.0/0',
                                 from_port='', to_port=''):
        """
        It adds the security group rule(s) in the default security group
        created for the tenant.
        params:
            from_port: Ingress port
            to_port: Egress Port
            protocol: Name of the protocol. Ex: tcp/udp/ ...
            cidr: Subnet CIDR.
        Reurn:
            True, on success.
        """
        sg_list = self.list_security_groups()
        if not sg_list:
            return "Failed to list security groups."

        parent_group_id = None
        for rules in sg_list:
            if rules['name'] == "default":
                parent_group_id = rules['id']

        status = self.create_security_group_rule(parent_group_id, protocol,
                                                 cidr, from_port, to_port)
        if not status:
            return

        LOG_OBJ.debug("Security group rules added to Default group.")
        return True

    def get_token(self, tenant_name, user_name, password):
        """
        It gets the token of the tenant..
        params:
            tenant_name: Name of the tenant.
            user_name: Name of the user.
            password: Password of the user.
        Return: Token (Unicode), on success.
        """
        _url = "http://" + self.host_ip + ":5000/v2.0/tokens"
        _headers = {"content-type": "application/json"}
        _token_info = {"auth": {"tenantName": tenant_name,
                                "passwordCredentials":
                                {"username": user_name,
                                 "password": password}}
                       }

        _body = json.dumps(_token_info)
        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while getting token for"
                          " tenant: %s" % tenant_name)
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Request of token for %s tenant Failed with"
                          " status %s " % (tenant_name, response.status))
            return response.status
        output = json.loads(response.data)
        token_id = output['access']['token']['id']
        LOG_OBJ.debug("Token ID for tenant %s is %s" % (tenant_name, token_id))

        return token_id

    def get_tenant_id(self, tenant_name):
        """
        It returns the tenant id of a tenant.

        params: tenant_name: Name of the tenant.
        Return:
            tenant_id (unicode) on success.
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/tenants"
        _headers = {'x-auth-token': self.cloud_admin_info['token_project']}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while getting tenants")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Tenant list Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)
        for tenant in output['tenants']:
            if tenant['name'] == tenant_name:
                LOG_OBJ.debug("Tenant Details : %s " % tenant)
                return tenant['id']

        LOG_OBJ.error("There is NO tenant with name: %s" % tenant_name)
        return None

    def get_user_id(self, tenant_id, user_name):
        """
        This function is to get user id when user name is provided.
        Arguments:
            tenant_id: id of the tenant.
            userName: name of the tenant user.
        Return:
            user id (unicode)
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/users"
        _body = None
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting user.")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get userID for %s tenant Failed with status %s " %
                          (self.tenant_name, response.status))
            return response.status

        output = json.loads(response.data)
        _user_id = None

        LOG_OBJ.debug("User list: %s" % output)
        LOG_OBJ.debug("tenant ID: %s" % tenant_id)
        for value in output['users']:
            if value is not None and "tenantId" in value.keys():
                if value['tenantId'] == tenant_id and value[
                        'name'].lower() == user_name.lower():
                    _user_id = value['id']
                    return _user_id

        LOG_OBJ.error("User with name '%s' Not Found" % user_name)
        return _user_id

    def get_role_id(self, role_name):
        """
        It gets the role id corresponding to a user role.
        params:
            role_name: Role name of the user.
        Return:
            Role ID (unicode), on success.
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/OS-KSADM/roles"
        _body = None
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}
        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while getting roles.")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get role id for %s Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)

        for value in output['roles']:
            if value['name'].lower() == role_name.lower():
                LOG_OBJ.debug("The role id for role: %s is %s" % (role_name,
                                                                  value['id']))
                return value['id']

        LOG_OBJ.error("There is NO Role with name: %s" % role_name)
        return None

    def create_user(self, _user_data):
        """
        It creates the user in a tenant.
        params:
            _user_data: The dict contains user info.
            {"user": {"email":,
                      "password":
                      "enabled": True,
                      "name":,
                      "tenantId": }}
        Return:
            User ID(Unicode) on success.
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/users"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}
        _body = json.dumps(_user_data)
        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while creating user: %s" %
                          _user_data['user']['name'])
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create user Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)
        LOG_OBJ.info("User created successfully. Details:%s" % output)

        return output['user']['id']

    def list_users(self):
        """
        Returns list of tenants info.
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/users"
        _body = None
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(" no response from Server")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(
                "get user list Failed with status %s " %
                response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("users List : %s")
        return output["users"]

    def delete_user(self, tenant_id, user_name):
        """
        Arguments:
            tenant_id: tenant id
            user_name: user name
        Return: On successful deletion of tenant user returns True.
        """
        # get user id
        _user_id = self.get_user_id(tenant_id, user_name)
        if not isinstance(_user_id, unicode):
            return None

        _url = "http://" + self.host_ip + ":35357/v2.0/users/" + str(_user_id)
        _headers = {'x-auth-token': self.cloud_admin_info['token_project']}
        _body = None

        LOG_OBJ.debug("Deleting user %s" % _user_id)

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(
                "Failed to delete user with status %s " %
                response.status)
            return response.status

        LOG_OBJ.debug("Deleted User %s successfully" % _user_id)

        return True

    def add_user_role(self, tenant_id, user_id, role_id):
        """
        It adds the user role to the user.
        params:
            tenant_id: Id of the tenant
            user_id: Id of the user.
            role_id: Id of the role.
        Return:
            True, on success.
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/tenants/" + \
            tenant_id + "/users/" + user_id + "/roles/OS-KSADM/" + role_id
        _headers = {'x-auth-token': self.cloud_admin_info['token_project']}
        _body = None
        response = self.request("PUT", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while adding role")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Add user role Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Role: %s is added to user:%s successfully."
                     % (role_id, user_id))
        return True

    def set_quota(self, tenant_id):
        """
        It sets the tenant quota like cores, floating_ips, instances, ram
        param:
            tenant_id: Name of the tenant whose quota has to be modified.
        Return:
            True, on success.
        """
        # Get the admin tenant's id.

        _url = "http://" + self.host_ip + ":8774/v2/" + \
            self.cloud_admin_info['project_id'] + "/os-quota-sets/" + tenant_id
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}
        _body = {"quota_set": {
            "cores": 80,
            "floating_ips": 40,
            "instances": 100,
            "ram": 512000}}
        response = self.request("PUT", _url, _headers, json.dumps(_body))
        if response is None:
            LOG_OBJ.error("No response from server while setting the quota"
                          " for tenant: %s" % tenant_id)
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Modifying quota Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)
        LOG_OBJ.info("Tenant Quota Modified. Details : %s " % output)

        return True

    def quota_update(self, tenant_id, fields):
        """
        It updates the tenant quota.
        params:
            fields: Dict which contains quota fields(key) and values(value)
                eg:  {networks: 100, subnet: 100, ports: 50, ...}
        Return: Dict containing the quota of tenant, on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/quotas/" + \
            tenant_id + ".json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}
        _body = {"quota": fields}

        response = self.request("PUT", _url, _headers, json.dumps(_body))
        if response is None:
            LOG_OBJ.error("No response from server while updating the quota"
                          " for tenant: %s" % tenant_id)
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Updating quota Failed with status %s "
                          % response.status)
            return response.status
        output = json.loads(response.data)

        LOG_OBJ.info("Tenant Quota Details : %s " % output)
        return output

    def create_tenant(self, tenant_info):
        """
        It creates the tenant whose basic info is given in tenant_info.
        It does some updates in the tenant like adding security group rules,
        changing the quotas, etc.

        params: tenant_info: A dict
                {tenant_name: Name of the tenant
                user_name: User name in the tenant.[New user to be created]
                user_id: ID of the user (Optional). Required, only if an
                        existing user needs to be added in the tenant.
                password: Password of the user.
                roles: role list (list)
                }
        Return: Tenant ID (Unicode), on success.
        """
        LOG_OBJ.debug("Creating Tenant:%s" % tenant_info['project_name'])
        _tenant_name = tenant_info['project_name']
        _user_name = tenant_info.get('user_name', _tenant_name + "_user")
        _password = tenant_info.get('password', _tenant_name + "_pass")

        _url = "http://" + self.host_ip + ":35357/v2.0/tenants"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info['token_project']}
        _tenant_data = {"tenant": {"enabled": True, "name": _tenant_name,
                                   "description": "Testing API 3"}}

        _body = json.dumps(_tenant_data)

        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while creating tenant: %s"
                          % _tenant_name)
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create tenant Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Created tenant: %s successfully." % _tenant_name)

        _tenant_id = output['tenant']['id']
        # If user id is passed then, directly add that user to the tenant.
        # otherwise Create a new user.
        _user_id = tenant_info.get('user_id', None)
        if not _user_id:
            _user_data = {"user": {"email": None,
                                   "password": _password,
                                   "enabled": True,
                                   "name": _user_name,
                                   "tenantId": _tenant_id}}
            _user_id = self.create_user(_user_data)
            if not isinstance(_user_id, unicode):
                return
        tenant_info['userID'] = _user_id

        # Add the user roles.
        for role_name in tenant_info['roles']:
            role_id = self.get_role_id(role_name)
            if not isinstance(role_id, unicode):
                return
            # Add user role.
            if not self.add_user_role(_tenant_id, _user_id, role_id):
                return
        # Get the token.
        token_id = self.get_token(_tenant_name, _user_name, _password)
        if not isinstance(token_id, unicode):
            return
        # Set the new context. note: This is v2 token, so only project scope.
        self.set_tenant_info(_tenant_name, token_id, token_id, _tenant_id)

        # Adding Security Group Rules
        # Add the ICMP rule.
        # if not isinstance(self.add_security_group_rules("icmp"), bool):
        #    return
        # Add the rule for ssh
        # if not isinstance(self.add_security_group_rules(
        #            "tcp", from_port='22', to_port='22'), bool):
        #    return
        # Add the rule for all udp
        # if not isinstance(self.add_security_group_rules(
        #                    "udp", from_port='1', to_port='65535'), bool):
        #    return

        # Modify the tenant quota.
        # if not isinstance(self.set_quota(_tenant_id), bool):
        #    return
        # Update the quota
        # fields = {"network": 50, "subnet": 50, "port": 100, "floatingip": 50}
        # quotas = self.quota_update(_tenant_id, fields)
        # if not isinstance(quotas, dict):
        #    return
        # LOG_OBJ.info("Quota for tenant[%s] is:%s" % (_tenant_id,
        #                                             str(quotas)))
        return _tenant_id

    def list_tenants(self):
        """
        It will return list tenants info.
        """
        _url = "http://" + self.host_ip + ":35357/v2.0/tenants"
        _headers = {'x-auth-token': self.cloud_admin_info['token_project']}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(" no response from Server")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(
                " tenant list Failed with status %s " %
                response.status)
            return response.status
        output = json.loads(response.data)
        LOG_OBJ.info("Tenant List : %s " % output)
        return output["tenants"]

    def delete_tenant(self, tenant_id):    # not modified
        """
        Arguments:
            tenant_id: id of the tenant to be deleted.
        Return: On successful deletion of tenant returns True.
        """
        LOG_OBJ.debug("Deleting Tenant %s" % tenant_id)

        _url = "http://" + self.host_ip + ":35357/v2.0/tenants/" + tenant_id
        _headers = {'x-auth-token': self.cloud_admin_info['token_project']}
        _body = None

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(" no response from Server")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(
                "get tenant delete Failed with status %s " %
                response.status)
            return response.status

        LOG_OBJ.debug("Deleted tenant %s successfully." % tenant_id)

        return True

    def get_net_id(self, net_name):
        """
        It gets the network ID.
        params:
            net_name: Name of the network.
        Return: network ID (Unicode), on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/networks"
        _headers = {'x-auth-token': self.project_info["token_project"]}
        _body = None

        result = self.request("GET", _url, _headers, _body)

        if result is None:
            LOG_OBJ.error(
                "No response from Server while trying to"
                " get networks of tenant: %s" %
                self.project_info["project_id"])
            return result

        if result.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get network Failed with status %s " % result.status)
            return result.status

        output = json.loads(result.data)
        LOG_OBJ.debug("Networks: %s" % output['networks'])

        for nets in output['networks']:
            if nets['name'].lower() == net_name.lower() and \
                    net_name == config.extnet_name:
                LOG_OBJ.debug("Net ID : %s " % nets['id'])
                return nets['id']
            if nets['name'].lower() == net_name.lower() and \
                    nets['tenant_id'] == self.project_info["project_id"]:
                LOG_OBJ.debug("Net ID : %s " % nets['id'])
                return nets['id']

        LOG_OBJ.debug("Net:%s Not Found" % net_name)
        return

    def create_net(self, net_name, shared="false"):
        """
        It creates the net.
        params:
            net_name: Name of the network.
            shared: Whether the net is shared or not.
        Return:
            Net ID (Unicode), on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/networks.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _net_info = {"network":
                     {"name": net_name,
                      "shared": shared,
                      "admin_state_up": True}}
        _body = json.dumps(_net_info)

        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while creating network.")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Creation of network Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Network is created successfully. Details : %s " %
                     output['network'])

        return output['network']['id']

    def delete_net(self, net_id):
        """
        It deletes the network specified by network id.
        param:
            net_id: Netwrok ID.
        Return:
            True on success.
        """
        LOG_OBJ.debug("Deleting network %s" % net_id)
        _url = "http://" + self.host_ip + ":9696/v2.0/networks/" + \
            net_id + ".json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while  deleting net:%s" %
                          net_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Deletion of Network Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Deleted the network : %s " % net_id)
        return True

    def list_net(self):
        """
        It lists the network under a tenant.
        Return:
            A List of networks.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/networks"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while listing the networks")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get network list Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)

        LOG_OBJ.info("Network List : %s " % output)
        return output['networks']

    def get_net_details(self, net_name="dummy_net", net_id=None):
        """
        It gets the network details either by network name or id.
        params:
            net_name: Name of the network.
        Optional params:
            net_id: ID of the network.
            Note: When net id is given net_name can be anything.
        Return:
            Dict containing the network details, on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/networks"
        _headers = {'x-auth-token': self.project_info["token_project"]}
        _body = None

        result = self.request("GET", _url, _headers, _body)
        if result is None:
            LOG_OBJ.error("No response from Server while listing the nets")
            return result.status
        if result.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get network Failed with status %s " % result.status)
            return result.status
        output = json.loads(result.data)

        for nets in output['networks']:
            if (net_id is not None and (nets['id'] == net_id)) or \
                    nets['name'].lower() == net_name.lower():
                LOG_OBJ.debug("Net details : %s " % nets)
                return nets

        LOG_OBJ.debug("Network with name:%s or with ID:%s is Not Found" %
                      (net_name, net_id))

    def create_external_network(self, extnet_info, ignore_privious=False):
        """
        It creates the external network.
        params:
            1. extnet_info: Info of ext net.
                {extnet_name: Name of the external network.
                gateway: Gateway IP
                cidr: External network's subnet cidr.
                start_ip: Starting IP to be used in the subnet.
                end_ip: End IP to be used in the subnet.
                }
            2. ignore_privious  (True/False). default false.
        Return:
            Ext Network ID (Unicode), on success.
        """
        LOG_OBJ.debug("Creating External Network : ")
        _tenant_name = config.cloud_admin_project
        _net_name = extnet_info['extnet_name']
        _gateway = extnet_info['gateway']
        _cidr = extnet_info['cidr']
        _start_ip = extnet_info['start_ip']
        _end_ip = extnet_info['end_ip']

        if not ignore_privious:
            _url = "http://" + self.host_ip + ":9696/v2.0/networks"
            _headers = {'x-auth-token': self.cloud_admin_info["token_project"]}
            _body = None

            response = self.request("GET", _url, _headers, _body)
            output = json.loads(response.data)
            if output is None:
                LOG_OBJ.error("No response from server while getting"
                              " networks.")
                return
            if response.status not in [200, 201, 202, 203, 204]:
                LOG_OBJ.error("Getting networks list Failed with status %s " %
                              response.status)
                return response.status

            for nets in output['networks']:
                if nets['router:external']:
                    LOG_OBJ.info("External Network already created")
                    return

        _url = "http://" + self.host_ip + ":9696/v2.0/networks.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info["token_project"]}
        _extnet_info = {"network": {
            "tenant_id": self.cloud_admin_info["project_id"],
            "name": _net_name,
            "router:external": "True",
            "admin_state_up": True}}
        _body = json.dumps(_extnet_info)

        response = self.request("POST", _url, _headers, _body)
        output = json.loads(response.data)
        if output is None:
            LOG_OBJ.error("No response from server while creating ext net.")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create ext network Failed with status %s " %
                          response.status)
            return response.status

        _ext_net_id = output['network']['id']
        LOG_OBJ.debug("External Network created successfully. ID:%s" %
                      _ext_net_id)

        # Creating External Subnet
        _url = "http://" + self.host_ip + ":9696/v2.0/subnets.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.cloud_admin_info["token_project"]}
        _ext_subnet_info = {"subnet": {
            "ip_version": 4,
            "allocation_pools": [{"start": _start_ip,
                                  "end": _end_ip}],
            "gateway_ip": _gateway,
            "enable_dhcp": "False",
            "network_id": _ext_net_id,
            "tenant_id": self.cloud_admin_info["project_id"],
            "cidr": _cidr,
            "name": _net_name + "-sub"}}
        _body = json.dumps(_ext_subnet_info)
        output = self.request("POST", _url, _headers, _body)
        if output is None:
            LOG_OBJ.error("No response from server while creating ext-subet")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create subnet Failed with status %s " %
                          response.status)
            return response.status

        return _ext_net_id

    def create_subnet(self, network_name, subnet_name, cidr):
        """
        It creates the subnet in the network specified.
        params:
            network_name: Name of the network
            subnet_name: Name of the subnet
            cidr: CIDR of the subnet.
            allocation_pool (optional)
        Return:
            Subnet id (unicode), on success.
        """
        _net_id = self.get_net_id(network_name)
        if not isinstance(_net_id, unicode):
            return

        _url = "http://" + self.host_ip + ":9696/v2.0/subnets.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _subnet_info = {"subnet":
                        {"ip_version": 4,
                         "network_id": _net_id,
                         "cidr": cidr,
                         "name": subnet_name}}

        _body = json.dumps(_subnet_info)

        LOG_OBJ.debug("Creating subnet in network %s of tenant %s."
                      % (_net_id, self.project_info["project_id"]))

        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while creating subnet")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Creation of subnet Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Subnet details : %s " % output['subnet'])
        return output['subnet']['id']

    def delete_subnet(self, subnet_id):
        """
        It deletes the subnet based on the id.
        param:
            subnet_id: ID of the subnet.
        Return: True(Bool), on success.
        """

        LOG_OBJ.debug("Deleting subnet %s" % subnet_id)

        _url = "http://" + self.host_ip + ":9696/v2.0/subnets/" + \
            subnet_id + ".json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while deleting subnet:%s" %
                          subnet_id)
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Deletion of subnet Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Deleted the subnet : %s " % subnet_id)
        return True

    def list_subnet(self):
        """
        It gets the subnets in a tenant.
        Return:
            A list containing subnets info.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/subnets"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while listing subnet.")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get subnet list Failed with status %s " %
                          response.status)
            return response.status
        output = json.loads(response.data)

        LOG_OBJ.info("subnet List : %s " % output)
        return output["subnets"]

    def get_subnet_details(self, subnet_name="dummy_subnet", subnet_id=None):
        """
        It gets the subnet details by subnet name or subnet id.
        params:
            subnet_name: Name of the subnet.
        Optional params:
            subnet_id: ID of the subnet.
        Return:
            Dict containing the subnet details.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/subnets"
        _headers = {'x-auth-token': self.project_info["token_project"]}
        _body = None

        result = self.request("GET", _url, _headers, _body)
        if result is None:
            LOG_OBJ.error("No response from Server while getting subnets")
            return result
        if result.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get subnet details Failed with status %s " %
                          result.status)
            return result.status

        output = json.loads(result.data)

        for subnets in output['subnets']:
            if (subnet_id is not None and (subnets['id'] == subnet_id)) or\
                    subnets['name'].lower() == subnet_name.lower():
                LOG_OBJ.debug("Subnet Details: %s" % subnets)
                return subnets

        LOG_OBJ.error("Subnet with name:%s or with id:%s is Not Found" %
                      (subnet_name, subnet_id))

    def get_specific_port_by_server_id(self, net_id, server_id):
        """
        This is basically used to identify a particular port info for a vm
        that has multiple interfaces.

        This will return the port of the vm created in the net: net_id.
        Return: Dict containing port details, on success
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/ports.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting ports.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get port ID Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.debug("Port details: %s" % output)

        for port in output['ports']:
            if port["device_id"] == server_id and port['network_id'] == net_id:
                LOG_OBJ.debug("Port ID:%s" % port['id'])
                return port
        LOG_OBJ.error("There is NO port corresponding to server ID: %s"
                      " in Network: %s" % (server_id, net_id))

    def create_port(self, network_name, port_name="port",
                    security_groups=None, net_id=None, **kwargs):
        """
        It creates the port on the specified network.
        params:
            network_name: Name of the network.
            port_name: Name of the port.
        Optional params:
            security_groups: Id of the security group.
            net_id: Network id.
            port_security_enabled: True/False. Default is True
                    Whether the port security for the port to be enabled or NOT
        Return:
            Port ID (Unicode) on success.
        """
        LOG_OBJ.debug("Creating Port : ")

        if net_id is None:
            net_id = self.get_net_id(network_name)
            if not isinstance(net_id, unicode):
                return

        _url = "http://" + self.host_ip + ":9696/v2.0/ports.json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _port_info = {"port": {"network_id": net_id,
                               "tenant_id": self.project_info["project_id"],
                               "name": port_name,
                               "admin_state_up": True,
                               "port_security_enabled": kwargs.get(
                                   'port_security_enabled', True)
                               }}
        if security_groups is not None:
            _port_info["port"]["security_groups"] = security_groups
        _body = json.dumps(_port_info)
        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(" no response from Server")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create port Failed with status %s" %
                          response.status)
            return response.status
        output = json.loads(response.data)

        LOG_OBJ.info("Port Details:%s" % output['port'])
        return output['port']['id']

    def list_port(self):
        """
        Returns list of ports details.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/ports.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server, while listing ports.")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get port list Failed with status %s"
                          % response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Port List : %s " % output)
        return output["ports"]

    def show_port(self, port_id):
        """
        It gives the port info.
        params: port_id: Id of the port.
        Returns: dictionary containing port details.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/ports/" + \
            port_id + ".json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None
        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server, while accessing "
                          "details of %s port." % port_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get port details Failed with status %s"
                          % response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Port Details : %s " % output)

        return output["port"]

    def delete_port(self, port_id):
        """
        It deletes the port.

        params: port_id: Id of the port
        Returns: On successful deletion of port returns True.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/ports/" +\
            port_id + ".json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server, while deleting "
                          "%s port." % port_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Delete port Failed with status %s"
                          % response.status)
            return response.status

        LOG_OBJ.debug("Deleted port: %s" % port_id)
        return True

    def list_router(self):
        """
        It gets the routers info in a tenant.
        Return:
            A list of of routers, on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/routers.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while listing routers.")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("List router Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Router List : %s " % output)

        return output["routers"]

    def list_router_ports(self, router_id):
        """
        It lists all router ports related to given router.
        param: router_id: ID of the router.
        Return: List (containing the router ports), on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/ports.json?"\
            "device_id=" + router_id
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from server, while listing router "
                          "ports of %s router" % router_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Failed to list router ports with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Router port list related to %s router: "
                     "%s " % (router_id, output))
        return output["ports"]

    def create_router(self, router_name="test_router"):
        """
        This is used to create router.

        params:
            router_name: Name of the router.

        Return: Router ID (unicode), on success
        """
        LOG_OBJ.debug(
            "Creating router in tenant %s" %
            self.project_info["project_id"])

        _url = "http://" + self.host_ip + ":9696/v2.0/routers.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}

        _router_info = {
            "router": {
                "tenant_id": self.project_info["project_id"],
                "name": router_name,
                "admin_state_up": True}}

        _body = json.dumps(_router_info)

        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Create router Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Router Details : %s " % output)

        return output['router']['id']

    def delete_router(self, router_id):
        """
        It deletes the router.
        params:
            router_id: Id of the router.

        Return: True, on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/routers/" + \
            router_id + ".json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}
        _body = None

        response = self.request("DELETE", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error(" no response from Server")
            return
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Router delete Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Deleted router:%s " % router_id)
        return True

    def set_router_gateway(self, ext_net_name, router_id):
        """
        It sets the router to the external gateway.
        params:
            ext_net_name: External network name.
            router_id: Id of the router.

        Return: True on success.
        """
        _ext_net_id = self.get_net_id(ext_net_name)
        if not isinstance(_ext_net_id, unicode):
            return

        LOG_OBJ.debug("Setting external gateway of %s router." % router_id)

        _url = "http://" + self.host_ip + ":9696/v2.0/routers/" + \
            router_id + ".json"

        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _gwdata = {"router": {"external_gateway_info":
                              {"network_id": _ext_net_id}}}
        _body = json.dumps(_gwdata)

        response = self.request("PUT", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while setting router:"
                          " %s to gateway: %s" % (router_id, _ext_net_id))
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Setting router gateway Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Router Gateway set is done for  %s router" % router_id)
        return True

    def clear_router_gateway(self, router_id):
        """
        For clearing external gateway for a router.
        Argu:
            router_id: router id
        Return: On clearing external gateway successfully returns True.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/routers/" + \
            router_id + ".json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _gwdata = {"router":
                   {"external_gateway_info": {}}}

        _body = json.dumps(_gwdata)

        response = self.request("PUT", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from server. while clearing external "
                          "gateway of %s router." % router_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Clearing router gateway Failed with "
                          "status %s " % response.status)
            return response.status

        LOG_OBJ.info("Cleared external gateway of %s router" % router_id)
        return True

    def add_router_interface(self, router_id, subnet_id=None, **kwargs):
        """
        It attaches the subnet to the router.
        :param router_id: Id of the router.
        :param subnet_id: Id of the subnet to be attached to router.
        :optional params:
            port_id unicode: UUID of a new neutron port to be used as gateway.
        Return:
            True on success.
        """
        port_id = kwargs.get("port_id")
        if port_id is None and subnet_id is None:
            LOG_OBJ.error("To attach subnet to router either provide "
                          "subnet id or a new port id")
            return
        _url = "http://" + self.host_ip + ":9696/v2.0/routers/" + \
            router_id + "/add_router_interface.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}

        _router_interface_info = {"port_id": port_id} \
            if port_id else {"subnet_id": subnet_id}
        _body = json.dumps(_router_interface_info)

        response = self.request("PUT", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while attaching subnet:%s"
                          " to router: %s" % (subnet_id, router_id))
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Adding interface to router Failed with status %s " %
                          response.status)
            return response.status

        LOG_OBJ.info("Added interface of subnet %s to %s router." %
                     (subnet_id, router_id))
        return True

    def remove_router_interface(self, router_id, subnet_id=None, **kwargs):
        """
        Deletes router interfaces.
        Argu:
            router_id: router id
            subnet_id: subnet id

        Optional Argu:
            port_id: port uuid.

        Returns: On successful removal of router insterface True.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/routers/" + \
            router_id + "/remove_router_interface.json"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.project_info["token_project"]}

        if subnet_id:
            _router_interface_info = {"subnet_id": subnet_id}

        if kwargs.get("port_id"):
            _router_interface_info = {"port_id": kwargs.get("port_id")}

        _body = json.dumps(_router_interface_info)

        response = self.request("PUT", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server, while removing "
                          "interface of %s router" % router_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Removing interface to router Failed with "
                          "status %s " % response.status)
            return response.status

        LOG_OBJ.info("Removed router interface to router: %s" % router_id)
        return True

    def create_floating_ip(self, extnet_name,
                           return_details=False):
        """
        It creates the floating ip from external ip pool.
        params:
            extnet_name: External network name.
            return_details: Tells whether to return the details of floating ip.
        Return:
            On success: Floating Ip (Unicode), if return_details=False
                        Dictionary, if return_details=True
        """
        _external_net_id = self.get_net_id(extnet_name)
        if not isinstance(_external_net_id, unicode):
            return

        LOG_OBJ.debug("Creating floating ip.")

        _url = "http://" + self.host_ip + ":9696/v2.0/floatingips.json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}

        _floatingip_info = {"floatingip": {
            "floating_network_id": _external_net_id}}
        _body = json.dumps(_floatingip_info)

        response = self.request("POST", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating floating ip")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating floating ip Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Floating IP details : %s " % output)
        if return_details:
            return output['floatingip']
        return output['floatingip']['id']

    def list_floating_ip(self):
        """
        It lists the floating ip allocated for the tenant.
        Return:
            List of floating IP, on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/floatingips.json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while listing the"
                          " floating ips")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Retriving floating ip list Failed with"
                          " status %s " % response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.debug("Floating ip list: %s" % output)

        return output["floatingips"]

    def get_floating_ip_by_port_id(self, port_id):
        """
        It Returns the floating ip i.e associated with the port_id.
        params:
            port_id: neutron port_id
        Return:
            Floating IP(Unicode), on success.
        """
        floatingips = self.list_floating_ip()
        if not isinstance(floatingips, list):
            return None

        for floating_ip_info in floatingips:
            if floating_ip_info['port_id'] == port_id:
                floating_ip = floating_ip_info['floating_ip_address']
                LOG_OBJ.debug("Floating ip for port id:%s is %s" %
                              (port_id, floating_ip))
                return floating_ip

        LOG_OBJ.debug("There is NO floating ip for port id: %s" % port_id)
        return None

    def associate_floating_ip(self, floatingip_id, port_id):
        """
        It associates the floating ip to a port.
        params:
            floatingip_id: Id of the floating IP.
            port_id: Id of the port to which floating ip will be associated.
        Return: True, on success.
        """
        _url = "http://" + self.host_ip + ":9696/v2.0/floatingips/" + \
            floatingip_id + ".json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _floatingip_info = {"floatingip": {"port_id": port_id}}
        _body = json.dumps(_floatingip_info)

        response = self.request("PUT", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while associating"
                          " the floating ip")
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Associating floating ip Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Associated floating ip %s with VM ip : %s " %
                     (output['floatingip']['floating_ip_address'],
                      output['floatingip']['fixed_ip_address']))

        return True

    def disassociate_floating_ip(self, floating_id):
        """
        Disassociates floating ip from vm port.
        Arguments:
            floating_id: floating ip id.
        Return: True on successful disassociation of floating ip.
        """
        LOG_OBJ.debug("Disassociate Floatingip with id %s" % floating_id)

        _url = "http://" + self.host_ip + ":9696/v2.0/floatingips/" + \
            floating_id + ".json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _floatingip_info = {"floatingip": {"port_id": None}}
        _body = json.dumps(_floatingip_info)

        response = self.request("PUT", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error(" no response from Server")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Disassociating floating ip Failed with status %s "
                          % response.status)
            return response.status

        output = json.loads(response.data)

        LOG_OBJ.info("Dissociated floating ip %s "
                     % output['floatingip']['floating_ip_address'])
        return True

    def delete_floating_ip(self, floating_id):
        """
        For Deleting floating ips.
        Argu:
            floating_id: floating ip id.
        Return: On successful deletion of floating ip returns True,
        """
        LOG_OBJ.debug("Deleting floating ip with id %s" % floating_id)

        _url = "http://" + self.host_ip + ":9696/v2.0/floatingips/" + \
            floating_id + ".json"
        _headers = {'x-auth-token': self.project_info["token_project"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("DELETE", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from server while deleting flaoting "
                          "ip with id %s" % floating_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Deleting floating ip Failed with status %s"
                          % response.status)
            return response.status

        LOG_OBJ.info("Deleted floating ip with id: %s " % floating_id)
        return True

    # ######################################
    # ####### Keystone V3 API calls ########
    # ######################################

    def get_keystone_v3_token(self, tenant_name, domain_name,
                              user_name, password, scope="domain"):
        """
        It gets the token of the tenant..
        params:
            tenant_name: Name of the tenant.
            user_name: Name of the user.
            password: Password of the user.
            scope: token scope (domain/project)
        Return: Token (Unicode), on success.
        """
        _url = "http://" + self.host_ip + ":5000/v3/auth/tokens"
        _headers = {"content-type": "application/json"}
        _token_info = {"auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "domain": {
                            "name": domain_name
                        },
                        "name": user_name,
                        "password": password
                    }
                }
            },
            "scope": {}
        }
        }
        if scope == "domain":
            _token_info['auth']['scope'] = {"domain": {"name": domain_name}}
        else:
            _token_info['auth']['scope'] = \
                {"project": {"domain": {"name": domain_name},
                             "name": tenant_name}}
        _body = json.dumps(_token_info)
        response = self.request("POST", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while getting token for"
                          " tenant: %s" % tenant_name)
            return response
        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Request of token for %s tenant Failed with"
                          " status %s " % (tenant_name, response.status))
            return response.status

        token_id = response.headers['x-subject-token']
        print ("Token ID for tenant %s is %s" % (tenant_name, token_id))
        LOG_OBJ.debug("Token ID for tenant %s is %s" % (tenant_name, token_id))

        return token_id

    def create_keystone_v3_domain(self, **kwargs):
        """
        It creates the domain.
        params:
            kwargs : dictionary contains
            Compulsory argument :
                name = ""
            Optional arguments
                description = ""
                enable/disable = True/False ...etc
        Return:
            On success: Domain ID
        """
        LOG_OBJ.debug("Creating the domain.")
        print self.project_info

        _url = "http://" + self.host_ip + ":35357/v3/domains"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _domain_info = {"domain": {}}
        for argument in ["name", "description", "enabled", "disabled"]:
            try:
                _domain_info['domain'].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        _body = json.dumps(_domain_info)
        response = self.request("POST", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating domain")
            print ("No response from Server while creating domain")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating domain Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Creating domain Failed with status %s and error : %s " %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Domain details : %s " % output)
        print ("Domain details : %s " % output)
        return output['domain']['id']

    def set_keystone_v3_domain(self, **kwargs):
        """
        It set the domain status.
        params:
            kwargs : dictionary contains
            Compulsory argument :
                domain_id = domain ID
            Optional arguments
                name = name of domain
                description = ""
                enable/disable = True/False ...etc
            domain_id: domain ID
            enable: True/False (to enable or disable the domain)
        Return:
            On success: True
        """
        LOG_OBJ.debug("Creating the domain.")

        _url = "http://" + self.host_ip + ":35357/v3/domains/" + \
               str(kwargs['domain_id'])
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _domain_info = {"domain": {}}
        for argument in ["name", "description", "enabled", "disabled"]:
            try:
                _domain_info['domain'].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        _body = json.dumps(_domain_info)
        response = self.request("PATCH", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while set the domain")
            print ("No response from Server while set the domain")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Set domain Failed with status %s and error : %s" %
                          (response.status, response.data))
            print ("Set domain Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status
        return True

    def delete_keystone_v3_domain(self, domain_id):
        """
        It deletes the domain.
        params:
            domain_id: domain ID
        Return:
            On success: True
        """
        LOG_OBJ.debug("Disable the domain.")
        kwargs = {"domain_id": domain_id, "enabled": False}
        self.set_keystone_v3_domain(**kwargs)

        LOG_OBJ.debug("Deleting the domain.")

        _url = "http://" + self.host_ip + ":35357/v3/domains/" + str(domain_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("DELETE", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while deleting the domain")
            print ("No response from Server while deleting the domain")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Deleting domain Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Deleting domain Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def list_keystone_v3_domains(self):
        """
        It gives list of all the domains.
        Return:
            On success: List of domains list
        """
        LOG_OBJ.debug("List the domains.")

        _url = "http://" + self.host_ip + ":35357/v3/domains"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating domain")
            print ("No response from Server while creating domain")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Listing domains Failed with status %s "
                          "and error : %s" % response.status, response.data)
            print (" Listing domains Failed with status %s and error : %s" %
                   response.status, response.data)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Domains list : %s " % output)
        print ("Domains list : %s " % output)
        return output['domains']

    def show_keystone_v3_domain(self, domain_id):
        """
        It gives the domain info.
        params: domain_id: Id of the domain.
        Returns: dictionary containing domain details.
        """
        LOG_OBJ.debug("Details of a domain.")

        _url = "http://" + self.host_ip + ":35357/v3/domains/" + str(domain_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "details of domain")
            print ("No response from Server while getting the "
                   "details of domain")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Show domain Failed with status %s and error : %s" %
                          (response.status, response.data))
            print ("Show domain Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Domains details : %s " % output)
        print ("Domains details : %s " % output)
        return output['domain']

    def get_keystone_v3_domain_id(self, domain_name):
        """
        It gives the domain ID.
        params: domain_name: name of the domain.
        Returns: domain ID.
        """
        LOG_OBJ.debug("Get the domain ID.")

        _url = "http://" + self.host_ip + ":35357/v3/domains?name=" + \
               str(domain_name)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "ID of domain")
            print ("No response from Server while getting the "
                   "ID of domain")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get domain ID Failed with status %s and error "
                          ": %s" % (response.status, response.data))
            print ("Get domain ID Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Domain details : %s " % output)
        if len(output['domains']) != 1:
            LOG_OBJ.debug("No. of domains with name %s is %s"
                          % (domain_name, len(output['domains'])))
            print("No. of domains with name %s is %s"
                  % (domain_name, len(output['domains'])))
            return

        return output['domains'][0]['id']

    def create_keystone_v3_project(self, **kwargs):
        """
        It creates the project.
        params:
            kwargs : dictionary contains
            Compulsory argument :
                name = project name
                domain = domain ID
            Optional arguments
                description = ""
                enable/disable = True/False ...etc
        Return:
            On success: Project ID
        """
        LOG_OBJ.debug("Creating the project.")
        print self.project_info

        _url = "http://" + self.host_ip + ":35357/v3/projects"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _project_info = {"project": {}}
        for argument in ["name", "description", "domain_id",
                         "enabled", "disabled"]:
            try:
                _project_info['project'].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        _body = json.dumps(_project_info)
        response = self.request("POST", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating project")
            print ("No response from Server while creating project")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating project Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Creating project Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Project details : %s " % output)
        print ("Project details : %s " % output)
        return output['project']['id']

    def delete_keystone_v3_project(self, project_id, domain_id):
        """
        It deletes the project.
        params:
            domain_id: project ID
        Return:
            On success: True
        """
        LOG_OBJ.debug("Disable the project.")
        kwargs = {"project_id": project_id, "enabled": False}
        self.set_keystone_v3_project(**kwargs)

        LOG_OBJ.debug("Deleting the project.")

        _url = "http://" + self.host_ip + ":35357/v3/projects/" + \
               str(project_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("DELETE", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while deleting the project")
            print ("No response from Server while deleting the project")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Deleting project Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Deleting project Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def list_keystone_v3_projects(self):
        """
        It gives list of all the project.
        Return:
            On success: List of projects list
        """
        LOG_OBJ.debug("List the projects.")

        _url = "http://" + self.host_ip + ":35357/v3/projects"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating project")
            print ("No response from Server while creating project")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating project Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Creating project Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Projects list : %s " % output)
        print ("Projects list : %s " % output)
        return output['projects']

    def set_keystone_v3_project(self, **kwargs):
        """
        It set the project status.
        params:
            kwargs : dictionary contains
            Compulsory argument :
                project_id: project ID
            Optional arguments
                description = ""
                name = project name
                domain = domain ID
                enable/disable = True/False ...etc
            project_id: project ID
            enable: True/False (to enable or disable the domain)
        Return:
            On success: True
        """
        LOG_OBJ.debug("Creating the project.")

        _url = "http://" + self.host_ip + ":35357/v3/projects/" + \
               str(kwargs['project_id'])
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _project_info = {"project": {}}
        for argument in ["name", "description", "domain_id",
                         "enabled", "disabled"]:
            try:
                _project_info['project'].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        _body = json.dumps(_project_info)
        response = self.request("PATCH", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while set the project")
            print ("No response from Server while set the project")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Set project Failed with status %s and error : %s" %
                          (response.status, response.data))
            print (" Set project Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def show_keystone_v3_project(self, project_id):
        """
        It gives the project info.
        params: project_id: Id of the project.
        Returns: dictionary containing project details.
        """
        LOG_OBJ.debug("Details of a project.")

        _url = "http://" + self.host_ip + ":35357/v3/projects/" + \
               str(project_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "details of project")
            print ("No response from Server while getting the "
                   "details of project")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Show project Failed with status %s and error : %s" %
                          (response.status, response.data))
            print ("Show project Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Project details : %s " % output)
        print ("Project details : %s " % output)
        return output['project']

    def get_keystone_v3_project_id(self, project_name):
        """
        It gives the project ID.
        params: project_name: name of the project.
        Returns: project ID.
        """
        LOG_OBJ.debug("Get the project ID.")

        _url = "http://" + self.host_ip + ":35357/v3/projects?name=" + \
               str(project_name)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "ID of project")
            print ("No response from Server while getting the "
                   "ID of project")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get project ID Failed with status %s and error "
                          ": %s" % (response.status, response.data))
            print ("Get project ID Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("project details : %s " % output)
        print ("project details : %s " % output)
        if len(output['projects']) != 1:
            LOG_OBJ.debug("No. of projects with name %s is %s"
                          % (project_name, len(output['projects'])))
            print("No. of projects with name %s is %s"
                  % (project_name, len(output['projects'])))
            return
        return output['projects'][0]['id']

    def usage_keystone_v3_project(self):
        """
        """
        pass

    def create_keystone_v3_user(self, **kwargs):
        """
        It creates the user.
        params:
            kwargs : dictionary contains
            Compulsory argument :
                name = user name
                password = password for user
                domain = domain ID
                project = project ID
            Optional arguments
                description = ""
        Return:
            On success: Project ID
        """
        LOG_OBJ.debug("Creating the user.")
        print self.project_info

        _url = "http://" + self.host_ip + ":35357/v3/users"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _project_info = {"user": {}}
        for argument in ["name", "description", "domain_id",
                         "default_project_id", "password",
                         "enable", "disable"]:
            try:
                _project_info['user'].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        _body = json.dumps(_project_info)
        response = self.request("POST", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating user")
            print ("No response from Server while creating user")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating user Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Creating user Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("User details : %s " % output)
        print ("User details : %s " % output)
        return output['user']['id']

    def delete_keystone_v3_user(self, user_id):
        """
        It deletes the user.
        params:
            user_id: user ID
        Return:
            On success: True
        """
        LOG_OBJ.debug("Disable the user.")
        kwargs = {"user_id": user_id, "enabled": False}
        self.set_keystone_v3_user(**kwargs)

        LOG_OBJ.debug("Deleting the user.")

        _url = "http://" + self.host_ip + ":35357/v3/users/" + str(user_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("DELETE", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while deleting the user")
            print ("No response from Server while deleting the user")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Deleting user Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Deleting user Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def list_keystone_v3_users(self):
        """
        It gives list of all the users.
        Return:
            On success: List of users list
        """
        LOG_OBJ.debug("List the users.")

        _url = "http://" + self.host_ip + ":35357/v3/users"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating user")
            print ("No response from Server while creating user")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating user Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Creating user Failed with status %s " %
                   response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Users list : %s " % output)
        print ("Users list : %s " % output)
        return output['users']

    def set_keystone_v3_user(self, **kwargs):
        """
        It set the user properties.
        params:
            kwargs : dictionary contains
            Compulsory argument :
                user_id = user ID
            Optional arguments
                description = ""
                name = user name
                password = password for user
                domain = domain ID
                project = project ID
        Return:
            On success: True
        """
        LOG_OBJ.debug("Creating the project.")

        _url = "http://" + self.host_ip + ":35357/v3/users/" + \
               str(kwargs['user_id'])
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _user_info = {"user": {}}
        for argument in ["name", "description", "domain_id",
                         "default_project_id", "password",
                         "enabled", "disabled"]:
            try:
                _user_info['user'].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        _body = json.dumps(_user_info)
        response = self.request("PATCH", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while set the user")
            print ("No response from Server while set the user")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Set user Failed with status %s and error : %s" %
                          (response.status, response.data))
            print (" Set user Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def show_keystone_v3_user(self, user_id):
        """
        It gives the user info.
        params: user_id: Id of the project.
        Returns: dictionary containing user details.
        """
        LOG_OBJ.debug("Details of a user.")

        _url = "http://" + self.host_ip + ":35357/v3/users/" + str(user_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "details of user")
            print ("No response from Server while getting the "
                   "details of user")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Show user Failed with status %s and error : %s" %
                          (response.status, response.data))
            print ("Show user Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("User details : %s " % output)
        print ("User details : %s " % output)
        return output['user']

    def get_keystone_v3_user_id(self, user_name):
        """
        It gives the user ID.
        params: user_name: name of the user.
        Returns: user ID.
        """
        LOG_OBJ.debug("Get the user ID.")

        _url = "http://" + self.host_ip + ":35357/v3/users?name=" + \
               str(user_name)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "ID of user")
            print ("No response from Server while getting the "
                   "ID of user")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get user ID Failed with status %s and error "
                          ": %s" % (response.status, response.data))
            print ("Get user ID Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("user details : %s " % output)
        print ("user details : %s " % output)
        if len(output['users']) != 1:
            LOG_OBJ.debug("No. of users with name %s is %s"
                          % (user_name, len(output['users'])))
            print("No. of users with name %s is %s"
                  % (user_name, len(output['users'])))
            return
        return output['users'][0]['id']

    def password_change_keystone_v3_user(self):
        """
        """
        pass

    def create_keystone_v3_role(self, role_name):
        """
        It creates the role.
        params:
            role_name: role name.
        Return:
            On success: Role ID
        """
        LOG_OBJ.debug("Creating the role.")

        _url = "http://" + self.host_ip + ":35357/v3/roles"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _role_info = {"role": {
            "name": role_name}}
        _body = json.dumps(_role_info)
        response = self.request("POST", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while creating role")
            print ("No response from Server while creating role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Creating role Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" Creating role Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Role details : %s " % output)
        print ("Role details : %s " % output)
        return output['role']['id']

    def delete_keystone_v3_role(self, role_id):
        """
        It deletes the role.
        params:
            user_id: role ID
        Return:
            On success: True
        """
        LOG_OBJ.debug("Deleting the role.")

        _url = "http://" + self.host_ip + ":35357/v3/roles/" + str(role_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("DELETE", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while deleting the role")
            print ("No response from Server while deleting the role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Deleting role Failed with status %s and error"
                          " : %s " % (response.status, response.data))
            print (" Deleting role Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def list_keystone_v3_roles(self):
        """
        It gives list of all the roles.
        Return:
            On success: List of roles list
        """
        LOG_OBJ.debug("List the roles.")

        _url = "http://" + self.host_ip + ":35357/v3/roles"
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while listing role")
            print ("No response from Server while listing role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" List roles Failed with status %s and error : %s" %
                          (response.status, response.data))
            print (" List roles Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Roles list : %s " % output)
        print ("Roles list : %s " % output)
        return output['roles']

    def set_keystone_v3_role(self, role_id, role_new_name):
        """
        It set the role properties.
        params:
            user_id: role ID
            role_new_name : new name for role
        Return:
            On success: True
        """
        LOG_OBJ.debug("Creating the role.")

        _url = "http://" + self.host_ip + ":35357/v3/roles/" + str(role_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _role_info = {"role": {
            "name": role_new_name}}
        _body = json.dumps(_role_info)
        response = self.request("PATCH", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while set the role")
            print ("No response from Server while set the role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" Set role Failed with status %s and error : %s" %
                          (response.status, response.data))
            print (" Set role Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        return True

    def show_keystone_v3_role(self, role_id):
        """
        It gives the role info.
        params: role_id: Id of the project.
        Returns: dictionary containing role details.
        """
        LOG_OBJ.debug("Details of a role.")

        _url = "http://" + self.host_ip + ":35357/v3/roles/" + str(role_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "details of role")
            print ("No response from Server while getting the "
                   "details of role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Show role Failed with status %s and error : %s" %
                          (response.status, response.data))
            print ("Show role Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Role details : %s " % output)
        print ("Role details : %s " % output)
        return output['role']

    def remove_keystone_v3_role_from_user_or_group(self, user_id,
                                                   domain_id, role_id):
        """
        It removes a role from a user or group.
        params:
            role_id: role ID,
            domain_id: domain ID,
            user_id: user ID
        Return:
            On success: True
        """
        LOG_OBJ.debug("Removing the role.")

        _url = "http://" + self.host_ip + ":35357/v3/domains/" + \
               str(domain_id) + "/users/" + str(user_id) + "/roles/" + \
               str(role_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}

        _body = None
        response = self.request("DELETE", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while removing role")
            print ("No response from Server while removing role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Removing role Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print ("Removing role Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status
        return True

    def add_keystone_v3_role_to_user_or_group(self, user_id, role_id,
                                              pro_dom_id, id_flag):
        """
        It adds a role to a user or group.
        params:
            user_id: user ID,
            role_id: role ID,
            pro_dom_id: project ID or domain ID,
            id_flag = "domain"/ "project"
        Return:
            On success: True
        """
        LOG_OBJ.debug("Adding the role.")

        _url = "http://" + self.host_ip + ":35357/v3/" + id_flag + "s/" + \
               str(pro_dom_id) + "/users/" + str(user_id) + "/roles/" + \
               str(role_id)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None
        response = self.request("PUT", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while adding role")
            print ("No response from Server while adding role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Adding role Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print ("Adding role Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status
        return True

    def list_assigned_keystone_v3_roles(self, **kwargs):
        """
        It gives list of all the roles assigned to users/projects/domains.
        paramenters :
            kwargs : dictionary contains
            Optional argument :
                role = role ID
                user = user ID
                domain = domain ID (or) project = project ID
        Return:
            On success: List of roles assignment list
        """
        LOG_OBJ.debug("List the roles.")

        url_filter = ""
        for argument in kwargs.keys():
            if "id" in url_filter:
                url_filter += "&"
            if argument in ["role", "user"]:
                url_filter += argument + ".id=" + kwargs[argument]
            elif argument in ["domain", "project"]:
                url_filter += "scope." + argument + ".id=" + kwargs[argument]

        _url = "http://" + self.host_ip + ":35357/v3/role_assignments"
        if url_filter:
            _url += "?" + url_filter
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while listing "
                          "roles assignment")
            print ("No response from Server while listing roles assignment")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error(" List roles assignment is Failed with status %s "
                          "and error : %s" % (response.status, response.data))
            print (" List roles asignment is Failed with status %s "
                   "and error : %s" % (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Roles assignment list : %s " % output)
        print ("Roles assignment list : %s " % output)
        return output['role_assignments']

    def get_keystone_v3_role_id(self, role_name):
        """
        It gives the role ID.
        params: role_name: name of the role.
        Returns: role ID.
        """
        LOG_OBJ.debug("Get the role ID.")

        _url = "http://" + self.host_ip + ":35357/v3/roles?name=" + \
               str(role_name)
        _headers = {'x-auth-token': self.cloud_admin_info["token_domain"],
                    'content-type': 'application/json'}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while getting the "
                          "ID of role")
            print ("No response from Server while getting the "
                   "ID of role")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get role ID Failed with status %s and error "
                          ": %s" % (response.status, response.data))
            print ("Get role ID Failed with status %s and error : %s" %
                   (response.status, response.data))
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("role details : %s " % output)
        print ("role details : %s " % output)
        if len(output['roles']) != 1:
            LOG_OBJ.debug("No. of roles with name %s is %s"
                          % (role_name, len(output['roles'])))
            print("No. of roles with name %s is %s"
                  % (role_name, len(output['roles'])))
            return
        return output['roles'][0]['id']

    def poll_on_server_to_delete(self, service_id, monitor_time=200):
        """
        Polls for deletion of server
        params:
            server_id: ID of the server.
            monitor_time: Number of seconds to poll on server.
        Return:
         True  on successful deletion of server.
         error msg if server not got deleted.
        """
        # monitor_time = 300
        iteration = monitor_time / 10
        try:
            old_project_info = self.set_tenant_info(
                self.cloud_admin_info["project_name"],
                self.cloud_admin_info["token_domain"],
                self.cloud_admin_info["token_project"],
                self.cloud_admin_info["project_id"])
            for attempt in range(1, iteration):
                services_list = self.list_servers()
                # assuming services_list is list of dict in true case.
                if not isinstance(services_list, list):
                    return services_list
                server_id_list = []
                for service_dict in services_list:
                    server_id_list.append(service_dict["id"])
                if service_id in server_id_list:
                    msg = "Server %s not yet deleted at attempt %s "\
                          "retrying once more...."\
                          % (service_id, attempt)
                    LOG_OBJ.warning(msg)
                    time.sleep(10)
                else:
                    msg = "Server %s deleted successfully" % (service_id)
                    LOG_OBJ.info(msg)
                    break
            else:
                msg = "Server %s not deleted" % (service_id)
                LOG_OBJ.info(msg)
                return msg

            return True
        except Exception as err:
            err_msg = "Exception %s occurred in polling server to delete" % err
            LOG_OBJ.exception(err_msg)
            return err_msg
        finally:
            reset_project_info = self.set_tenant_info(
                                                *old_project_info)
            if not isinstance(reset_project_info, tuple):
                LOG_OBJ.warning("Not able to reset tenant info")

    def create_keystone_v3_user_and_add_roles(self, project_info, domain_id,
                                              domain_role, project_id):
        """
        This creates a user and adds the user to domain and project,
        with given roles
        params:
              project_info: project information dictionary (dict)
                           {'project_name': '',
                            'user_name': '',
                            'password': '',
                            'roles': []
                           }
              domain_id: Id of domain.
              domain_role: Name of role to add user to domain
              project_id: Id of project

        Returns: user Id
        """
        kwargs = {"name": project_info['user_name'],
                  "password": project_info['password']}
        if domain_id:
            kwargs.update({"domain_id": domain_id})
        if project_id:
            kwargs.update({"default_project_id": project_id})

        user_id = self.create_keystone_v3_user(**kwargs)
        if not isinstance(user_id, unicode):
            err_msg = "Problem while creating user: %s." % kwargs['name']
            LOG_OBJ.error(err_msg)
            return err_msg

        for pro_dom_id in [domain_id, project_id]:
            if pro_dom_id == domain_id:
                id_flag = "domain"
                roles = [domain_role]
            else:
                id_flag = "project"
                roles = project_info['roles']
            for role in roles:
                role_id = self.get_keystone_v3_role_id(role)
                if not isinstance(role_id, unicode):
                    err_msg = "Failed to get role: %s. " % (role)
                    LOG_OBJ.error(err_msg)
                    return err_msg
                output = self.add_keystone_v3_role_to_user_or_group(
                    user_id, role_id, pro_dom_id, id_flag)
                if output is not True:
                    err_msg = ("Adding role %s to user-id %s is failed"
                               % (role, user_id))
                    LOG_OBJ.error(err_msg)
                    return err_msg

        return user_id

    def create_keystone_v3_project_user(self, domain_name, domain_role,
                                        project_details, set_context=True):
        """
        Creates project in a domain, Creates user and adds the user
        to domain and project with given roles
        params:
              domain_name: name of the domain.
              domain_role: Name of role to add user to domain
              project_details: project information dictionary (dict)
                           {'project_name': '',
                            'user_name': '',
                            'password': '',
                            'roles': []
                           }
            set_context: Whether to set the project context or NOT.
        Returns: project Id
        """
        domain_id = self.get_keystone_v3_domain_id(domain_name)
        if not isinstance(domain_id, unicode):
            err_msg = ("Get domain id is failed with reason %s" % domain_id)
            LOG_OBJ.error(err_msg)
            return err_msg

        # Creation of project
        kwargs = {"name": project_details['project_name'],
                  "domain_id": domain_id}
        project_id = self.create_keystone_v3_project(**kwargs)
        if not isinstance(project_id, unicode):
            err_msg = ("Project creation failed with reason %s" % project_id)
            LOG_OBJ.error(err_msg)
            return err_msg

        # creation of user with adding roles.
        user_id = self.create_keystone_v3_user_and_add_roles(
            project_details, domain_id, domain_role, project_id)
        if not isinstance(user_id, unicode):
            err_msg = ("Problem while creating user and assigning role."
                       "Reason %s" % user_id)
            LOG_OBJ.error(err_msg)
            return err_msg

        # Set the context to that of this new user of the tenant.
        if set_context:
            tokens = []
            for token_scope in ["domain", "project"]:
                token = self.get_keystone_v3_token(
                    project_details['project_name'], domain_name,
                    project_details['user_name'], project_details['password'],
                    scope=token_scope)
                # NOTE: The token id is of type str not unicode, in v3 case.
                if not isinstance(token, str):
                    err_msg = ("Get v3 user token is failed with "
                               "reason %s" % token)
                    LOG_OBJ.error(err_msg)
                    return err_msg
                tokens.append(token)
            # Set the token
            self.set_tenant_info(project_details['project_name'], tokens[0],
                                 tokens[1], project_id)
        return project_id

    def reboot_server(self, server_id, action="reboot", action_type="soft"):
        """
        Reboots(hard/soft)/Starts/Stops the server.
        params: server_id : id of the server to reboot/start/stop.
                action: action can be either reboot or start or stop.
                action_type: takes either soft/hard values, applies only for
                             reboot action.
        """
        try:
            LOG_OBJ.info("server %s %sing..." % (server_id, action))
            _url = "http://" + self.host_ip + \
                   ":8774/v2/" + self.cloud_admin_info["project_id"] + \
                   "/servers/" + server_id + "/action"
            _headers = {'x-auth-token': self.cloud_admin_info["token_project"],
                        'content-type': 'application/json'}
            if action.lower() == "start":
                _body = '{"os-start": null}'
            elif action.lower() == "stop":
                _body = '{"os-stop": null}'
            else:
                if action_type.lower() == "hard":
                    _body = '{"reboot": {"type": "HARD"}}'
                else:
                    _body = '{"reboot": {"type": "SOFT"}}'

            response = self.request("POST", _url, _headers, _body)
            if response is None:
                LOG_OBJ.error("No response from Server while performing %s" %
                              action)
                print "No response from Server while performing %s" % action
                return response

            if response.status not in [200, 201, 202, 203, 204]:
                LOG_OBJ.error(" %s action Failed with status %s and error %s" %
                              (action, response.status, response.data))
                print " %s action Failed with status %s and error : %s" % \
                      (action, response.status, response.data)
                return response.status
            return True
        except Exception as err:
            err_msg = "Exception %s occurred in %sing server to delete" % \
                      (err, action)
            LOG_OBJ.exception(err_msg)
            return None
