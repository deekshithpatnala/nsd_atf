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

# pylint: disable=W0703

"""
This file corresponds to Load Balancer as a service APIs.
"""

import json
# import sys
import time
from urllib3.poolmanager import PoolManager

# sys.path.append("../../")
from atf.lib.request import OCRequest
import atf.lib.nvp_atf_logging as log

LOG_OBJ = log.get_atf_logger()


class LbaasLib(OCRequest):

    """
    LbaasLib provides APIs to access different functionality of the load
    balancer as a service.
    """

    def __init__(self, token, host_ip='127.0.0.1'):
        """
        token:tenant token.
        host_ip: OS node's public ip.
        """
        OCRequest.__init__(self)
        self.api_url = "http://%s:9696/v2.0/lb/" % host_ip
        self.nova_url = "http://%s:8774/v2" % host_ip
        self.conn_pool = PoolManager(num_pools=10)

        self.token = token

    def list_pool(self):
        """
        It returns the list of pools.
        """
        request_url = "%s/pools.json" % (self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list pools")
                return

            return data['pools']

        except Exception as err:
            LOG_OBJ.exception(err)

    def show_pool(self, _id):
        """It gets the details of the pool.
        param:
            _id: Pool ID.
        Return: A dict containing the pool details, on success.
        """

        request_url = "%s/pools/%s.json" % (self.api_url, _id)
        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to show Pool:%s" % _id)
                return

            return data['pool']

        except Exception as err:
            LOG_OBJ.exception(err)

    def list_vip(self):
        """
        It returns the list of vips.
        """
        request_url = "%s/vips.json" % (self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list vip")
                return

            return data['vips']

        except Exception as err:
            LOG_OBJ.exception(err)

    def show_vip(self, _id):
        """
        It gets the details of the vip.
        params:
            _id: ID of the VIP.
        Return: Dict containing the vip details, on success.
        """
        request_url = "%s/vips/%s.json" % (self.api_url, _id)
        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to show vip:%s" % _id)
                return

            return data['vip']

        except Exception as err:
            LOG_OBJ.exception(err)

    def create_member(self, address, protocol_port, pool_id, **kwargs):
        """It creates the member of the pool.
        params:
            address: IP addrees of the member.
            protocol_port: Protocol port
            pool_id: Pool id.
        Optional params:
            weight: Weight of the member.
            tenant_id: tenant ID for whom this member has to be created.
        Return:
            Dict containing the details of the member, on success.
        """

        request_url = "%s/members.json" % (self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        data = {
            "member": {
                "protocol_port": protocol_port,
                "address": address,
                "pool_id": pool_id,
            }
        }
        for argument in ['weight']:
            try:
                data['member'].update({argument: kwargs[argument]})
            except KeyError:
                pass

        if kwargs.get("tenant_id"):
            data["member"].update({"tenant_id": kwargs["tenant_id"]})

        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.exception(err)

        if resp is None:
            LOG_OBJ.error("Failed to create member")
            return
        LOG_OBJ.debug("Created member successfully")

        return resp['member']

    def list_member(self):
        """
        It returns the list of members
        """
        request_url = "%s/members.json" % (self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list member")
                return

            return data['members']

        except Exception as err:
            LOG_OBJ.exception(err)

    def show_member(self, _id):
        """
        It gets the details of the member.
        params:
            ID: Member ID.
        Return:
            Dict containing the details of the member, on success.
        """
        request_url = "%s/members/%s.json" % (self.api_url, _id)
        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to show member:%s" % _id)
                return

            return data['member']

        except Exception as err:
            LOG_OBJ.exception(err)

    def delete_member(self, member_id):
        """
        It deletes the member.
        param:
            member_id: ID of the member.
        Return: True on success.
        """
        request_url = "%s/members/%s.json" % (self.api_url, member_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            resp = self.process_request("DELETE", request_url, headers, None)
        except Exception as err:
            LOG_OBJ.exception(err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to delete member:%s" % member_id)
            return
        LOG_OBJ.debug("Deleted member:%s successfully" % member_id)

        return True

    def poll_on_resource_status(self, resource_name, resource_id,
                                status, **kwargs):
        """
        params:
            resource_name: Name of the Resource to be polled.
            resource_id: ID of the resource.
            status: Expected success status of the resource. Ex: ACTIVE
        Optional params:
            monitor_duration: Duration (in sec) for polling the resource.
            negative_status: Expected Negative status. Ex: ERROR
        Return:
            Status of the resource, on success of polling.
        """
        start = time.time()
        try:
            monitor_duration = kwargs.get('monitor_duration', 300)
            while True:
                time.sleep(5)
                try:
                    resource = getattr(self, "show_%s" % resource_name)(
                        resource_id)
                except AttributeError as err:
                    LOG_OBJ.error("'%s' is not a valid resource name,"
                                  " error: %s" % (resource_name, err))
                    return
                try:
                    current_status = str(resource['status']).upper()
                except (TypeError, KeyError) as err:
                    LOG_OBJ.info(
                        "show_%s failed, error: %s, %s_info: %s" %
                        (resource_name, err, resource_name, resource))
                    return

                if current_status in [status.upper(),
                                      kwargs.get('negative_status',
                                                 "error").upper()]:
                    LOG_OBJ.info("%s %s become %s" % (
                        resource_name, resource_id, current_status))
                    return current_status

                NOW = time.time()
                if NOW - start >= monitor_duration:
                    LOG_OBJ.info(
                        "%s %s doesn't become %s in %d sec."
                        "The current status: %s" %
                        (resource_name,
                         resource_id,
                         status.upper(),
                            monitor_duration,
                            current_status))
                    return current_status

        except Exception as err:
            LOG_OBJ.exception(err)

    def get_vip_info_by_pool_id(self, pool_id):
        """
        It gives the details of the vip corresponding to a pool.
        Params:
            pool_id: ID of the pool.
        Returns: Dict containing the details of the vip, on success.
        """
        try:
            vips = self.list_vip()
            if not isinstance(vips, list):
                return
            for vip in vips:
                if vip['pool_id'] == pool_id:
                    LOG_OBJ.debug("VIP info for pool: %s is %s" %
                                  (pool_id, vip))
                    return vip
            LOG_OBJ.error("There is NO vip for the pool: %s" % pool_id)

        except Exception as err:
            LOG_OBJ.exception(err)
