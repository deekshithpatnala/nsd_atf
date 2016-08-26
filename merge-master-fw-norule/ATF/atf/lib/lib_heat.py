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
HEAT Restful API Library.

This provides few APIs for HEAT like getting all stack list, displaying
a stack details, getting stack id based on the stack name, etc.
"""

import time
import json
# sys.path.append("../../")

from atf.lib.request import OCRequest
import atf.lib.nvp_atf_logging as log

LOG_OBJ = log.get_atf_logger()


class HeatLibrary(OCRequest):

    """
    This class contains basic operation on stack like stack list, show,
    stack resource list, etc.
    """

    def __init__(self, os_pub_ip, tenant_id, tenant_token):
        """ It requires the ID and token of the tenant."""
        OCRequest.__init__(self)
        self.host_ip = os_pub_ip
        self.tenant_id = tenant_id
        self.tenant_token = tenant_token

    def stack_list(self):
        """
        To get the list of created stacks.
        Return:
            List of all stacks created in the tenant.
        """
        _url = "http://" + self.host_ip + ":8004/v1/" + self.tenant_id + \
            "/stacks"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.tenant_token}
        _body = None

        response = self.request("GET", _url, _headers, _body)

        if response is None:
            LOG_OBJ.error("No response from Server while listing stacks.")
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get stack list Failed with status %s" %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Stack List:%s " % output)
        return output['stacks']

    def stack_show(self, stack_id):
        """
        To get the details of stack
        params :
            stack_id : ID of the stack created
        Return:
            Dict containing the stack details, on success.
        """
        _url = "http://" + self.host_ip + ":8004/v1/" + self.tenant_id + \
            "/stacks/" + stack_id
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.tenant_token}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while showing stack: %s" %
                          stack_id)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Show stack Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Stack Details : %s " % output)
        return output['stack']

    def stack_resource_list(self, stack_name, stack_id=None):
        """
        To get the resources information that are created by stack.
        params :
                tenantName : tenantName where stack created
                stack_name : name of the stack created
        Optional param: stack_id: Id of thestack.
        Return:
            List containing the stack Resources, on success.
        """
        if stack_id is None:
            stack_id = self.get_stack_id(stack_name)
            if not isinstance(stack_id, unicode):
                return

        _url = "http://" + self.host_ip + ":8004/v1/" + self.tenant_id + \
            "/stacks/" + stack_id + "/resources"
        _headers = {'Content-type': 'application/json',
                    'x-auth-token': self.tenant_token}
        _body = None

        response = self.request("GET", _url, _headers, _body)
        if response is None:
            LOG_OBJ.error("No response from Server while getting resources"
                          " of stack: %s" % stack_name)
            return response

        if response.status not in [200, 201, 202, 203, 204]:
            LOG_OBJ.error("Get stack resource list Failed with status %s " %
                          response.status)
            return response.status

        output = json.loads(response.data)
        LOG_OBJ.info("Resource Details of stack: %s is :%s" %
                     (stack_name, output))

        return output['resources']

    def poll_on_stack_status(self, stack_id, status="create"):
        """
        It polls on the stack status.
        params:
            stack_id: ID of the stack.
            status: Which status to check. Default is create.
        Return:
            True, on success.
        """
        loop_count = 30
        output = self.stack_show(stack_id)
        if not isinstance(output, dict):
            return "Stack [%s] is not created" % stack_id

        if status.lower() == 'create':
            # polling for stack CREATE_COMPLETE/UPDATE_COMPLETE
            while output['stack_status'].upper() not in \
                    ["CREATE_COMPLETE", "UPDATE_COMPLETE"] and loop_count:
                LOG_OBJ.debug("Stack creation is not completed. Sleeping for"
                              "10 seconds")
                time.sleep(10)
                output = self.stack_show(stack_id)
                if "CREATE_FAILED" in output['stack_status']:
                    LOG_OBJ.error("Stack creation failed : %s, reason : %s" %
                                  (stack_id, output["stack_status_reason"]))
                    return output["stack_status_reason"]
                loop_count -= 1

            if not loop_count:
                err_msg = "waited for 5 minutes, still stack creation" \
                    " not done. Status : %s" % output['stack_status']
                LOG_OBJ.error(err_msg)
                return err_msg

        LOG_OBJ.debug("Stack: %s is created successfully." % stack_id)
        return True

    def get_stack_id(self, stack_name):
        """
        It gets the stack id of the created stack identified by stack_name.
        params:
            stack_name : name of the stack created
        Return:
            Stack ID (Unicode), on success.
        """
        stacks = self.stack_list()
        if not isinstance(stacks, list):
            return
        for stack in stacks:
            if stack['stack_name'] == stack_name:
                LOG_OBJ.debug("Stack Details : %s " % stack['id'])
                return stack['id']

        LOG_OBJ.error("There is NO stack with this name: %s" % stack_name)
