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

import json
import time
from urllib3 import PoolManager
import atf.lib.nvp_atf_logging as log

LOG_OBJ = log.get_atf_logger()


class OCRequest(object):

    def __init__(self):
        self._pool = PoolManager(num_pools=10)

    def request(self, method, url, headers, body):
        response = None
        conn = self._pool

        LOG_OBJ.debug("Method : %s\nURL : %s\nHeaders : %s\nBody : %s" %
                      (method, url, headers, body))
        retry = 2
        while True:
            try:
                response = conn.urlopen(method, url, body=body,
                                        headers=headers, release_conn=True)
            except Exception as err:
                LOG_OBJ.exception(err)
                return
            try:
                response.release_conn()
            except Exception as err:
                LOG_OBJ.exception(err)
                # return

            if response is None:
                LOG_OBJ.error("No response from the server for method: %s"
                              " and url: %s. \nRetrying once more.\n" %
                              (method, url) + 80 * "*")
                if retry == 0:
                    return
                time.sleep(5)
                retry -= 1
                continue
            if response.status not in [200, 201, 202, 203, 204]:
                try:
                    LOG_OBJ.error("Error while processing the request: %s "
                                  "Response status: %s.\nResponse data: %s "
                                  "\nNow retrying once more...." %
                                  (url, response.status,
                                   json.loads(response.data)))
                except Exception as err:
                    LOG_OBJ.exception(err)
                    # return
                if method == "GET":
                    if retry == 0:
                        LOG_OBJ.error("Several times the GET request"
                                      " is failing. So exiting.")
                        # return
                        break
                    time.sleep(5)
                    retry -= 1
                    continue
                else:
                    break  # return response
            else:
                break  # return response

        return response

    def process_request(self, method, request_url, headers, data):
        """ Perform the REST API call.

        :param method: Type of method (GET/POST/PUT/DELETE)
        :param request_url: Absolute URL of the REST call
        :param headers: HTML headers
        :param data: HTML body

        :return: On Failure: None
                 On success:
                  for method = DELETE: HTTP response
                  for Other methods: HTTP response.data

        """
        retry_count = 3
        while retry_count:
            try:
                conn = self.conn_pool
                response = conn.urlopen(method, request_url, body=data,
                                        headers=headers, release_conn=True)
                response.release_conn()
            except Exception as err:
                LOG_OBJ.exception(err)
                return

            # check whether the request is successful or not.
            if response is None:
                LOG_OBJ.error("No response from the server.")
                return
            try:
                response_status = response.status
                response_data = ""
                LOG_OBJ.debug("Response Status: %s" % response_status)
                LOG_OBJ.debug("Response Data with out json: %s"
                              % (response.data))
                print ("##### %s" % response.data)
                if response.data:
                    response_data = json.loads(response.data)
                LOG_OBJ.debug("Response Data: %s" % response_data)
            except Exception as err:
                LOG_OBJ.exception(err)
                return

            if method != 'GET':
                if response_status not in [200, 201, 202, 203, 204]:
                    return
                if method == 'DELETE':
                    return response
                return response_data
            else:
                # Retry the GET request if it fails due to client error (4xx)
                if response_status > 399 and response_status < 500:
                    time.sleep(5)
                    retry_count -= 1
                    if retry_count == 0:
                        return
                    LOG_OBJ.debug("Retrying once more...")
                    continue
                elif response_status not in [200, 201, 202, 203, 204]:
                    return

                return response_data
