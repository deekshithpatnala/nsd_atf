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
# import sys
import time
import traceback
from urllib3.poolmanager import PoolManager
# sys.path.append("../../")
from atf.lib.request import OCRequest
import atf.lib.nvp_atf_logging as log


LOG_OBJ = log.get_atf_logger()


class gbp_construct(OCRequest):

    def __init__(self, token, host_ip='127.0.0.1'):
        """
        Created new instance for service_insertion object.
        """
        OCRequest.__init__(self)
        self.api_url = "http://%s:9696/v2.0/" % host_ip
        self.nova_url = "http://%s:8774/v2" % host_ip
        self.conn_pool = PoolManager(num_pools=10)
        self.token = token

#     def create_policy_target_group_provider(self, **kwargs):
#         """
#         It creates the connectivity group.
#         Args: subnetid, name, description
#         """
#         request_url = "%s/grouppolicy/policy_target_groups.json" %\
#             self.api_url
#
#         headers = {
#             'Content-type': 'application/json;charset=utf8',
#             'Accept': 'application/json',
#             'x-auth-token': self.token
#         }
#
#         data = {
#             "policy_target_group": {
# "subnets": kwargs["subnets"],
#                 "l2_policy_id": kwargs["l2_policy_id"],
#                 "provided_policy_rule_sets": kwargs[
#                                                 "provided_policy_rule_sets"]
#             }
#         }
#         for argument in ["name", "description"]:
#             try:
#                 data["policy_target_group"].update(
#                     {argument: kwargs[argument]})
#             except KeyError:
#                 pass
#         if kwargs.get("tenant_id"):
#             data["policy_target_group"].update(
#                 {"tenant_id": kwargs["tenant_id"]})
#
#         try:
#             resp = self.process_request("POST", request_url, headers,
#                                         json.dumps(data))
#             print "response is:", resp
#         except Exception as err:
#             LOG_OBJ.error("Exception occured while creating"
#                                " conectivity group: %s" % err)
#             return
#
#         if resp is None:
#             LOG_OBJ.error("Failed to create connectivity group.")
#             return
#
#         LOG_OBJ.debug("Connectivity group is created successfully")
#         return resp["policy_target_group"]
#
#     def create_policy_target_group_consumer(self, **kwargs):
#         """
#         It creates the connectivity group.
#         Args: subnetid, name, description
#         """
#         request_url = "%s/grouppolicy/policy_target_groups.json" %\
#             self.api_url
#
#         headers = {
#             'Content-type': 'application/json;charset=utf8',
#             'Accept': 'application/json',
#             'x-auth-token': self.token
#         }
#         data = {
#             "policy_target_group": {
# "subnets": kwargs["subnets"],
#                 "l2_policy_id": kwargs["l2_policy_id"],
#                 "consumed_policy_rule_sets": kwargs[
#                                                 "consumed_policy_rule_sets"]
#             }
#         }
#         for argument in ["name", "description"]:
#             try:
#                 data["policy_target_group"].update(
#                     {argument: kwargs[argument]})
#             except KeyError:
#                 pass
#         if kwargs.get("tenant_id"):
#             data["policy_target_group"].update(
#                 {"tenant_id": kwargs["tenant_id"]})
#
#         try:
#             resp = self.process_request("POST", request_url, headers,
#                                         json.dumps(data))
#
#         except Exception as err:
#             LOG_OBJ.error("Exception occured while creating"
#                                " conectivity group: %s" % err)
#             return
#
#         if resp is None:
#             LOG_OBJ.error("Failed to create connectivity group.")
#             return
#
#         LOG_OBJ.debug("Connectivity group is created successfully")
#         return resp["policy_target_group"]

    def create_policy_target_group(self, name, **kwargs):
        """
        It creates the connectivity group.
        Required Args: name
        Optional args :
                 description
                 subnets
                 l2_policy_id
                 tenant_id,
                 network_service_policy_id
        """
        request_url = "%s/grouppolicy/policy_target_groups.json" % \
            self.api_url

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_target_group": {
            "name": name
        }
        }

        if kwargs.get("consumed_policy_rule_sets"):
            data["policy_target_group"]["consumed_policy_rule_sets"] = \
                kwargs["consumed_policy_rule_sets"]
        elif kwargs.get("provided_policy_rule_sets"):
            data["policy_target_group"]["provided_policy_rule_sets"] = \
                kwargs["provided_policy_rule_sets"]

        for argument in ["description", "tenant_id", "subnets",
                         "l2_policy_id", "network_service_policy_id"]:
            try:
                data["policy_target_group"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.exception(err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create connectivity group.")
            return

        LOG_OBJ.debug("Connectivity group is created successfully")
        return resp['policy_target_group']

    def update_policy_target_group(self, group_id, name, **kwargs):
        """
        It Updates the policy target group.
        Required Args: group_id (policy_target_group id), name
        Optional Args: description,
        """
        request_url = ("%s/grouppolicy/policy_target_groups/%s.json" %
                       (self.api_url, group_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_target_group": {
                "name": name
                }
                }
        for argument in ["description", "provided_policy_rule_sets",
                         "consumed_policy_rule_sets",
                         "network_service_policy_id"]:
            try:
                data["policy_target_group"].update({argument:
                                                    kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occurred while updating"
                          " policy target group: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update policy target group:%s" %
                          group_id)
            return

        LOG_OBJ.debug("Updated policy target group:%s Successfully" %
                      group_id,)
        return resp["policy_target_group"]

    def show_policy_target_group(self, group_id):
        """
        On success it returns the dictionary containing the connectivity
        group details.
        Positional Argsments : id (connectitvity group id)
        """
        request_url = ("%s/grouppolicy/policy_target_groups/%s.json" %
                       (self.api_url, group_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to show connectivity group: %s " %
                              group_id)
                return

            return data['policy_target_group']

        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " connectivity group: %s" % err)
            return

    def list_policy_target_group(self):
        """
        On success it returns the LIST of dictionaries containing details of
        policy target groups.
        """
        request_url = ("%s/grouppolicy/policy_target_groups.json" %
                       (self.api_url))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list policy target group.")
                return

            return data['policy_target_groups']

        except Exception as err:
            LOG_OBJ.error("Exception occurred in listing"
                          " policy target groups: %s" % err)
            return

    def delete_policy_target_group(self, group_id):
        """
        On success it delete the policy target group.
        Positional Argsments : id (policy target group id)
        """
        request_url = ("%s/grouppolicy/policy_target_groups/%s.json" %
                       (self.api_url, group_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers, None)
        except Exception as err:
            LOG_OBJ.error("Exception occurred while deleting"
                          " policy target group: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to delete policy target group: %s " %
                          group_id)
            return
        LOG_OBJ.debug("Deleted policy target group:%s successfully" %
                      group_id)
        return True

    def create_policy_target(self, name, **kwargs):
        """
        It creates the policy target.
        Required Args: name
        Optional Args : description
                        tenant_id
                        policy_target_group_id
                        port_id
        """
        request_url = "%s/grouppolicy/policy_targets.json" % (
            self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {
            "policy_target": {
                "name": name
            }
        }
        for argument in ["description", "tenant_id",
                         "policy_target_group_id", "port_id"]:
            try:
                data["policy_target"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occurred while creating"
                          " policy target: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create policy target")
            return
        LOG_OBJ.debug("Created policy target successfully")
        return resp['policy_target']

    def update_policy_target(self, target_id, **kwargs):
        """
        It will updates policy targets.
        Required Args: target_id (id of policy target)
        Optional Args:
            name
            description
        """
        request_url = ("%s/grouppolicy/policy_targets/%s.json" %
                       (self.api_url, target_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {
            "policy_target": {}
            }
        for argument in ["name", "description"]:
            try:
                data["policy_target"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occurred while updating policy"
                          " target group.\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update policy target %s" % target_id)
            return

        LOG_OBJ.debug("Successfully Updated policy target: %s" % target_id)
        return resp["policy_target"]

    def show_policy_target(self, target_id):
        """
        It gives the details of the policy target.
        Required Args: id (policy_target id)
        """
        request_url = ("%s/grouppolicy/policy_targets/%s.json" %
                       (self.api_url, target_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to show details of policy target"
                              ": %s " % target_id)
                return

            return data['policy_target']

        except Exception as err:
            LOG_OBJ.error("Exception occurred in show"
                          " policy target: %s" % err)
            return

    def list_policy_target(self):
        """
        It list all policy targets.
        """
        request_url = ("%s/grouppolicy/policy_targets.json" %
                       (self.api_url))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list policy targets.")
                return

            return data['policy_targets']

        except Exception as err:
            LOG_OBJ.error("Exception occurred in list"
                          " Policy Targets: %s" % err)
            return

    def delete_policy_target(self, target_id):
        """
        It deletes the policy target.
        Required Args: id (policy_target id)
        """
        request_url = "%s/grouppolicy/policy_targets/%s.json" % (
            self.api_url, target_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers, None)
        except Exception as err:
            LOG_OBJ.error("Exception occured while deleting"
                          " policy target: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to delete policy target: %s" %
                          target_id)
            return
        LOG_OBJ.debug("Deleted policy target: %s successfully" %
                      target_id)
        return True

    def create_policy_classifier(self, name, **kwargs):
        """
        It creates the classifier
        Required Args: name
        Optional Args : description
                        tenant_id
                        direction
                        port_range
                        protocol
        """
        request_url = ("%s/grouppolicy/policy_classifiers.json" %
                       self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_classifier": {"name": name}}
        for argument in ["description", "tenant_id", "direction",
                         "port_range", "protocol"]:
            try:
                data["policy_classifier"].update({argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.exception(err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create classifier")
            return
        LOG_OBJ.debug("Created classifier successfully")
        return resp["policy_classifier"]

    def delete_policy_classifier(self, classifier_id):
        """
        It deletes the classifier.
        Required Args: id (id of classifier)
        """
        request_url = "%s/grouppolicy/policy_classifiers/%s.json" % (
            self.api_url, classifier_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers, None)
        except Exception as err:
            LOG_OBJ.error("Exception occured while deleting"
                          " classifier: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to delete classifier: %s" %
                          classifier_id)
            return
        LOG_OBJ.debug("Deleted Classifier: %s successfully" %
                      classifier_id)
        return True

    def update_policy_classifier(self, classifier_id, **kwargs):
        """
        It updates classifier.
        Required Args: id (id of classifier)
        Optional Args : name
                        description
                        direction
                        port_range
                        protocol
        """
        request_url = ("%s/grouppolicy/policy_classifiers/%s.json" %
                       (self.api_url, classifier_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_classifier": {}}

        for argument in ["name", "description", "direction",
                         "port_range", "protocol"]:
            try:
                data["policy_classifier"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while updating"
                          " classifier: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update classifier: %s" %
                          classifier_id)
            return
        LOG_OBJ.debug("Updated Classifier: %s successfully" %
                      classifier_id)
        return resp["policy_classifier"]

    def show_policy_classifier(self, classifier_id):
        """
        It gives the details of classifier.
        Required Args: id (id of classifier)
        """
        request_url = ("%s/grouppolicy/policy_classifiers/%s.json" %
                       (self.api_url, classifier_id))
        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)

            if data is None:
                LOG_OBJ.error("Failed to show classifier: %s " %
                              classifier_id)
                return

            return data['policy_classifier']

        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " classifier: %s" % err)
            print (" %s" % traceback.format_exc())
            return

    def list_policy_classifier(self):
        """
        It lists all the policy classifiers .
        """
        request_url = ("%s/grouppolicy/policy_classifiers.json" %
                       (self.api_url))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list policy classifiers.")
                return

            return data['policy_classifiers']

        except Exception as err:
            LOG_OBJ.error("Exception occured in list"
                          " classifier: %s" % err)
            return

    def create_policy_action(self, name, **kwargs):
        """
        It creates the action
        Required Args: name
        Optional Args : description
                        tenant_id
                        action_type
                        action_value
        """
        request_url = "%s/grouppolicy/policy_actions.json" % (
            self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_action": {
                "name": name
                }
                }
        for argument in ["description", "tenant_id", "action_type",
                         "action_value"]:
            try:
                data["policy_action"].update({argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while creating"
                          " Policy Action: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create Policy Action")
            return
        LOG_OBJ.debug("Created Policy Action successfully")
        return resp["policy_action"]

    def update_policy_action(self, action_id, **kwargs):
        """
        It updates the action.
        Required Args: id (Id of action)
        Optional Args : name
        """
        request_url = ("%s/grouppolicy/policy_actions/%s.json" %
                       (self.api_url, action_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_action": {}}
        for argument in ["name", "description", "action_type",
                         "action_value"]:
            try:
                data["policy_action"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while updating"
                          " Policy Action: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update Policy Action: %s" %
                          action_id)
            return
        LOG_OBJ.debug("Updated Policy Action: %s successfully" %
                      action_id)
        return resp["policy_action"]

    def show_policy_action(self, action_id):
        """
        It gives the details of action.
        Required Args: id (Id of the action)
        """
        request_url = ("%s/grouppolicy/policy_actions/%s.json" %
                       (self.api_url, action_id))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to show POlicy Action: %s " %
                              action_id)
                return

            return data['policy_action']

        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " Policy Action: %s" % err)
            return

    def list_policy_action(self):
        """
        It list all the action of tenant
        """
        request_url = ("%s/grouppolicy/policy_actions.json" %
                       (self.api_url))

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            data = self.process_request('GET', request_url, headers, None)
            if data is None:
                LOG_OBJ.error("Failed to list Policy Actions.")
                return

            return data['policy_actions']

        except Exception as err:
            LOG_OBJ.error("Exception occured in list"
                          " Policy Actions: %s " % err)
            return

    def delete_policy_action(self, action_id):
        """
        It deletes the action
        Required Args: id( Id of a action)
        """
        request_url = "%s/grouppolicy/policy_actions/%s.json" % (
            self.api_url, action_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers, None)
        except Exception as err:
            LOG_OBJ.error("Exception occured while deleting"
                          " Policy Action: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to delete Policy Action: %s" %
                          action_id)
            return
        LOG_OBJ.debug("Deleted Policy Action: %s successfully" %
                      action_id)
        return True

    def create_policy_rule(self, name, **kwargs):
        """
        It creates Policy rule
        Positional Args: name
        Optional Args: description
                       tenant_id
                       enabled
                       policy_classifier_id,
                       policy_actions (action id list)
        """
        request_url = "%s/grouppolicy/policy_rules.json"\
                      % self.api_url

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_rule": {
                "name": name
                }
                }

        for argument in ["description", "tenant_id", "enabled",
                         "policy_classifier_id", "policy_actions"]:
            try:
                data["policy_rule"].update({argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while creating policy "
                          "rule:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Policy Rule Creation failed")
            return

        LOG_OBJ.debug("Policy Rule Created Successfully")
        return resp["policy_rule"]

    def list_policy_rule(self):
        """
        It lists all the Policy Rules of a tenant
        """
        request_url = "%s/grouppolicy/policy_rules.json"\
            % self.api_url

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Excption in list policy "
                          "rule:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("List Policy Rule Failed")
            return

        LOG_OBJ.debug("Policy Rule List Successful")
        return resp["policy_rules"]

    def show_policy_rule(self, policy_rule_id):
        """
        It gives the details of action.
        Positional Args: policy_rule_id
        """
        request_url = "%s/grouppolicy/policy_rules/%s.json"\
            % (self.api_url, policy_rule_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in show policy "
                          "rule:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Policy Rule %s Show Failed"
                          % policy_rule_id)
            return

        LOG_OBJ.debug("Policy Rule %s Show Successful"
                      % policy_rule_id)
        return resp["policy_rule"]

    def update_policy_rule(self, policy_rule_id, **kwargs):
        """
        It updates the Policy Rule
        Positional Args: policy_rule_id
        Optional Args : name
                        description
                        policy_classifier_id
                        policy_actions
                        enabled
        """
        request_url = "%s/grouppolicy/policy_rules/%s.json"\
            % (self.api_url, policy_rule_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"policy_rule": {}}

        for argument in ["name", "description",
                         "policy_classifier_id", "policy_actions",
                         "enabled"]:
            try:
                data["policy_rule"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception in update policy "
                          "rule:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Policy Rule: %s Update Failed"
                          % policy_rule_id)
            return

        LOG_OBJ.debug("Policy Rule: %s Update Successfully"
                      % policy_rule_id)
        return resp["policy_rule"]

    def delete_policy_rule(self, policy_rule_id):
        """
        It deletes the Policy Rule
        Positional Args: policy_rule_id
        """
        request_url = "%s/grouppolicy/policy_rules/%s.json"\
            % (self.api_url, policy_rule_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in Delete Policy "
                          "Rule:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Policy Rule %s Delete Failed"
                          % policy_rule_id)
            return

        LOG_OBJ.debug("Policy Rule %s Deleted Successfully"
                      % policy_rule_id)
        return True

    def create_policy_rule_set(self, name, **kwargs):
        """
        It creates Policy rule set
        Positional Args: name
        Optional Args: tenant_id
                       description
                       policy-rules
                       child_policy_rule_sets (id list),
        """
        request_url = "%s/grouppolicy/policy_rule_sets.json"\
            % (self.api_url)

        headers = {'Content-type': 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"policy_rule_set": {
                "name": name
                }
                }

        for argument in ["tenant_id", "description",
                         "policy_rules", "child_policy_rule_sets"]:
            try:
                data["policy_rule_set"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while creating"
                          " policy rule set: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create policy rule set")
            return

        LOG_OBJ.debug("Created Policy Rule Set Successfully")
        return resp["policy_rule_set"]

    def list_policy_rule_set(self):
        """
        It will list policy rule sets
        """
        request_url = "%s/grouppolicy/policy_rule_sets.json"\
            % (self.api_url)

        headers = {'Content-type': 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            data = self.process_request('GET', request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception occured in list"
                          " policy rule set: %s" % err)
            return

        if data is None:
            LOG_OBJ.error("Failed to list policy rule set")
            return

        return data['policy_rule_sets']

    def show_policy_rule_set(self, policy_rule_set_id):
        """
        It gives the details of policy_rule_set
        Positional Args: policy_rule_set_id
        """
        request_url = "%s/grouppolicy/policy_rule_sets/%s.json"\
            % (self.api_url, policy_rule_set_id)

        headers = {'Content-type': 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            data = self.process_request('GET', request_url, headers, None)
        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " policy rule set: %s" % err)
            return

        if data is None:
            LOG_OBJ.error("Failed to show policy rule sets:%s" %
                          policy_rule_set_id)
            return

        LOG_OBJ.debug("Policy Rule Set Show Successful")
        return data['policy_rule_set']

    def update_policy_rule_set(self, policy_rule_set_id, **kwargs):
        """
        It updates the details of policy rule set
        Positional Args: policy_rule_set_id
        Optional Args: name
                       description
                       child_policy_rule_sets
                       policy_rules
        """
        request_url = "%s/grouppolicy/policy_rule_sets/%s.json"\
            % (self.api_url, policy_rule_set_id)

        headers = {'Content-type': 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"policy_rule_set": {}}

        for argument in ["name", "description",
                         "child_policy_rule_sets", "policy_rules"]:
            try:
                data["policy_rule_set"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while updating policy"
                          "rule set:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Policy Rule Set: %s Update Failed" %
                          policy_rule_set_id)
            return

        LOG_OBJ.debug("Policy Rule Set: %s Updated Successfully" %
                      policy_rule_set_id)
        return resp["policy_rule_set"]

    def delete_policy_rule_set(self, policy_rule_set_id):
        """
        It deletes the policy rule set
        Positional Args: policy_rule_set_id
        """
        request_url = "%s/grouppolicy/policy_rule_sets/%s.json"\
            % (self.api_url, policy_rule_set_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ("Excption while Deleting policy rule set:\n %s"
                    % err)
            return

        if resp is None:
            LOG_OBJ.error("Policy Rule Set Deletion failed: %s"
                          % policy_rule_set_id)
            return

        LOG_OBJ.debug("Policy Rule Set: %s Deleted Successfully"
                      % policy_rule_set_id)
        return True

    def create_service_chain_node(self, name, **kwargs):
        """
        It creates the service chain node
        positional arguments: name
        optional arguments: description
                            tenant_id
                            service_type
                            config
                            template_file
                            param-names
                            service_profile_id,
                            shared
        """
        request_url = "%s/servicechain/servicechain_nodes.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"servicechain_node": {"name": name}}
        if kwargs.get("config"):
            data["servicechain_node"].update({"config": kwargs["config"]})
        elif kwargs.get("template_file"):
            data["servicechain_node"].update(
                {"template_file": kwargs["template_file"]})
        else:
            return "Either config or template-file must be provided. "

        for argument in ["description", "tenant_id", "service_type",
                         "param-names", "service_profile_id", "shared"]:
            try:
                data["servicechain_node"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while creating service chain "
                          "node:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Node Creation Failed")
            return

        LOG_OBJ.debug("Service Chain Node Created Successfully")
        return resp["servicechain_node"]

    def list_service_chain_node(self):
        """
        It will list service chain nodes
        """
        request_url = "%s/servicechain/servicechain_nodes.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception while listing service chain "
                          "nodes:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Node List Failed")
            return

        return resp['servicechain_nodes']

    def show_service_chain_node(self, service_chain_node_id):
        """
        It will show details of the service chain nodes
        Arguments: service_chain_node_id
        """

        request_url = "%s/servicechain/servicechain_nodes/%s.json"\
            % (self.api_url, service_chain_node_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Excption in show service chain "
                          "node:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Show Service chain node %s Failed"
                          % service_chain_node_id)
            return

        LOG_OBJ.debug("Service Chain Node: %s Show Successful"
                      % service_chain_node_id)
        return resp["servicechain_node"]

    def update_service_chain_node(self, service_chain_node_id, **kwargs):
        """
        It updates the details of Service Chain Node
        Positional Args: service_chain_node_id.
        """
        request_url = "%s/servicechain/servicechain_nodes/%s.json"\
            % (self.api_url, service_chain_node_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"servicechain_node": {}}

        for argument in ["name", "description", "servicetype", "config"]:
            try:
                data["servicechain_node"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Excption in update service "
                          "chain node:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Update Service Chain Node %s failed"
                          % service_chain_node_id)
            return

        LOG_OBJ.debug("Service Chain Node %s Updated Successfully"
                      % service_chain_node_id)
        return resp["servicechain_node"]

    def delete_service_chain_node(self, service_chain_node_id):
        """
        It will Delete service chain node.
        Positional Args: service_chain_node_id
        """
        request_url = "%s/servicechain/servicechain_nodes/%s.json"\
            % (self.api_url, service_chain_node_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception while deleting service chain "
                          "node:\n%s"
                          % (err))
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Node %s Deletion failed"
                          % service_chain_node_id)
            return

        LOG_OBJ.debug("Service Chain Node %s Deleted Successfully"
                      % service_chain_node_id)
        return True

    def create_service_chain_spec(self, name, **kwargs):
        """
        It creates the service chain spec
        positional arguments: name
        optional arguments: description
                            tenant_id
                            nodes (node id list),
                            shared
        """
        request_url = "%s/servicechain/servicechain_specs.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"servicechain_spec": {"name": name}}

        for argument in ["tenant_id", "description", "nodes", "shared"]:
            try:
                data["servicechain_spec"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while creating service chain "
                          "spec:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Spec Creation Failed")
            return

        LOG_OBJ.debug("Servie Chain Spec Created Succeesfully")
        return resp["servicechain_spec"]

    def list_service_chain_spec(self):
        """
        It will list all service chain specs
        """
        request_url = "%s/servicechain/servicechain_specs.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception while list service chain "
                          "node:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Spec List failed")
            return

        LOG_OBJ.debug("Service Chain Spec List Successful")
        return resp["servicechain_specs"]

    def show_service_chain_spec(self, service_chain_spec_id):
        """
        It gives the details of Service Chain Spec
        Positional Args: service_chain_spec_id
        """
        request_url = "%s/servicechain/servicechain_specs/%s.json"\
            % (self.api_url, service_chain_spec_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in Show Service Chain "
                          "Node:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Spec %s Show Failed"
                          % service_chain_spec_id)
            return

        LOG_OBJ.debug("Service Chain Spec %s Show Successful"
                      % service_chain_spec_id)
        return resp["servicechain_spec"]

    def update_service_chain_spec(self, service_chain_spec_id, **kwargs):
        """
        It updates the details of Service Chain Spec
        Positional Args: service_chain_spec_id
        Optional Args: name
                       description
                       tenant_id
                       nodes
                       config_param_names
        """
        request_url = "%s/servicechain/servicechain_specs/%s.json"\
            % (self.api_url, service_chain_spec_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"servicechain_spec": {}}

        for argument in ["name",
                         "description",
                         "tenant_id",
                         "nodes",
                         "config_param_names"
                         ]:
            try:
                data["servicechain_spec"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while updating service "
                          "chain spec:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Service Chain Spec: %s Update failed"
                          % service_chain_spec_id)
            return

        LOG_OBJ.debug("Service Chain Spec %s Updated Successfully"
                      % service_chain_spec_id)
        return resp["servicechain_spec"]

    def delete_service_chain_spec(self, service_chain_spec_id):
        """
        It deletes the Service Chain Spec
        Positional Args: service_chain_spec_id
        """
        request_url = "%s/servicechain/servicechain_specs/%s.json"\
            % (self.api_url, service_chain_spec_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception while Deleting Service Chain "
                          "Spec:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Sevice Chain Spec %s Deletion Failed"
                          % service_chain_spec_id)
            return

        LOG_OBJ.debug("Service Chain Spec %s Deleted Successfully"
                      % service_chain_spec_id)
        return True

    def create_l2policy(self, name, **kwargs):
        """
        It creates the l2policy
        positional arguments: name
        optional arguments: tenant_id,
                            description
                            network_id
                            l3_policy_id
        """
        request_url = "%s/grouppolicy/l2_policies.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"l2_policy": {"name": name}}

        for argument in ["description",
                         "tenant_id",
                         "network_id", "l3_policy_id"]:
            try:
                data["l2_policy"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception While Creating l2policy:\n %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("L2policy Creation Failed")
            return

        LOG_OBJ.debug("L2Policy Created Successfully")
        return resp["l2_policy"]

    def list_l2policy(self):
        """
        It will list all l2policies created
        """
        request_url = "%s/grouppolicy/l2_policies.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in list l2policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("L2Policy List Failed")
            return

        LOG_OBJ.debug("L2Policies Listed Successfully")
        return resp["l2_policies"]

    def show_l2policy(self, l2_policy_id):
        """
        It gives the details of l2policy
        Positional Args: l2_policy_id
        """
        request_url = "%s/grouppolicy/l2_policies/%s.json"\
            % (self.api_url, l2_policy_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in show l2policy:\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("L2Policy %s Show Failed"
                          % l2_policy_id)
            return

        LOG_OBJ.debug("L2Policy %s Show Successful"
                      % l2_policy_id)
        return resp["l2_policy"]

    def update_l2policy(self, l2_policy_id, **kwargs):
        """
        It updates the details of l2policy
        Positional Args: l2_policy_id
        """
        request_url = "%s/grouppolicy/l2_policies/%s.json"\
            % (self.api_url, l2_policy_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"l2_policy": {}}

        for argument in ["name", "description", "l3_policy_id"]:
            try:
                data["l2_policy"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while updating l2policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("L2Policy %s Updation Failed"
                          % l2_policy_id)
            return

        LOG_OBJ.debug("L2Policy %s Updated Successfully"
                      % l2_policy_id)
        return resp["l2_policy"]

    def delete_l2policy(self, l2_policy_id):
        """
        It deletes the l2policy
        Positional Args: l2_policy_id
        """
        request_url = "%s/grouppolicy/l2_policies/%s.json"\
            % (self.api_url, l2_policy_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception while deleting l2policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("L2Policy %s Delete Failed"
                          % l2_policy_id)
            return

        LOG_OBJ.debug("L2Policy %s Deleted Successfully"
                      % l2_policy_id)
        return True

    def create_l3policy(self, name, **kwargs):
        """
        It creates the l3policy
        positional arguments: name
        optional arguments: description
                            tenant_id
                            subnet_prefix_length
                            ip_pool
                            ip_version
                            external_segments
        """
        request_url = "%s/grouppolicy/l3_policies.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"l3_policy": {"name": name}}

        for argument in ["description", "subnet_prefix_length",
                         "ip_pool", "ip_version", "external_segments",
                         "tenant_id"]:
            try:
                data["l3_policy"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception while creating l3policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Create L3policy Failed")
            return

        LOG_OBJ.debug("L3Policy Created Successfully")
        return resp["l3_policy"]

    def list_l3policy(self):
        """
        It list all the l3policies
        """
        request_url = "%s/grouppolicy/l3_policies.json"\
            % self.api_url

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in list l3policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("List L3policy Failed.")
            return

        LOG_OBJ.debug("List L3poilcy Successful")
        return resp["l3_policies"]

    def show_l3policy(self, l3policy_id):
        """
        It gives the details of l3policy
        Positional Args: l3policy_id
        """
        request_url = "%s/grouppolicy/l3_policies/%s.json"\
            % (self.api_url, l3policy_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("GET", request_url, headers, None)
        except Exception as err:
            LOG_OBJ.error("Exception in show l3policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("L3policy %s Show Failed"
                          % l3policy_id)
            return

        LOG_OBJ.debug("L3policy %s Show Successful"
                      % l3policy_id)
        return resp["l3_policy"]

    def update_l3policy(self, l3policy_id, **kwargs):
        """
        It updates the details of l3policy
        Positional Args: l3policy_id
        Optional Args: name
                       description
                       ip-version
                       subnet-prefix-length
                       external-segment
        """
        request_url = "%s/grouppolicy/l3_policies/%s.json"\
            % (self.api_url, l3policy_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        data = {"l3_policy": {}}

        for argument in ["name", "description", "external_segments",
                         "ip_version", "l2_policies",
                         "subnet_prefix_length"]:
            try:
                data["l3_policy"].update({argument: kwargs[argument]})
            except KeyError:
                pass

        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception in update l3policy:"
                          "\n%s" % err)
            return

        if resp is None:
            LOG_OBJ.error("l3policy %s updation Failed"
                          % l3policy_id)
            return

        LOG_OBJ.debug("L3policy %s Updated Successfully"
                      % l3policy_id)
        return resp["l3_policy"]

    def delete_l3policy(self, l3policy_id):
        """
        It deletes the l3policy
        Positional Args: l3policy_id
        """
        request_url = "%s/grouppolicy/l3_policies/%s.json"\
            % (self.api_url, l3policy_id)

        headers = {"Content-type": 'application/json;charset=utf8',
                   'Accept': 'application/json',
                   'x-auth-token': self.token
                   }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
        except Exception as err:
            LOG_OBJ.error("Exception in Delete l3policy:"
                          "\n%" % err)
            return

        if resp is None:
            LOG_OBJ.error("L3policy %s Deletion Failed"
                          % l3policy_id)
            return

        LOG_OBJ.debug("L3Policy %s Deleted Successfully"
                      % l3policy_id)
        return True

    def create_server(self, **kwargs):
        """
        It creates the service vm.
        Required Args: tenant_id, name, image_id,
        Optional Args : name, description, security_groups, availability_zone
        """
        request_url = self.nova_url + "/" + kwargs["tenant_id"] + "/servers"
        request_headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        server_info = {"server": {
            "name": kwargs["name"],
            "imageRef": kwargs["image_id"],
            "flavorRef": "2",
            "networks": []
        }
        }
        if kwargs.get("security_groups"):
            server_info["server"]["security_groups"].append(
                {"security_groups": kwargs["security_groups"]})

        server_info["server"]["networks"] = eval(kwargs["net_info"])
        if kwargs.get("availability_zone"):
            server_info["server"].update(
                {"availability_zone": "nova:" +
                 kwargs.get("availability_zone")})
        if kwargs["tenant_id"]:
            server_info["server"]["tenant_id"] = kwargs["tenant_id"]

        try:
            server = self.process_request("POST", request_url, request_headers,
                                          json.dumps(server_info))
        except Exception as err:
            LOG_OBJ.error("Exception occured while creating"
                          " Server: %s" % err)
            return

        if server is None:
            LOG_OBJ.error("Failed to create server in tenant: %s" %
                          kwargs["tenant_id"])
            return
        LOG_OBJ.debug("Created server in tenant: %s successfully" %
                      kwargs["tenant_id"])
        return server

############################################

    def poll_on_resource_status(self, **kwargs):
        """
        It polls the creation or deltion of service resource
        like connectivity group, action, rule...etc.
        Required kwargs:
        name, id, status, monitor_duration (in sec), negative_status
        """
        start = time.time()
        try:
            while True:
                time.sleep(5)
                try:
                    resource = getattr(self, "show_%s" % kwargs['name'])(
                        id=kwargs['id']
                    )
                except AttributeError as err:
                    LOG_OBJ.error("'%s' is not a valid resource name,"
                                  " error: %s" % (kwargs['name'], err))
                    raise

                try:
                    status = resource['status'].upper()
                except (TypeError, KeyError) as err:
                    LOG_OBJ.info(
                        "show_%s failed, error: %s, %s_info: %r" %
                        (kwargs['name'], err, kwargs['name'], resource))
                    return

                if status in [kwargs['status'].upper(),
                              kwargs['negative_status'].upper()]:
                    LOG_OBJ.info("%s %s become %s" %
                                 (kwargs['name'].upper(), kwargs['id'],
                                  status))
                    return status

                now = time.time()
                if now - start >= kwargs['monitor_duration']:
                    LOG_OBJ.info("%s %s doesn't become %s"
                                 " in %d sec. The current status: %s" %
                                 (kwargs['name'].upper(),
                                  kwargs['id'],
                                  kwargs['status'].upper(),
                                  kwargs['monitor_duration'],
                                  status))
                    return status

        except Exception:
            print "\nAn exception occured in poll_on_resource_status."\
                "\n%s" % traceback.format_exc()
            LOG_OBJ.debug(
                "\nAn exception occured in poll_on_resource_status."
                "\n%s" % traceback.format_exc())
            return

    def create_network_service_policy(self, name, **kwargs):
        """
        It creates the network service policy
        Required Args: name
        Optional Args :
              description
              tenant_id
              network_service_params: [{"type": "", "name": "", "value": ""}]
        """
        request_url = "%s/grouppolicy/network_service_policies.json" % (
            self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"network_service_policy": {
                "name": name
                }
                }

        for argument in ["description", "tenant_id", "network_service_params"]:
            try:
                data["network_service_policy"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while creating"
                          " network_service_policy: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create network_service_policy")
            return

        LOG_OBJ.debug("Created network_service_policy successfully")
        return resp["network_service_policy"]

    def update_network_service_policy(self, name, policy_id, **kwargs):
        """
        It updates the network service policy
        Required Args: name, network_service_policy id
        Optional Args :
              description
              network_service_params: [{"type": "", "name": "", "value": ""}]
        """
        request_url = "%s/grouppolicy/network_service_policies/%s.json" % (
                      self.api_url, policy_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"network_service_policy": {
                "name": name
                }
                }

        for argument in ["description", "network_service_params"]:
            try:
                data["network_service_policy"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while updating"
                          " network_service_policy: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update network_service_policy: %s "
                          % policy_id)
            return

        LOG_OBJ.debug("Updated network_service_policy successfully")
        return resp["network_service_policy"]

    def show_network_service_policy(self, policy_id):
        """
        It updates the network service policy
        Required Args: network_service_policy id
        """
        request_url = "%s/grouppolicy/network_service_policies/%s.json" % (
                      self.api_url, policy_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to show network_service_policy: %s"
                              % policy_id)
                return

            return resp["network_service_policy"]

        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " network_service_policy: %s" % err)
            return

    def list_network_service_policy(self):
        """
        It lists all the network service policies.
        """
        request_url = "%s/grouppolicy/network_service_policies.json" % (
                      self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to list network service policies.")
                return

            return resp["network_service_policies"]

        except Exception as err:
            LOG_OBJ.error("Exception occured in list"
                          " network_service_policies: %s" % err)
            return

    def delete_network_service_policy(self, policy_id):
        """
        It deletes the network service policy
        Required Args: network_service_policy id
        """
        request_url = "%s/grouppolicy/network_service_policies/%s.json" % (
                      self.api_url, policy_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to delete network_service_policy:"
                              " %s" % policy_id)
                return

            return True

        except Exception as err:
            LOG_OBJ.error("Exception occured in delete"
                          " network_service_policy: %s" % err)
            return

    def create_external_policy(self, name, **kwargs):
        """
        It creates the external policy
        Required Args: name
        Optional Args :
              description
              tenant_id
              external_segments
              provided_policy_rule_sets
              consumed_policy_rule_sets
              shared
        """
        request_url = "%s/grouppolicy/external_policies.json" % (
            self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"external_policy": {
                "name": name
                }
                }

        for argument in ["description", "tenant_id", "external_segments",
                         "provided_policy_rule_sets",
                         "consumed_policy_rule_sets", "shared"]:
            try:
                data["external_policy"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while creating"
                          " external_policy: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create external_policy")
            return

        LOG_OBJ.debug("Created external_policy successfully")
        return resp["external_policy"]

    def update_external_policy(self, external_policy_id, **kwargs):
        """
        It updates the external_policy
        Required Args: external_policy id
        Optional Args :
              name
              description
              external_segments
              provided_policy_rule_sets
              consumed_policy_rule_sets
              shared
        """
        request_url = "%s/grouppolicy/external_policies/%s.json" % (
                      self.api_url, external_policy_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"external_policy": {}}

        for argument in ["name", "description", "tenant_id",
                         "external_segments",
                         "provided_policy_rule_sets",
                         "consumed_policy_rule_sets", "shared"]:
            try:
                data["external_policy"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while updating"
                          " external_policy: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update external_policy: %s "
                          % external_policy_id)
            return

        LOG_OBJ.debug("Updated external policy successfully")
        return resp["external_policy"]

    def show_external_policy(self, external_policy_id):
        """
        It updates the external_policy
        Required Args: external_policy id
        """
        request_url = "%s/grouppolicy/external_policies/%s.json" % (
                      self.api_url, external_policy_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to show external_policy: %s"
                              % external_policy_id)
                return

            return resp["external_policy"]

        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " external_policy: %s" % err)
            return

    def list_external_policy(self):
        """
        It lists all the external_policies
        """
        request_url = "%s/grouppolicy/external_policies.json" % (
                      self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to list external_policies")
                return

            return resp["external_policies"]

        except Exception as err:
            LOG_OBJ.error("Exception occured in list"
                          " external_policies: %s" % err)
            return

    def delete_external_policy(self, external_policy_id):
        """
        It deletes the external_policy
        Required Args: external_policy id
        """
        request_url = "%s/grouppolicy/external_policies/%s.json" % (
                      self.api_url, external_policy_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to delete external_policy:"
                              " %s" % external_policy_id)
                return

            return True

        except Exception as err:
            LOG_OBJ.error("Exception occured in delete"
                          " external_policy: %s" % err)
            return

    def create_external_segment(self, name, **kwargs):
        """
        It creates the external policy
        Required Args: name
        Optional Args :
              description
              tenant_id
              ip-version
              subnet_id
              cidr
              external-route: [{"destination": "", "nexthop": ""}]
              port-address-translation
              shared
        """
        request_url = "%s/grouppolicy/external_segments.json" % (
            self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"external_segment": {
                "name": name
                }
                }

        for argument in ["description", "tenant_id", "ip_version",
                         "cidr", "external-route", "subnet_id",
                         "port-address-translation", "shared"]:
            try:
                data["external_segment"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("POST", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while creating"
                          " external_segment: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to create external_segment")
            return
        return resp["external_segment"]

    def update_external_segment(self, external_segment_id, **kwargs):
        """
        It updates the network service policy
        Required Args: external_segment id
        Optional Args :
              name
              description
              ip-version
              cidr
              external-route: [{"destination": "", "nexthop": ""}]
              port-address-translation
              shared
        """
        request_url = "%s/grouppolicy/external_segments/%s.json" % (
                      self.api_url, external_segment_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        data = {"external_segment": {}}

        for argument in ["description", "tenant_id", "ip-version",
                         "cidr", "external-route",
                         "port-address-translation", "shared"]:
            try:
                data["external_segment"].update(
                    {argument: kwargs[argument]})
            except KeyError:
                pass
        try:
            resp = self.process_request("PUT", request_url, headers,
                                        json.dumps(data))
        except Exception as err:
            LOG_OBJ.error("Exception occured while updating"
                          " external_segment: %s" % err)
            return

        if resp is None:
            LOG_OBJ.error("Failed to update external_segment: %s "
                          % external_segment_id)
            return

        LOG_OBJ.debug("Updated external_segment successfully")
        return resp["external_segment"]

    def show_external_segment(self, external_segment_id):
        """
        It updates the external_segment
        Required Args: external_segment id
        """
        request_url = "%s/grouppolicy/external_segments/%s.json" % (
                      self.api_url, external_segment_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to show external_segment: %s"
                              % external_segment_id)
                return

            return resp["external_segment"]

        except Exception as err:
            LOG_OBJ.error("Exception occured in show"
                          " network_service_policy: %s" % err)
            return

    def list_external_segments(self):
        """
        It lists all the external_segments
        """
        request_url = "%s/grouppolicy/external_segments.json" % (
                      self.api_url)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("GET", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to list external_segments")
                return

            return resp["external_segments"]

        except Exception as err:
            LOG_OBJ.error("Exception occured in list"
                          " external_segments: %s" % err)
            return

    def delete_external_segment(self, external_segment_id):
        """
        It deletes the external_segment
        Required Args: external_segment id
        """
        request_url = "%s/grouppolicy/external_segments/%s.json" % (
                      self.api_url, external_segment_id)

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }

        try:
            resp = self.process_request("DELETE", request_url, headers,
                                        None)
            if resp is None:
                LOG_OBJ.error("Failed to delete external_segment:"
                              " %s" % external_segment_id)
                return

            return True

        except Exception as err:
            LOG_OBJ.error("Exception occured in delete"
                          " external_segment: %s" % err)
            return

    def get_external_segment(self, ext_segment_name):
        """
        It gets the details of external segment whose name is ext_segment_name.
        Args:
            ext_segment_name: Name of the external segment.
        Return:
            A dict containing the external segment details.
        """
        try:
            ext_segments = self.list_external_segments()
            if not isinstance(ext_segments, list):
                LOG_OBJ.error(
                    "Problem while getting the external segments.")
                return

            LOG_OBJ.debug("External Segments: %s" % ext_segments)
            for ext_segment in ext_segments:
                if ext_segment['name'] == ext_segment_name:
                    LOG_OBJ.debug("External segment details: %s" %
                                  ext_segment)
                    return ext_segment

            LOG_OBJ.error("There is NO external segment with name %s" %
                          ext_segment_name)

        except Exception as msg:
            LOG_OBJ.exception(msg)

    def list_service_profile(self):
        """
        It lists all the service profiles.
        """
        request_url = "%s/servicechain/service_profiles.json" % self.api_url

        headers = {
            'Content-type': 'application/json;charset=utf8',
            'Accept': 'application/json',
            'x-auth-token': self.token
        }
        try:
            resp = self.process_request("GET", request_url, headers, None)
            if resp is None:
                LOG_OBJ.error("Failed to list external_segments")
                return

            return resp["service_profiles"]

        except Exception as err:
            LOG_OBJ.exception(err)

    def get_service_profile(self, profile_name, profile_id=None):
        """It returns the details of the service profile.
        Args:
            profile_name: Name of the Service Profile.
        Optional Args:
            profile_id: ID of the servioce profile.
                        NOte: If ID is passed then the name can be any string.
        Return:
            Dict containing the details of the service profile, on success.
        """
        profiles = self.list_service_profile()
        if not isinstance(profiles, list):
            LOG_OBJ.error("Problem while listing the service profiles.")
            return
        for profile in profiles:
            if profile_name.lower() == profile['name'].lower() or\
                    profile_id == profile['id']:
                LOG_OBJ.debug("Profile details: %s" % profile)
                return profile
        LOG_OBJ.error("Profile with name: %s or ID: %s is NOT found." %
                      (profile_name, profile_id))

"""
from atf.lib.libOS import TEMPLATELIBRARY as libos
libOBJ = libos()
os_ip = "192.168.6.77"
libOBJ.hostIP = os_ip
token = libOBJ.get_token("admin", "admin", "admin_pass")
libOBJ.token_dict['admin'] = token
driver = gbp_resorces(token, host_ip=os_ip)
tenant_id = "a8440dbf8b8e445f87f382b8839fb91b"

kwargs = {}
kwargs["policy_target_group_id"] = "03230130-052b-4f99-ae1e-8735c6839558"
kwargs["port_id"] = "717b4b0f-a3e4-4eb0-aeb3-0efac6f93e0b"
# kwargs["direction"] = "bi"
kwargs["name"] = "ptarget1"
kwargs["tenant_id"] = tenant_id
# output = driver.create_policy_target(**kwargs)
# print "output after creation of classifier is:",output
# kwargs = {}

kwargs["id"] = "03230130-052b-4f99-ae1e-8735c6839558"
kwargs["tenant_id"] = tenant_id
output1 = driver.show_policy_target_group(**kwargs)
print "show classifier output is:", output1

kwargs["id"] = "03230130-052b-4f99-ae1e-8735c6839558"
output2 = driver.list_policy_target_group(**kwargs)
print "list classifier output is:", output2


kwargs["id"] = "03230130-052b-4f99-ae1e-8735c6839558"
# output3 = driver.update_classifier(**kwargs)
# print "update classifier output is:",output3
output4 = driver.delete_policy_target_group(**kwargs)
print "delete classifier output is:", output4
"""
