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
File contains class and methods for prepartion of
traffic resources.
"""


# import sys
# sys.path.append("../../")

from atf.config import gbp_config
from atf.config import common_config
from atf.lib.lib_common import commonLibrary
import atf.lib.nvp_atf_logging as log

LOG = log.get_atf_logger()


class TrafficPreparation(object):
    """Contains methods for preparing traffic resource dictionary.
    """

    def __init__(self, gbp_resources_info):
        """
        Arguments:
            1. gbp_resources_info: (output dict returned by the
                create_gbp_resources of gbp_resource_create.)
            2. common_lib_obj: Common library object. (optional.)
        """
        self.set_gbp_resources_info(gbp_resources_info)
        self.nfp_model = common_config.nfp_model
        """
        self.gbp_resources_info = gbp_resources_info.copy()

        self.traffic_type = "E-W"
        self.vpn_in_chain = False
        if self.gbp_resources_info.get('remote_resource_info'):
            self.traffic_type = "N-S"
            if self.gbp_resources_info['remote_resource_info'
                                       ].get('vpn_type'):
                self.vpn_in_chain = True
        """

    def set_gbp_resources_info(self, gbp_resources_info):
        """ setter method for setting (replacing ) gbp_resources_info
            dictionary
        """
        LOG.debug("Setting gbp_resources_info.\n New gbp_resources_info: %s" %
                  gbp_resources_info)

        self.gbp_resources_info = gbp_resources_info.copy()
        self.traffic_type = "E-W"
        self.vpn_in_chain = False

        if self.gbp_resources_info.get('remote_resource_info'):
            self.traffic_type = "N-S"
            if self.gbp_resources_info['remote_resource_info'
                                       ].get('vpn_type'):
                self.vpn_in_chain = True

    def prepare_consumer_details(self, policy_targets=None,
                                 traffic_type='n-s'):
        """It returns the consumer details for both east-west and
        north-south case in a list.
        NOTE: When traffic type is N-S then the remote client is the consumer.

        NOTE: By default the object is searched. If above optional argument
              (policy_targets) are given then it will operate on them instead
              of operating on the object.
        params:
            traffic_type: Type of traffic, default is n-s.
            policy_targets: A list of dict. Each dict is a policy target.
                Consumer policy targets (for e-w) or remote side client
                policy targets (for north-south).
        """
        try:
            # Filling consumer details
            consumers = []
            temp_consumer_pt = {}
            if not policy_targets:
                if traffic_type.lower() == "n-s":
                    policy_targets = [self.gbp_resources_info[
                        'remote_resource_info']['remote_client_info']]
                else:
                    policy_targets = self.gbp_resources_info['ptg_info'][
                        'consumer']['policy_targets']
            for consumer_pt in policy_targets:
                temp_consumer_pt['pt_ip'] = consumer_pt['vm_ip'] \
                    if consumer_pt.get('vm_ip') else consumer_pt['fixed_ip']
                temp_consumer_pt['floating_ip'] = consumer_pt['floating_ip']
                # Special case. For remote vpn case take tun iface in client vm
                if consumer_pt.get('tun_iface_ip'):
                    temp_consumer_pt['tun_iface_ip'] = \
                        consumer_pt['tun_iface_ip']
                consumers.append(temp_consumer_pt)

            return consumers
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting details of consumer."

    def prepare_provider_details(self, policy_targets=None,
                                 traffic_type='n-s', lb_in_chain=False):
        """It returns the provider details for both east-west and
        north-south case in a list.
        NOTE: When traffic type is N-S then the remote client is the consumer.

        NOTE: By default the object is searched. If above argument
            (policy_targets) are given then it will operate on them instead
            of operating on the object.
        params:
            traffic_type: Type of traffic, default is n-s.
            policy_targets: A list of dict. Each dict is a policy target.
            lb_in_chain: Whether the LB service is in chain or not.
        """
        try:
            providers = []
            if not policy_targets:
                policy_targets = self.gbp_resources_info['ptg_info'][
                    'provider']['policy_targets']
            for provider_pt in policy_targets:
                temp_prov_pt = {}
                temp_prov_pt['pt_ip'] = provider_pt['vm_ip']
                temp_prov_pt['port_id'] = provider_pt['port_id']
                # Fill the compute host ip.
                compute_host_ip = commonLibrary.get_compute_node_ip(
                                           provider_pt['host_name'])
                if not isinstance(compute_host_ip, unicode):
                    return compute_host_ip
                temp_prov_pt['compute_ip'] = compute_host_ip

                # If LB is there in chain then pass the weight.
                if lb_in_chain:
                    temp_prov_pt['weight'] = \
                        provider_pt.get('weight', gbp_config.member_weight[0])

                # For N-S case and only FW
                if not lb_in_chain and traffic_type.lower() == 'n-s' and \
                        provider_pt.get('floating_ip'):
                    temp_prov_pt['floating_ip'] = provider_pt['floating_ip']

                providers.append(temp_prov_pt)

            return providers
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting details of provider."

    def prepare_classifier_details(self):
        """It returns the classifier (dict) in the redirect rule."""
        try:
            temp_classifier = {}
            for rule in self.gbp_resources_info['policy_rule_set'][
                    'policy_rules']:
                if not rule['action'].get('service_chain'):
                    continue
                # Filling classifier details
                #import pdb; pdb.set_trace()
                temp_classifier['protocol'] = rule['classifier'].get(
                    'protocol_original_name')
                if rule['classifier']['port_range']:
                    temp_classifier['port'] = rule['classifier']['port_range']
                temp_classifier['direction'] = rule['classifier']['direction']

            return temp_classifier
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting redirect classifier details."

    def prepare_service_details(self, vpn_in_chain, services=None,
                                traffic_type='n-s', chain_index=0):
        """It prepares the services details for traffic validation.

        params:
            vpn_in_chain: A flag to tell whether the vpn is there as part
                            of the chain or not.
            services: A list of dict. Each dict contains info of the service
                    inserted in the chain.
            chain_index: Chain index. As a service can be part of a multiple
                    chains, so this tells which chain index detail the user
                    wants. This no. is basically relative to the order in which
                    providers ids passed to the get_svm_info() when multiple
                    chains are there.
            service_ha: A flag which tells whether the Service HA is there
                or not. If True then it also gets the standby service vm info.

        NOTE: By default the object is searched. If above optional
                arguments (services) are  given then it will operate on
                them instead of operating on the object.
        """
        try:
            if not services:
                for rule in self.gbp_resources_info['policy_rule_set'][
                        'policy_rules']:
                    if rule['action'].get('service_chain'):
                        services = rule['action']['service_chain']['services']
                        break
                else:
                    services = None
            if not services:
                services = []

            service_details = []
            # Filling service node details
            for service in services:
                temp_service = {}
                # Get the provider side interface ip of svm
                if not service.get('service_details'):
                    continue
                temp_service['service_type'] = service['service_type']

                if self.nfp_model.lower() == "advanced":
                    vms = [""]
                    if service.get('service_ha'):
                        vms.append("standby_")

                    for _vm in vms:
                        # Get the provider side interface ip of svm
                        svm_provider_side_iface = service['service_details'][
                                '%sconsumer_provider_interfaces'
                                % _vm][chain_index][1]
                        temp_service['%sservice_vm_ip' % _vm] = \
                            svm_provider_side_iface['fixed_ip']
                        temp_service['%sport_id' % _vm] = \
                            svm_provider_side_iface['port_id']
                        # Optional: Store vm id. To be used in HA
                        temp_service['%svm_id' % _vm] = \
                            svm_provider_side_iface['vm_id']

                        # Fill the compute host ip.
                        compute_host_ip = commonLibrary.get_compute_node_ip(
                            svm_provider_side_iface['host_name'])
                        if not isinstance(compute_host_ip, unicode):
                            return compute_host_ip
                        temp_service['%scompute_ip' % _vm] = compute_host_ip

                vip_ips = {}
                # For N-S with VPN+FW+LB or E-W with FW+LB
                if service['service_type'].lower() == "lb":
                    vip_ips['pt_ip'] = \
                     service['service_details']['vip_details']['fixed_ip']
                    temp_service['vip_details'] = vip_ips

                # For N-S case and for FW-LB (no vpn)
                if traffic_type.lower() == "n-s" and not vpn_in_chain:
                    if service['service_type'].lower() == "lb":
                        vip_ips['floating_ip'] = service['service_details'][
                                        'vip_details']['floating_ip']
                service_details.append(temp_service)

            return service_details
        except Exception as err:
            LOG.exception(err)
            return "Problem while getting service details."

    def prepare_for_traffic_validation(self, chain_index=0):
        """This prepares and returns the dictionary containing respective
        details in a specified format required for the traffic validation.
        This basically parses the gbp resource info dict in the object.

        params:
            chain_index: The service chain index. As multiple chains are
                possible & a single service can be part of multiple chains.
        """
        try:
            traffic_info = {'classifiers': [], 'consumer_pt_details': [],
                            'provider_pt_details': [], 'service_details': []}
            # Filling service node details
            service_details = self.prepare_service_details(
                self.vpn_in_chain, traffic_type=self.traffic_type,
                chain_index=chain_index)
            if not isinstance(service_details, list):
                return service_details
            traffic_info['service_details'] = service_details

            # Fill the consumer details.
            consumers = \
                self.prepare_consumer_details(traffic_type=self.traffic_type)
            if not isinstance(consumers, list):
                return consumers
            traffic_info['consumer_pt_details'] = consumers

            # Filling provider details
            lb_in_chain = False
            if len([service for service in service_details
                   if service['service_type'].lower() == "lb"]):
                lb_in_chain = True

            providers = \
                self.prepare_provider_details(traffic_type=self.traffic_type,
                                              lb_in_chain=lb_in_chain)
            if not isinstance(providers, list):
                return providers
            traffic_info['provider_pt_details'] = providers

            # Filling classifier
            classifier = self.prepare_classifier_details()
            if not isinstance(classifier, dict):
                return classifier
            traffic_info['classifiers'].append(classifier)

            LOG.debug("traffic_info : %s" % traffic_info)
            return traffic_info

        except Exception as err:
            LOG.exception(err)
            return "Problem while preparing for traffic validation."
