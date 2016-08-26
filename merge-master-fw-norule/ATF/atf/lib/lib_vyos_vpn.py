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
  Library for vyos vpn site to site connection configuration.
"""

import json
import request
import sys

from atf.config import gbp_config
import atf.lib.nvp_atf_logging as log
sys.path.append("../../")

LOG = log.get_atf_logger()

VPN_SERVICE_OBJ = {
               "router_id": "23db62c6-ad18-4e16-897f-6f9aac56a4bf",
               "status": "ACTIVE",
               "name": "vpnsvc1",
               "admin_state_up": True,
               "subnet_id": "cacb2816-0e42-4935-b907-4839924535c5",
               "tenant_id": "967668ef5627437da279313dd433b6ca",
               "cidr": "30.0.0.0/24",  # local-address for tunnel interface
               "id": "bf6569a3-52c5-4819-b8b8-844cef060bf4",
               "description": "fip=192.168.6.146;tunnel_local_cidr=50.0.0.0/24"
               }

IPSEC_SITE_CONNS_OBJ = {
                    "status": "PENDING_CREATE",
                    "psk": gbp_config.vpn_s2s_secret_key,
                    "initiator": "bi-directional",
                    "name": "conn1",
                    "admin_state_up": True,
                    "tenant_id": "967668ef5627437da279313dd433b6ca",
                    "auth_mode": "psk",
                    "peer_cidrs": ["60.0.0.0/24"],  # remote_prefix,
                    "mtu": 1500,
                    "ikepolicy_id": "a05ff843-ae36-4718-92b7-6e3d144333e0",
                    "vpnservice_id": "bf6569a3-52c5-4819-b8b8-844cef060bf4",
                    "dpd": {"action": "hold",
                            "interval": 30,
                            "timeout": 120
                            },
                    "route_mode": "static",
                    "ipsecpolicy_id": "468d0852-9e29-4cc8-995f-68c1fff29b2c",
                    "peer_address": "192.168.6.148",  # remote_address,
                                    # remote vpn floating ip
                    "peer_id": "30.0.0.11",  # remote vpn tunnel fixed ip
                    "id": "ec746387-7904-4b63-a829-dd04d0cdd614",
                    "tunnel_local_cidr": "50.0.0.0/24",  # local cidr
                    "description": "conn1"
                    }

IKE_POLICY_OBJ = {"name": "ike",
                  "tenant_id": "967668ef5627437da279313dd433b6ca",
                  "description": "ike",
                  "auth_algorithm": "sha1",
                  "encryption_algorithm": "3des",
                  "pfs": "group5",
                  "lifetime": {"units": "seconds", "value": 3600},
                  "ike_version": "v1",
                  "id": "a05ff843-ae36-4718-92b7-6e3d144333e0",
                  "phase1_negotiation_mode": "main"
                  }

IPSEC_POLICY_OBJ = {
                "name": "ipse",
                "transform_protocol": "esp",
                "auth_algorithm": "sha1",
                "encapsulation_mode": "tunnel",
                "encryption_algorithm": "3des",
                "pfs": "group5",
                "tenant_id": "967668ef5627437da279313dd433b6ca",
                "lifetime": {"units": "seconds", "value": 3600},
                "id": "468d0852-9e29-4cc8-995f-68c1fff29b2c",
                "description": "ipse"
                }

SSL_VPN_CONNS_OBJ = {
                     "id": "9b7d3020-15f4-497b-a0d0-a9adb72a4828",
                     "tenant_id": "42fecf3bc1af4713b69a1fea30377038",
                     "name": "vtun0",
                     "credential_id": "",
                     "admin_state_up": True,
                     "vpnservice_id": "2715ab07-bef8-4715-b24f-09b7d504b4de",
                     "client_address_pool_cidr": "192.168.200.0/24",
                     }


class VyosVPN:
    """
     Class for site to site and remote connections
    """
    def __init__(self, host="127.0.0.1"):
        """ Constructor """
        self.logger = LOG
        LOG.debug("VyosVPN Class")
        self.api_url = "http://%s:9696/v2.0/" % host
        self.vpn_service_obj = VPN_SERVICE_OBJ
        self.ipsec_site_conns_obj = IPSEC_SITE_CONNS_OBJ
        self.ike_policy_obj = IKE_POLICY_OBJ
        self.ipsec_policy_obj = IPSEC_POLICY_OBJ
        self.ssl_vpn_conns_obj = SSL_VPN_CONNS_OBJ
        self.vpn_srvc_ip = ""
        self.os_ip = host
        self.connection = request.OCRequest()

    def create_ike_policy(self, **kwargs):
        """
        Function to create ike policy in neutron db
        kwargs is dictionary of optional arguments
        returns type : On success ike policy dictionary.
            On failure None.
        """
        # _url = "http://"+self.os_ip+":8888/create-ike-policy"
        _url = "%s/ikepolicy.json" % self.api_url
        _headers = {'Content-type': 'application/json'}

        ike_policy_info = {"ikepolicy": {}}
        for argument in [
                'tenant_id',
                'name']:
            try:
                ike_policy_info["ikepolicy"].update(
                    {argument: kwargs["ikepolicy"][argument]}
                )
            except KeyError:
                pass

        _body = json.dumps(ike_policy_info)

        response = self.connection.request("POST", _url, _headers, _body)

        if response is None:
            self.logger.error("Failed to create ike policy.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            self.logger.error("Create ike policy failed %s " % response.status)
            return None

        self.logger.info("created ike-policy with uuid: %s" %
                         response.data['ikepolicy']["id"])
        return response.data['ikepolicy']

    def create_ipsec_policy(self, **kwargs):
        """
        Function to create ipsec policy in neutron db
        kwargs is dictionary of optional arguments
        return type: On Success ipsec policy dictionary.
            On failure returns None.
        """
        # _url = "http://"+self.vpn_srvc_ip+":8888/create-ipsec-site-conn"
        _url = "%s/ipsecpolicy.json" % self.api_url
        _headers = {'Content-type': 'application/json'}

        ipsec_policy_info = {"ipsecpolicy": {}}
        for argument in [
                'tenant_id',
                'name']:
            try:
                ipsec_policy_info["ipsecpolicy"].update(
                    {argument: kwargs["ipsecpolicy"][argument]}
                )
            except KeyError:
                pass
        _body = json.dumps(ipsec_policy_info)

        response = self.connection.request("POST", _url, _headers, _body)

        if response is None:
            self.logger.error("Failed to create ipsec policy.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            self.logger.error("Create site to site connection failed %s" %
                              response.status)
            return None

        self.logger.info("created ipsec-policy with uuid: %s" %
                         response.data['ipsecpolicy']["id"])
        return response.data['ipsecpolicy']

    def create_ipsec_site_conn(self):
        """
        Function to create ipsec site to site connection
        return type: On success True.
            On failure None.
        """
        _url = "http://"+self.vpn_srvc_ip + \
            ":8888/create-ipsec-site-conn"
        _headers = {'Content-type': 'application/json'}

        # 'x-auth-token':self.token_dict[config.adminTenant]}
        _body = json.dumps({
                        "service": self.vpn_service_obj,
                        "siteconns": [{"connection": self.ipsec_site_conns_obj,
                                       "ikepolicy": self.ike_policy_obj,
                                       "ipsecpolicy": self.ipsec_policy_obj
                                       }]
                            })

        response = self.connection.request("POST", _url, _headers, _body)

        if response is None:
            self.logger.error("Failed to create site-to-site ipsec"
                              " vpn connection.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            self.logger.error("Create site to site connection failed %s" %
                              response.status)
            return None
        self.logger.info("Created site to site connection")
        return True

    def delete_ipsec_site_conn(self):
        """
          Function to delete ipsec site to site connection
          return type: On success True.
              On Failure None.
        """
        _peer_address = self.ipsec_site_conns_obj['peer_address']
        _url = "http://"+self.vpn_srvc_ip + \
            ":8888/delete_ipsec_site_conn?peer_address=" + _peer_address
        _headers = {'Content-type': 'application/json'}
        # 'x-auth-token':self.token_dict[config.adminTenant]}
        _body = json.dumps({})

        response = self.connection.request("DELETE", _url, _headers, _body)

        if response is None:
            self.logger.error("Failed to delete site-to-site ipsec"
                              " vpn connection.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            self.logger.error("Delete site to site connection failed %s" %
                              response.status)
            return None

        self.logger.info("Deleted site to site connection :%s" % _peer_address)
        return True

    def create_ssl_vpn_conn(self):
        """
         Function to create ssl vpn connection
         return type: True/ None
        """
        _url = "http://" + self.vpn_srvc_ip + ":8888/create-ssl-vpn-conn"
        _headers = {'Content-type': 'application/json'}

        # 'x-auth-token':self.token_dict[config.adminTenant]}
        _body = json.dumps({
                        "vpnserviceid": {
                                        "service": self.vpn_service_obj,
                                        "sslvpnconns": [{"connection":
                                                         self.ssl_vpn_conns_obj
                                                         }]
                                      }
                            })

        response = self.connection.request("POST", _url, _headers, _body)

        if response is None:
            self.logger.error("Failed to create site-to-site ssl"
                              " vpn connection.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            self.logger.error("Create ssl vpn connection failed %s" %
                              response.status)
            return None

        self.logger.info("Created ssl vpn connection")
        return True

    def delete_ssl_vpn_conn(self, vtun="vtun0"):
        """
         Function to delete ssl vpn connection
         return type: True/None
        """
        _url = "http://" + self.vpn_srvc_ip + \
            ":8888/delete-ssl-vpn-conn?tunnel=%s" % vtun

        _headers = {'Content-type': 'application/json'}

        # 'x-auth-token':self.token_dict[config.adminTenant]}
        _body = json.dumps({})

        response = self.connection.request("DELETE", _url, _headers, _body)

        if response is None:
            self.logger.error("Failed to delete site-to-site ssl"
                              " vpn connection.")
            return None

        if response.status not in [200, 201, 202, 203, 204]:
            self.logger.error("Delete ssl vpn connection failed %s" %
                              response.status)
            return None

        self.logger.info("Deleted ssl vpn connection")
        return True


class VpnWrapper:
    """
       Wrapper class for VPN site to site connection
    """
    def __init__(self, vpn_fip, os_ip="127.0.0.1"):
        """ Constructor """
        self.vpn_obj = VyosVPN(os_ip)
        self.vpn_obj.vpn_srvc_ip = vpn_fip

    def create_site_conn_wrapper(self, peer_address, remote_id,
                                 remote_prefix, local_tunn_cidr, local_prefix):
        """
          Wrapper function to create vpn site to site connection
          Args:
             peer_address: remote vpn floating IP
             remote_id: remote vpn fixed IP of tunnel interface
             remote_prefix: remote vpn client(site) cidr
             local_tunn_cidr: local vpn tunnel network cidr
             local_prefix : local vpn client(site) cidr
          return type: True/False
        """
        self.vpn_obj.vpn_service_obj["cidr"] = local_tunn_cidr
        self.vpn_obj.ipsec_site_conns_obj["peer_cidrs"] = [remote_prefix]
        self.vpn_obj.ipsec_site_conns_obj["peer_address"] = peer_address
        self.vpn_obj.ipsec_site_conns_obj["peer_id"] = remote_id
        self.vpn_obj.ipsec_site_conns_obj["tunnel_local_cidr"] = local_prefix

        exec_out = self.vpn_obj.create_ipsec_site_conn()
        if type(exec_out) is bool and exec_out is True:
            print "VPN site to site connection done"
            LOG.info("VPN site to site connection done")
            return True
        else:
            print "VPN site to site configuration failed"
            LOG.info("VPN site to site connection failed")
            return False
