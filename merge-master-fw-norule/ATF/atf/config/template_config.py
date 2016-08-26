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


from atf.config import common_config

vpn_remote_template_config = {
    "heat_template_version": "2013-05-23",
    "description": "Creates new vpn service - ike + ipsec + vpn service +"
                   " remote connection(s)",
    "parameters": {
        "RouterId": {
            "type": "string",
            "description": "Router ID"},
        "Subnet": {
            "type": "string",
            "description": "Subnet id on which vpn service is launched"},
        "ServiceDescription": {
            "type": "string",
            "description": "fip;tunnel_local-cidr"}},
    "resources": {
        "VPNService": {
            "type": "OS::Neutron::VPNService",
            "properties": {
                "router_id": {
                    "get_param": "RouterId"},
                "subnet_id": {
                    "get_param": "Subnet"},
                "description": {
                    "get_param": "ServiceDescription"},
                "name": "VPNService",
                "admin_state_up": True}},
        "IKEPolicy": {
            "type": "OS::Neutron::IKEPolicy",
            "properties": {
                "encryption_algorithm": "aes-128",
                "pfs": "group5",
                "phase1_negotiation_mode": "main",
                "name": "IKEPolicy",
                "lifetime": {
                    "units": "seconds",
                    "value": 3600},
                "auth_algorithm": "sha1",
                "ike_version": "v1"}},
        "IPsecPolicy": {
            "type": "OS::Neutron::IPsecPolicy",
            "properties": {
                "encapsulation_mode": "tunnel",
                "encryption_algorithm": "aes-128",
                "pfs": "group5",
                "name": "IPsecPolicy",
                "lifetime": {
                    "units": "seconds",
                    "value": 3600},
                "transform_protocol": "esp",
                "auth_algorithm": "sha1"}}}}

vpn_s2s_connection = {
        "site_to_site_connection1": {  # This will be appended in the resources
                                       # section in vpn template
            "type": "OS::Neutron::IPsecSiteConnection",
            "properties": {
                "admin_state_up": True,
                "dpd": {
                    "actions": "hold",
                    "interval": 30,
                    "timeout": 120
                },
                "ikepolicy_id": {
                    "get_resource": "IKEPolicy"
                },
                "initiator": "bi-directional",
                "ipsecpolicy_id": {
                    "get_resource": "IPsecPolicy"
                },
                "mtu": 1500,
                "name": "site_to_site_connection1",
                "peer_address": "",  # Floating ip of peer
                "peer_cidrs": [],  # subnet cidr of the backend lan
                "peer_id": "",   # Fixed ip of the peer on which it listens
                "psk": "secret",  # Can be read from the config
                "vpnservice_id": {
                    "get_resource": "VPNService"
                }
            }
        }}


fw_template_base = {
    "heat_template_version": "2013-05-23",
    "description": "Configuration for Firewall service",
    "resources": {
        "Firewall": {
            "type": "OS::Neutron::Firewall",
            "properties": {
                "admin_state_up": True,
                "firewall_policy_id": {
                    "get_resource": "Firewall_Policy"
                },
                "name": "FWaaS",
                "description": "Firewll Resource"
            }
        },
        "Firewall_Policy": {
            "type": "OS::Neutron::FirewallPolicy",
            "properties": {
                "description": "firewall policy Resource",
                "audited": False,
                "firewall_rules": [
                    {
                        "get_resource": "Rule_1"
                    }
                ],
                "name": "FW_policy"
            }
        }
    }
}

lb_template_config = {
    "heat_template_version": "2013-05-23",
    "description": "Configuration for Haproxy Neutron Loadbalacer service",
    "parameters": {
        "Subnet": {
            "type": "string",
            "description": "Pool Subnet CIDR, on which VIP"
            " port should be created"},
        "vip_ip": {
            "type": "string",
            "description": "VIP IP Address"},
        "service_chain_metadata": {
            "type": "string",
                    "description": "sc metadata"}
    },
    "resources": {
        "LoadBalancerPool": {
            "type": "OS::Neutron::Pool",
            "properties": {
                "lb_method": "ROUND_ROBIN",
                "protocol": "HTTP",
                "name": "Haproxy pool",
                "admin_state_up": True,
                "subnet_id": {
                    "get_param": "Subnet"},
                "vip": {
                    "subnet": {
                        "get_param": "Subnet"},
                    "protocol_port": 80,
                    "description": {
                        "get_param": "service_chain_metadata"},
                    "admin_state_up": True,
                    "address": {
                        "get_param": "vip_ip"},
                    "connection_limit": -1,
                    "name": "LoadBalancerPoolvip"},
                "provider": "haproxy_on_vm",
                "monitors": [
                    {"get_resource": "HealthMonitor"}],
                "description": "Haproxy pool from template"}
        },
        "HealthMonitor": {
            "type": "OS::Neutron::HealthMonitor",
            "properties": {
                "delay": 20,
                "max_retries": 2,
                "type": "TCP",
                "timeout": 10,
                "admin_state_up": True}
        },
        "LoadBalancer": {
            "type": "OS::Neutron::LoadBalancer",
            "properties": {
                "protocol_port": 90,
                "pool_id": {"get_resource": "LoadBalancerPool"}}
        }
    }
}

lb_template_config_v2 = {
    "heat_template_version": "2015-10-15",
    "description": "Configuration for Haproxy Neutron Loadbalacer V2 service",
    "parameters": {
        "lb_port": {
            "type": "number",
            "default": 80,
            "description": "Port used by the load balancer"
        },
        "app_port": {
            "type": "number",
            "default": 80,
            "description": "Port used by the servers"
        },
        "Subnet": {
            "type": "string",
            "description": "Subnet on which the load balancer will be located"
        },
        "vip_ip": {
            "type": "string",
            "description": "VIP IP Address"
        },
        "service_chain_metadata": {
            "type": "string",
            "description": "sc metadata"
        }
    },  # parameters
    "resources": {
        "monitor": {
            "type": "OS::Neutron::LBaaS::HealthMonitor",
            "properties": {
                "delay": 20,
                "type": "TCP",
                "timeout": 10,
                "max_retries": 2,
                "pool": {
                    "get_resource": "pool"
                }
            }
        },
        "pool": {
            "type": "OS::Neutron::LBaaS::Pool",
            "properties": {
                "lb_algorithm": "ROUND_ROBIN",
                "protocol": "HTTP",
                "listener": {
                    "get_resource": "listener"
                }
            }
        },  # pool
        "listener": {
            "type": "OS::Neutron::LBaaS::Listener",
            "properties": {
                "loadbalancer": {
                    "get_resource": "loadbalancer"
                },
                "protocol": "HTTP",
                "protocol_port": {
                    "get_param": "lb_port"
                }
            }
        },  # listener
        "loadbalancer": {
            "type": "OS::Neutron::LBaaS::LoadBalancer",
            "properties": {
                "vip_subnet": {
                    "get_param": "Subnet"
                },
                "provider": "loadbalancerv2",
                "vip_address": {
                    "get_param": "vip_ip"
                },
                "description": {
                    "get_param": "service_chain_metadata"
                }
            }
        }  # loadbalancer
    }  # resources
}

pool = lb_template_config["resources"]["LoadBalancerPool"]
if common_config.nfp_model.lower() == "base":
    # NOTE: For NFP base model provider will be 'haproxy'.
    pool["properties"]["provider"] = "haproxy"
else:
    # NOTE: For NFP advanced model provider will be loadbalancer.
    pool["properties"]["provider"] = "loadbalancer"
