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

# The port, in the pool member vm, in which there is a Service listening.
lb_member_port = 80

# Wieghts of the members. To be used in LB case.
member_weight = [1, 1, 1]

# authentication certificate file name.
# used in remote vpn client configuration
auth_crt_file = "ca.crt"

# auth crt file path in vpn service vm.
auth_crt_path = "/config/auth/ca.crt"

# path on remote vpn client where crt file will be copied.
auth_crt_path_on_client_vm = "/etc/openvpn/"

# vpn credentials (username & passwd) file name.
# It will created on remote client vm.
vpn_cred_file = "vpn_creds.txt"

vpn_s2s_secret_key = "secret"
vpn_handshake_encrypt_algos = ['3des']

# In current services ha tests fail over on active service
# instance is applied by stopping & starting it. If this
# flag is True, traffic validation will be done twice, i.e.
# after stopping active service vm & after starting it again.
regression_ha = False

# gbp crud test case numbers to test case id mapping.
gbp_crud_test_no_to_id_mapping = {
        1: "gbp_crud_service_chain_node", 2: "gbp_crud_service_chain_spec",
        3: "gbp_crud_policy_action", 4: "gbp_crud_policy_classifier",
        5: "gbp_crud_policy_rule", 6: "gbp_crud_policy_rule_set",
        7: "gbp_crud_l3_policy", 8: "gbp_crud_l2_policy",
        9: "gbp_crud_policy_target_group", 10: "gbp_crud_policy_target",
        11: "gbp_crud_network_service_policy", 12: "gbp_crud_external_segment",
        13: "gbp_crud_external_policy"
        }

# gbp resources cleanup sequence.
gbp_res_cleanup_seq = ("policy_targets", "policy_target_groups",
                       "external_policies", "policy_rule_sets",
                       "policy_rules", "policy_actions", "policy_classifiers",
                       "service_chain_specs", "service_chain_nodes",
                       "l2policies", "l3policies", "network_service_policies")

traffic_config = {
    "in": {"request": 'True', "response": 'True'},
    "udp": {"request": 'True', "response": 'False'}
}

service_type_vm_name_mapping = {'vyos_vpn': 'svc.vyos.active_service',
                                'vyos_fw': 'svc.vyos.active_service',
                                'lb': 'svc.haproxy.active_service',
                                'asav_vpn': 'svc.asav.active_service',
                                'asav_fw': 'svc.vyos.active_service'}
vpn_svm_alternate_names = []

# ===================================================================== #
protocol_port_details = {
                         "tcp": "50001:50002",
                         "udp": "50003:50004",
                         "icmp": "NA",
                         "http": "80",
                         "https": "443",
                         "smtp": "25",
                         "dns": "53",
                         "ftp": "21",
                         "any": "50001:50002"
                         }

ownership_types = ['project', 'shared']
traffic_types = ['E-W', 'N-S', 'N-S_S2S', 'N-S_REMOTE']
vpnfw_service_image = ['VYOS', 'ASAV', 'PALOALTO']
lb_service_image = ['HAPROXY', 'F5']
services = ['FW', 'VPN', 'VPN+FW', 'LB']
#services = ['FW', 'VPN', 'VPN+FW', 'LB', 'FW-NORULE']
lb_versions = ["V1", "V2"]
direction_types = ['IN']
protocol_types = ['TCP_PORT', 'TCP_RANGE', 'UDP_PORT', 'UDP_RANGE', 'ICMP',
                  'HTTP', 'HTTPS', 'SMTP', 'DNS', 'FTP', 'ANY_RANGE']
protocol_lb = ['TCP_PORT', 'HTTP', 'HTTPS']

LB_SERVICE_IMAGE_WT = 24
LB_VERSION_WT = 12
LB_SCOPE_WT = 6
LB_TRAFFIC_TYPE_WT = 3

VPNFW_SERVICE_IMAGE_WT = 264 #192
TC_SCOPE_WT = 132 #96
TRAFFIC_TYPE_WT = 22 # 16
SERVICE_CHAIN_WT = 10
MAX_INSERTION_TC_NO = 860 # 792, LB = 48

FWNORULE_START = 800
FWNORULE_TYPE_WT = 4
FWNORULE_SCOPE_WT = 2
FWNORULE_TRAFFIC_TYPE = 2

# services ha tests to base service insertion test mapping.
services_ha_base_test_mapping = {
        "vyos_ew_fw": 1, "vyos_ns_fw": 14, "vyos_ew_fw+lb": 11,
        "vyos_ns_fw+lb": 24, "vyos_ns_s2s_vpn+fw": 27,
        "vyos_ns_s2s_vpn+fw+lb": 37, "vyos_ns_remote_vpn+fw": 40,
        "vyos_ns_remote_vpn+fw+lb": 50,
        "asav_ew_fw": 105, "asav_ns_fw": 118, "asav_ew_fw+lb": 115,
        "asav_ns_fw+lb": 128, "asav_ns_s2s_vpn+fw": 131,
        "asav_ns_s2s_vpn+fw+lb": 141, "asav_ns_remote_vpn+fw": 144,
        "asav_ns_remote_vpn+fw+lb": 154
        }
MAX_SERVICES_HA_TC_NO = 48

# Testcases for Member Add and/or Delete.
member_add_del_tcs = {  # Test case no.s: 200-215.
                   '900': 1, '901': 11, '902': 14, '903': 24,
                   '904': 27, '905': 37, '906': 40, '907': 50,
                   '908': 209,
                   }

# Variables used for update testcases
# Maximum no. of update testcases
MAX_UPDATE_TC_NO = 15
# Update and service insertion testcase mapping
update_insertion_mapping_dict = {1: 27, 2: 24, 3: 27, 4: 27, 5: 24, 6: 37,
                                 7: 24, 8: 0, 9: 1, 10: 14, 11: 14, 12: 14,
                                 13: 0, 14: 1, 15: 14}
# Dictionary to build update testcases
update_resources = {'node': ['fw', 'lb', 'vpn_add', 'vpn_delete'],
                    'spec': ['add', 'delete'],
                    'action': ['delete'],
                    'rule': ['add', 'delete'],
                    'prs': ['allow_rule_add',
                            'allow_rule_delete', 'lb', 'fw_add', 'fw_del'],
                    'ptg': ['prs']
                    }


# no of parallel threads, used during stress tests
threads = 3
thread_name = 'thread'
# if true test cases will be load balanced between threads,
# for execution.
load_sharing = False

# Test cases for Multiple service insertions in a tenant
mul_insertion_tcs = {  # list of service insertion tests
                     '1': ['1', '12', '40', '26', '29']
                    }

max_chain_support = {'vyos': 4, 'asav': 2, 'lb': 9}

# Multiple chain insertion with/without HA and repeated
# insertion, deletion test cases.
multiple_chain_tcs = {
        # 1-9 for Multiple insertion without HA
        1: {'service_chains': [11, 24]},  # Haproxy sharing multiple LBs
        2: {'service_chains': [11, 24, 24]},  # Vyos sharing multiple FWs
        3: {'service_chains': [115, 128]},  # ASAv sharing with VPN&FW, VPN inserted last
        4: {'service_chains': [27, 14, 14, 1]},  # Vyos sharing with VPN&FW, VPN inserted first
        5: {'service_chains': [14, 24, 37]},  # Vyos sharing with VPN, and VPN inserted last
        6: {'service_chains': [128, 141]},  # ASAv sharing with VPN inserted first
        # max interface exceed case for vyos, asav, lb. ## These can be avoided running each time
        7: {'service_chains': [115, 128, 115]},# ASAv
        8: {'service_chains': [11, 24, 37, 1, 11]},  # Vyos
        9: {'service_chains': [24, 24, 24, 24, 24, 24, 24, 24, 24, 24]},  # Haproxy

        # 10-20 for Multiple insertion with HA.
        # HAproxy(lb), vyos(fw) and asav(fw) failover.
        10: {'service_chains': [11, 24], 'failover_vms': ['lb']},
        11: {'service_chains': [11, 24, 24], 'failover_vms': ['fw']},  # Vyos multiple FWs
        12: {'service_chains': [115, 128], 'failover_vms': ['fw']},  # ASAv multiple FWs

        # vyos(vpn) and asav(vpn) failover. Chain order matters here
        13: {'service_chains': [27, 14, 14, 1], 'failover_vms': ['vpn']},  # VYos sharing VPN & multiple FW, VPN inserted first
        14: {'service_chains': [14, 24, 37], 'failover_vms': ['vpn']},  # Vyos sharing VPN& multiple FWs, VPN inserted last
        15: {'service_chains': [128, 141], 'failover_vms': ['vpn']},  # ASAv sharing VPN & FW, VPN inserted last
        16: {'service_chains': [141, 128], 'failover_vms': ['vpn']},  # ASAv sharing VPN & FW, VPN inserted last

        # Both LB and VPN failover
        17: {'service_chains': [11, 37], 'failover_vms': ['lb', 'vpn']},  # vyos
        18: {'service_chains': [115, 141], 'failover_vms': ['lb', 'vpn']},  # ASAv

        # Only FW in HA.  # FW (vyos) fail-over.
        19: {'service_chains': [11, 24], 'failover_vms': ['fw'],
             'services_in_ha': ['fw']},  # Vyos
        20: {'service_chains': [115, 128], 'failover_vms': ['fw'],
             'services_in_ha': ['fw']},  # ASAv
        21: {'service_chains': [11, 24], 'failover_vms': ['lb'],
             'services_in_ha': ['lb']},  # Vyos

        # max interface exceed case for vyos, asav, lb.
        22: {'service_chains': [115, 128, 115],
             'failover_vms': ['fw']},  # ASAv
        23: {'service_chains': [11, 24, 37, 1, 11],
             'failover_vms': ['fw']},  # Vyos
        24: {'service_chains': [24, 24, 24, 24, 24, 24, 24, 24, 24, 24],
             'failover_vms': ['lb']},  # LB

        # Repeated insertion and deletion scenarios. [25-30]
        # Vyos and ASAV in NON-HA
        25: {'service_chains': [11, 1, 24, 11], "repeat": 1},  # Vyos
        26: {'service_chains': [115, 128], "repeat": 1},  # ASAv

        # Vyos and ASAV in HA without any failure.
        27: {'service_chains': [11, 1, 24, 11],
             'services_in_ha': ['fw', 'lb'], "repeat": 1},
        28: {'service_chains': [115, 128],
             'services_in_ha': ['fw', 'lb'], "repeat": 1},

        # Vyos and ASAV in HA with failure.
        29: {'service_chains': [11, 1, 24, 11],
             'failover_vms': ['fw'], "repeat": 1},
        30: {'service_chains': [115, 128],

             'failover_vms': ['fw'], "repeat": 1},
        }

"""
LOGICAL TREE  STRUCTURE FOR SERVICE INSERTION TEST CASES (TCs).

                            =================================================================
                                               service_insertion (600)
                            =================================================================
                                |             |            |                              |
    FW & VPN                    |             |            |                              |
SERVICE IMAGE TYPE  ==>       VYOS (192)    ASAV (192)  PaloAlto(192)                 HAPROXY (24)          <=== LB SERVICE IMAGE TYPE
                                |             |	           |                              |
                              ===================================                   ===============
                                /             \                                        /         \
                               /              |                    LB Version ===>  V1 (12)    V2 (12)
                              /               |                                     ===================
                             /                |                                      /              \
                           PROJECT (96)      SHARED (96)                         PROJECT (6)    SHARED (6)        <=== SCOPE OF TC
                             |                |                                     |             |
               =============================================================    ======================
                  /         |      |        |            |          |               |         |
                 E-W (16)  N-S    N-S_S2S  N-S_REMOTE  N-S_S2S  N-S_REMOTE        E-W (3)    N-S                 <=== TRAFFIC TYPE
                  |         |      |        |            |          |                |        |
                  |         |      |        |            |+VPN      |+VPN            |        |
               ====================================    ===============          ======================
                           /             \                /      \                       |
                          /              \               /       \                       |
                       FW/VPN(10)   FW/VPN + LB (6)    FW(10)   FW+LB (6)               LB(3)                   <=== SERVICE CHAIN
                         |               |               |         |                      |
             - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -     - - - - - - - - - - - - -  
                                                              | CLASSIFIER(IN)|                                  <=== DIRECTION
             - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -      - - - - - - - - - - - - - 
                        | Without LB              | with LB                                |                      
                [TCP_PORT, TCP_RANGE,        ==========                         [TCP_PORT, HTTP, HTTPS]          <=== PROTOCOL (AND/OR PORT)
                 UDP_PORT, UDP_RANGE,         V1     V2   <= LB Version
                 ICMP, HTTP, HTTPS, SMTP,   ============
                 DNS, FTP]                       |
                                        [TCP_PORT, HTTP, HTTPS]
"""
