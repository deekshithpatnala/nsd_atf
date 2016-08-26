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

"""This module is for updating the config files"""

nfp_model = "advanced"

extnet_name = "ext-net"

ext_segment_name = "default"

cloud_admin_user = "admin"

cloud_admin_domain = "default"

cloud_admin_project = "admin"

keystone_api_version = "v2"

cloud_admin_user_role = "admin"

cloud_admin_passwd = "mysecret"

test_execution_node_ip = "192.168.2.74"

image_user = "root"

image_pass = "root123"

flavor_name = "m1.small"

image_name = "sungard_client"

service_profile_names = {
			"asav_vpn" : "asav_vpn",
			"lb_v1_ha" : "haproxy_lb_ha_sh",
			"lb_v2" : "lbv2_profile",
			"lb_v1" : "lb_profile",
			"paloalto_vpn_ha" : "paloalto_vpn_ha",
			"vyos_vpn_ha" : "vyos_vpn_ha",
			"vyos_fw_ha" : "vyos_fw_ha",
			"vyos_fw" : "vyos_fw_profile",
			"lb_v2_ha" : "haproxy_lb_ha_sh",
			"asav_fw" : "asav_fw",
			"asav_fw_ha" : "asav_fw_ha",
			"paloalto_fw_ha" : "paloalto_fw_ha",
			"paloalto_vpn" : "paloalto_vpn",
			"paloalto_fw" : "paloalto_fw_profile",
			"vyos_vpn" : "VPN",
			"asav_vpn_ha" : "asav_vpn_ha"
}
port_name = "atf_port"

ftpuser = "test"

regression = False

traffic_capture = True

keystonev3_domain_name = "atf-dom"

log_level = "DEBUG"

keystonev3_project_details = [{'password': 'pass', 'project_name': 'Atf-prj', 'user_name': 'Atf-user', 'project_no': 1, 'roles': ['Member']}]

admin_passwd = "admin_pass"

ftppasswd = "test123"

vpn_user_details = {'password': 'pass', 'user_name': 'atf-vpn-user', 'roles': ['vpn']}

admin_user = "admin"

atf_log_file_name = "atf"

log_mode_for_feature = "one"

admin_tenant = "admin"

atf_log_path = "/var/log/atf/"

service_user = "neutron"

service_tenant = "services"

domain_member_role_name = "domain_member"

log_mode_for_testcase = "one"

service_passwd = "neutron_pass"

remote_project_info = [{'password': 'user-pass', 'project_name': 'remote-atf-prj', 'user_name': 'remote-atf-user', 'project_no': 1, 'roles': ['admin']}]

