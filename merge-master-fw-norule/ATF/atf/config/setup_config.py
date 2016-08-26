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

setupInfo = {
                "compute-node": [
                                {
                                                "datapath": "192.168.20.22", 
                                                "hostname": "stack", 
                                                "mgmtip": "192.168.20.22", 
                                                "password": "stack123", 
                                                "username": "stack"
                                }
                ], 
                "network-node": {
                                "datapath": "100.10.10.23", 
                                "interface": "eth1", 
                                "mgmtip": "100.10.10.23", 
                                "password": "root123", 
                                "username": "root"
                }, 
                "os-controller-node": {
                                "mgmtip": "192.168.20.22", 
                                "password": "stack123", 
                                "pubip": "192.168.20.22", 
                                "username": "stack"
                }
}