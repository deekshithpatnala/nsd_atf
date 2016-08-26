# One Convergence, Inc. CONFIDENTIAL
# Copyright (c) 2012-2015, One Convergence, Inc., USA
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

"""This script does interaction with mysql db"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# from sqlalchemy import *
from sqlalchemy import MetaData
from sqlalchemy import Table
# sys.path.append("../../")
# import atf.config.common_config as com_config
import atf.lib.nvp_atf_logging as log

LOG_OBJ = log.get_atf_logger()

mysqldb_user = "neutron"
mysqldb_password = "neutron_pass"
mysqldb_server = "127.0.0.1"


class AccessDb(object):
    """Class is used to access db"""
    def __init__(self):
        connector = "mysql://%s:%s@%s/neutron" % \
            (mysqldb_user, mysqldb_password, mysqldb_server)
        # connector = "mysql://neutron:neutron_pass@192.168.20.16/neutron"
        self.engine = create_engine(connector, echo=False)
        self.metadata = MetaData(self.engine)

    def _get_session(self):
        """returns session"""
        # LOG_OBJ.debug("In get session")
        session_bind = sessionmaker(bind=self.engine)
        session = session_bind()
        return session

    def _get_dict_from_tuple(self, row_tuple):
        """converts row in tuple to row in dictionary format"""
        # LOG_OBJ.debug("In get_dict_from_tuple)
        return row_tuple._asdict()

    def get_sc_id_from_ptg_id(self, provider_ptg_id):
        """Gets the service chain id from sc_instances table for
        corresponding provider ptg id.
        input: provider_ptg_id optionally: tenant_id
        returns service chain id if successfull
        otherwise returns None.
        """
        try:
            # LOG_OBJ.debug("In get_sc_id_from_ptg_id")
            sc_intances_table = Table('sc_instances', self.metadata,
                                      autoload=True)
            session = self._get_session()
            res = session.query(sc_intances_table.c.id).\
                filter(sc_intances_table.c.
                       provider_ptg_id == provider_ptg_id).\
                first()
            session.commit()
            if isinstance(res, tuple):
                row_dict = self._get_dict_from_tuple(res)
                return row_dict.get('id')
            return None

        except Exception as err:
            msg = "Exception occurred while getting service"\
                  "chain instance id from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_active_instance_id(self, service_chain_id,
                               service_type="FIREWALL"):
        """ Gets active service instance id from
        service chain instance id from table
        oneconvergence_service_info
        input: service chain instance id
        on success returns active service instance id.
        on failure returns None."""
        # discuss whether only one active service instance will be there
        # for service chain instance id.
        try:
            # LOG_OBJ.debug("In get_active_instance_id")
            oc_service_info_table = Table('oneconvergence_service_info',
                                          self.metadata,
                                          autoload=True)
            session = self._get_session()
            res = session.query(oc_service_info_table.c.
                                active_service_instance_id).\
                filter(oc_service_info_table.c.
                       service_chain_instance_id == service_chain_id).\
                filter(oc_service_info_table.c.service_type ==
                       service_type.upper()).\
                first()
            session.commit()
            if isinstance(res, tuple):
                row_dict = self._get_dict_from_tuple(res)
                return row_dict.get('active_service_instance_id')
            return None

        except Exception as err:
            msg = "Exception occurred while getting active service"\
                  "instance id from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_standby_instance_id(self, active_instance_id):
        """Gets standby instance id from active instace id"""
        try:
            oc_service_info_table = Table('oneconvergence_service_info',
                                          self.metadata,
                                          autoload=True)
            session = self._get_session()
            res = session.query(oc_service_info_table.c.
                                standby_service_instance_id).\
                filter(oc_service_info_table.c.
                       active_service_instance_id == active_instance_id).\
                first()
            session.commit()
            if isinstance(res, tuple):
                row_dict = self._get_dict_from_tuple(res)
                return row_dict.get('standby_service_instance_id')
            return None

        except Exception as err:
            msg = "Exception occurred while getting standby service"\
                  "instance id from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_from_instance_info_helper(self, instance_id):
        """Gets details from oneconvergence_service_instance_info
        corresponding to active_instance_id
        On success: returns a dictionary
                       {'status': 'ACTIVE',
                        'stitching_port_id': '',
                        'tenant_id': '',
                        'provider_port_id': '',
                        'service_vm_id': '',
                        'id': ''}
        On failure: returns None."""
        try:
            # LOG_OBJ.debug("In get_from_instance_info_helper")
            instance_info_table = Table(
                'oneconvergence_service_instance_info', self.metadata,
                autoload=True)
            session = self._get_session()
            res = session.query(instance_info_table).\
                filter(instance_info_table.c.id == instance_id).\
                first()
            session.commit()
            if isinstance(res, tuple):
                row_dict = self._get_dict_from_tuple(res)
                return row_dict
            return None

        except Exception as err:
            msg = "Exception occurred while getting service instance info"\
                  "from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_plugged_in_pt_id(self, instance_id,
                             port_id_type="provider_port_id"):
        """Gets plugged_in_pt_id from oneconvergence_service_vm_interface_info
        table for corresponding instance_id and port_id_type
        input: instance_id
        optionally: port_id_type = provider_port_id
        or stitching_port_id.
        Output: on success returns plugged_in_pt_id (string)
                on failure returns None. """
        try:
            # LOG_OBJ.debug("In get_plugged_in_pt_id")
            instance_dict = self.get_from_instance_info_helper(
                                instance_id)
            if not isinstance(instance_dict, dict):
                LOG_OBJ.error("Not able to retreive instance info details")
                return None
            interface_info_table = Table(
                'oneconvergence_service_vm_interface_info', self.metadata,
                autoload=True)
            session = self._get_session()
            res = session.query(interface_info_table).\
                filter(interface_info_table.c.mapped_real_port_id ==
                       instance_dict.get(port_id_type)).\
                filter(interface_info_table.c.service_vm_id ==
                       instance_dict.get('service_vm_id')).\
                first()
            session.commit()
            if isinstance(res, tuple):
                row_dict = self._get_dict_from_tuple(res)
                return row_dict.get('plugged_in_pt_id')
            return None

        except Exception as err:
            msg = "Exception occurred while getting plugged_in_pt_id"\
                  "from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_port_id(self, plugged_in_pt_id):
        """Gets port_id from gp_policy_targets for corresponding
        plugged_in_pt_id. Input: plugged_in_pt_id and
        output: on success returns port_id
        on failure returns None."""
        try:
            # LOG_OBJ.debug(In get_port_id)
            policy_target_table = Table('gp_policy_targets', self.metadata,
                                        autoload=True)
            session = self._get_session()
            res = session.query(policy_target_table).\
                filter(policy_target_table.c.id == plugged_in_pt_id).\
                first()
            session.commit()
            if res is None:
                return res
            elif isinstance(res, tuple):
                row_dict = self._get_dict_from_tuple(res)
                return row_dict.get('port_id')

        except Exception as err:
            msg = "Exception occurred while getting port id"\
                  "from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_instance_info(self, instance_id, vpn_fw="vyos"):
        """Gets instance info for corresponding instance_id and vpn_fw
        type Input: instance_id and optionally vpn_fw type which takes
        values either vyos or asav.
        Output: on success returns dictionary as follows
                       {'status': 'ACTIVE',
                        'stitching_port_id': '',
                        'tenant_id': '',
                        'provider_port_id': '',
                        'service_vm_id': '',
                        'id': '',
                        'plugged_in_provider_port_id': '',
                        'plugged_in_stitching_port_id': ''}
        In case of vyos/haproxy, return dictionary will not have
        plugged_in provider_port_id and plugged_in_stitching_port_id
        On failure: returns None"""
        try:
            # LOG_OBJ.debug(In get_instance_info)
            instance_dict = self.get_from_instance_info_helper(
                                instance_id)
            if not isinstance(instance_dict, dict):
                LOG_OBJ.error("Not able to retreive instance info details")
                return None
            if vpn_fw.lower() == "asav":
                plugged_in_provider_pt_id = self.get_plugged_in_pt_id(
                                                    instance_id)
                port_id = self.get_port_id(plugged_in_provider_pt_id)
                instance_dict["plugged_in_provider_port_id"] = port_id
                plugged_in_stitching_pt_id = self.get_plugged_in_pt_id(
                                                    instance_id,
                                                    "stitching_port_id")
                port_id = self.get_port_id(plugged_in_stitching_pt_id)
                instance_dict["plugged_in_stitching_port_id"] = port_id
                return instance_dict
            return instance_dict

        except Exception as err:
            msg = "Exception occurred in get_instance_info"\
                  "from db: %s" % err
            LOG_OBJ.exception(msg)
            return None

    def get_details_from_ptg_id(self, provider_ptg_id, service_type="FIREWALL",
                                vpn_fw="vyos"):
        """Returns tuple (active, standby) service details required for
        sending traffic.
        input: provider_ptg_id, service_type and vpn_fw type
        output: on success returns dictionary same as in get_instance_info
        method. On failure returns None"""
        try:
            sc_id = self.get_sc_id_from_ptg_id(provider_ptg_id)
            active_instance_id = self.get_active_instance_id(sc_id,
                                                             service_type)
            standby_instance_id = self.get_standby_instance_id(
                                        active_instance_id)
            if ((service_type.upper() == "FIREWALL") or
                (service_type.upper() == "VPN")) and \
               (vpn_fw.lower() == "asav"):
                return (self.get_instance_info(active_instance_id, "asav"),
                        self.get_instance_info(standby_instance_id, "asav"))
            return (self.get_instance_info(active_instance_id),
                    self.get_instance_info(standby_instance_id))
        except Exception as err:
            print err
            msg = "Exception occurred while getting details from ptg_id"\
                  "from db: %s" % err
            LOG_OBJ.exception(msg)
            return None
