"""
A module that provides wrappers on Keystone, Neutron and Nova clients.
This module is tested using clients with below versions:
python-openstackclient: 2.4.0
python-neutronclient: 4.2.0
python-novaclient: 4.0.0
python-keystoneclient: 2.3.1
"""

from contextlib import contextmanager
from decorator import decorator
from keystoneclient import session as ksc_session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client as keystone_v3
from neutronclient.v2_0.client import Client as neutron_client
from novaclient import client as nova_client

import atf.config.common_config as config
import atf.config.setup_config as setup_config
# import sys
# sys.path.append("../../")
import atf.lib.nvp_atf_logging as log

LOG = log.get_atf_logger()


class KeystoneDriver():
    """Wrapper class (helper) to create project, user etc.

    NOTE:
        a. If we have to go back to v2.0 then the domain_id has to
            be removed from the body of the request in __create_resource__
        b. The project in v3 is tenant in v2. So the create, list, show
            apis should take care of those conversion.
        c. v2 has also session based authentication
            [so ignore domain while creating auth]
    """

    cloud_admin_info = {"project_name": "",
                        "project_id": "",
                        "user_name": "",
                        "user_id": "",
                        "session": None}
    keystone_admin = None
    version = "v3"  # v2.0/v3
    host_ip = setup_config.setupInfo['os-controller-node']['pubip']
    # auth_url = "http://%s:35357/%s" % (host_ip, version)
    auth_url = "http://%s:5000/%s" % (host_ip, version)

    def __init__(self):
        """
        :param str os_pub_ip: Public IP of the OpenStack node.
        :param str version: Keystone api version (v2.0/v3)
        """
        # url = "http://" + self.host_ip + ":35357/"
        # self.auth_url = url + version
        # self.set_cloud_admin_info()
        # Below two are initialized by create_tenant/set_project_context
        # self.project_info = None
        # self.keystone = None
        pass

    @staticmethod
    def get_keystone_auth_session(project_type="admin", project_info=None,
                                  **kwargs):
        '''This gives the authentication session object which will be used
        to create respective client object.

        :param project_type str: Project type. (admin/non-admin)
        :param project_info dict: Full detail info of the project.
                Ignore this if it is admin project
        :optional params:
            domain_name: Name of the project and user domain,
                        if the set up is domain based.
        :return session object.
        '''
        try:
            temp_kwargs = {}
            if project_type.lower() == "admin":
                if KeystoneDriver.cloud_admin_info['session']:
                    return KeystoneDriver.cloud_admin_info['session']

                temp_kwargs['username'] = config.cloud_admin_user
                temp_kwargs['password'] = config.cloud_admin_passwd
                temp_kwargs['project_name'] = config.cloud_admin_project
                if config.is_setup_domain_based:
                    temp_kwargs['user_domain_name'] = config.cloud_admin_domain
                    temp_kwargs['project_domain_name'] = \
                        config.cloud_admin_domain
            else:
                temp_kwargs['username'] = project_info['user_name']
                temp_kwargs['password'] = project_info['password']
                temp_kwargs['project_name'] = project_info['project_name']
                if config.is_setup_domain_based:
                    temp_kwargs['user_domain_name'] = kwargs["domain_name"]
                    temp_kwargs['project_domain_name'] = kwargs["domain_name"]

            auth = v3.Password(auth_url=KeystoneDriver.auth_url, **temp_kwargs)
            session = ksc_session.Session(auth=auth)

            return session
        except Exception as err:
            LOG.exception(err)

    @staticmethod
    def set_cloud_admin_info():
        """It will initialize the cloud admin and keystone_admin"""
        try:
            if KeystoneDriver.cloud_admin_info["project_name"]:
                return True

            kdr = KeystoneDriver
            session = KeystoneDriver.get_keystone_auth_session()
            keystone_admin = keystone_v3.Client(session=session)
            kdr.keystone_admin = keystone_admin

            admin_prj = keystone_admin.projects.list(name=config.admin_tenant)
            if len(admin_prj):
                project_id = admin_prj[0].id
            else:
                LOG.error("Unable to get admin tenant:%s details.",
                          config.admin_tenant)
                return
            admin_user = keystone_admin.users.list(name=config.admin_user)
            if len(admin_user):
                user_id = admin_user[0].id
            else:
                LOG.error("Unable to get admin user: %s details.",
                          config.admin_user)
            kdr.cloud_admin_info["project_name"] = config.admin_tenant
            kdr.cloud_admin_info["project_id"] = project_id
            kdr.cloud_admin_info["user_name"] = config.cloud_admin_user
            kdr.cloud_admin_info["user_id"] = user_id
            if config.is_setup_domain_based:
                kdr.cloud_admin_info["user_domain"] = \
                    kdr.cloud_admin_info["project_domain"] = \
                    config.cloud_admin_domain
            kdr.cloud_admin_info['session'] = session

            # self.cloud_admin_info["token_project"]=keystone_admin.auth_token
            LOG.debug("Cloud admin info is set.")
            return True
        except Exception as err:
            LOG.exception(err)
            return False

    # Common Identity API for LIST
    @staticmethod
    def list_identity_resource(resource, **kwargs):
        '''A generic function to list the keystone resource.
        :param resource str: Name of the resource.
                Ex: domain/project/group/user/role
        :return on success: a list of dicts containing all resource details.
        '''
        try:
            resource_list = []
            results = eval("KeystoneDriver.keystone_admin.%ss.list" %
                           resource)(**kwargs)
            for res in results:
                resource_list.append(res.to_dict())
            # LOG.info("List of %s: %s", resource, resource_list)
            return resource_list
        except Exception as err:
            LOG.error("Unable to list %s", resource)
            LOG.exception(err)

    # Common Identity API for SHOW
    @staticmethod
    def get_identity_resource(resource, resource_name=None, resource_id=None,
                              only_id=False, **kwargs):
        '''It is a generic function that returns the keystone resource id
        based on the resource name.
        :param resource str: Name of the keystone resource
                    resource: domain/projec/group/user/role ,etc
        :param resource_name str: Name of the resource whose info is required.
        :param resource_id unicode: ID of the resource.
        :param only_id bool: True to get full detail, False to get only
                             ID of the resource.
        :optional params:
            domain_id, default_project_id
        :return on success: dict, if only_id is False else unicode
        '''
        try:
            if resource_id:
                kwargs['id'] = resource_id
            elif resource_name:
                kwargs['name'] = resource_name
            elif not len(kwargs):
                LOG.error("To get %s provide either id or name", resource)
                return
            results = KeystoneDriver.list_identity_resource(resource, **kwargs)
            if not results:
                LOG.info("%s with %s: %s could not be found",
                         resource, kwargs.keys()[0], kwargs.values()[0])
                return
            LOG.info("%s details: %s", resource, results)
            if len(results) > 1:
                LOG.warning("Multiple %s with %s:%s found", resource,
                            kwargs.keys()[0], kwargs.values()[0])
            res = results[0]
            if only_id:
                return res['id']
            return res
        except Exception as err:
            LOG.error("Unable to get %s with %s:%s", resource,
                      kwargs.keys()[0], kwargs.values()[0])
            LOG.exception(err)
            """
            # res = eval("KeystoneDriver.keystone_admin.%ss.list" %
            #           resource)(name=resource_name)
            # res is a list of resource objects. ex: ID = res[0].id
            if resource_name is not None:
                kwargs['name'] = resource_name
            res = eval("KeystoneDriver.keystone_admin.%ss.find" %
                       resource)(**kwargs)
        except Exception as err:
            LOG.error("The %s with %s:%s either doesn't exist or there are "
                      "multiple of such resource", resource,
                      kwargs.keys()[0], kwargs.values()[0])
            LOG.exception(err)
            return

        res = res.to_dict()
        LOG.info("Detail of %s with name: %s is %s",
                 resource, resource_name, res)
        if detail_info:
            return res
        return res['id']
        """

    # Common Identity API for DELETE
    @staticmethod
    def delete_identity_resource(resource, resource_id=None, **kwargs):
        '''It is a generic function that deletes the identity resources based
        on id or name of the resource.
        :param resource str: Name of the keystone resource
                    Ex: resource: domain/projec/group/user/role ,etc
        :param resource_id unicode: ID of the resource to be deleted..
                    Ex: resource: domain, resource_id: "sss234rf"
        :optional param:
            resource_name: Name of the resource to be deleted.
            ex: resource_name: dummy-project
        '''
        try:
            if resource_id is None:
                # Get the resource id from resource name.
                if kwargs.get('resource_name') is None:
                    LOG.error("Provide either resource id or name to delete.")
                    return
                resource_id = KeystoneDriver.get_identity_resource(
                    resource, resource_name=kwargs['resource_name'],
                    only_id=True)
                if resource_id is None:
                    return
            # To delete domain, first disable it.
            if resource == "domain":
                KeystoneDriver.keystone_admin.domains.update(
                    domain=resource_id, enabled=False)
            out = eval("KeystoneDriver.keystone_admin.%ss.delete" %
                       resource)(resource_id)
            if out:
                response = out[0]
                # response.status_code, response.headers, response.text
                if response.status_code not in range(200, 300):
                    LOG.error("Resource:%s with ID: %s couldn't be deleted.",
                              resource, resource_id)
                    return False
            LOG.info("Deleted %s with ID: %s.", resource, resource_id)
            return True
        except Exception as err:
            LOG.error("Unable to delete %s with id=%s", resource, resource_id)
            LOG.exception(err)
            return False

    @staticmethod
    def __create_resource__(resource, body):
        """A generic function that creates identity resources
        :param resource str: Name of the resource. domain/project/user
        :param: body dict: Input dictionary to create a resource.

        :return unicode on success.
        """
        try:
            cmd = "KeystoneDriver.keystone_admin.%ss.create" % resource
            result = eval(cmd)(**body)
            LOG.info("Created %s with details:%s", resource, result.to_dict())
            return result.id
        except Exception as err:
            LOG.error("Unable to create :%s", resource)
            LOG.exception(err)

    @staticmethod
    def create_domain(domain_name):
        '''Create a v3 domain.
        :param domain_name str: Name of the domain.
        :return domain id in unicode.
        '''
        return KeystoneDriver.__create_resource__(
                "domain", {"name": domain_name})

    @staticmethod
    def create_group(group_name, domain_id):
        '''Create a v3 group.
        :param group_name str: name of the group.
        :param domain_id unicode: ID of the domain.
        :return group id in unicode, on success.
        '''
        body = {"name": group_name, "domain": domain_id}
        return KeystoneDriver.__create_resource__("group", body)

    @staticmethod
    def add_user_to_group(user_id, group_id):
        '''Add user to a group.
        :param user_id unicode: ID of the user.
        :param group_id unicode: ID of the group.
        :return boolean: True on success
        '''
        try:
            KeystoneDriver.keystone_admin.users.add_to_group(user_id, group_id)
            LOG.debug("User:%s is added to group:%s", user_id, group_id)
            return True
        except Exception as err:
            LOG.error("Unable to add user:%s in group:%s", user_id, group_id)
            LOG.exception(err)
            return False

    @staticmethod
    def add_role(role_name, group_id=None, **kwargs):
        '''
        a. Add a user with a specific role in domain or
        b. Add a user with a specific role in project or
        c. Add a group to a project with a role or
        d. Add a group to a domain with a role or

        Add a group to a project/domain with a specific role.
        When the group is added to a project/domain with a role x then all
        the members of the group are by default have a role x.

        :param role_name str: name of the role.
        :param group_id:
        :optional params:
            :param project_id: ID of the project.
            :param domain_id: ID of the domain.
            :param role_id: ID of the role.
        '''
        try:
            role_id = kwargs.get('role_id')
            if not role_id:
                role_id = KeystoneDriver.get_identity_resource(
                    "role", resource_name=role_name, only_id=True)
                if not role_id:
                    return False
            kwa = {}
            if kwargs.get('project_id'):
                kwa['project'] = kwargs.get('project_id')
            elif kwargs.get('domain_id'):
                kwa['domain'] = kwargs.get('domain_id')
            else:
                msg = "Specify either a project or domain to which the" \
                    " %s will be added with a role."
                msg = msg % ("group" if group_id else "user")
                LOG.debug(msg)
                return False
            gr_or_usr = group_id
            if gr_or_usr is None:
                gr_or_usr = kwargs.get("user_id")
                kwa['user'] = gr_or_usr
            KeystoneDriver.keystone_admin.roles.grant(
                role=role_id, group=group_id, **kwa)
            LOG.debug("Group/User:%s is added to %s with role: %s",
                      gr_or_usr, kwa.keys()[0], role_id)
            return True
        except Exception as err:
            LOG.error("Unable to add role:%s to project/domain.", role_name)
            LOG.exception(err)
            return False

    @staticmethod
    def create_project(project_name, domain_id):
        '''It creates a project
        :param project_name str: Name of the project
        :param domain_id unicode: ID of the domain.
        :return project id in unicode, on success.
        '''
        body = {"name": project_name, "domain": domain_id}
        return KeystoneDriver.__create_resource__("project", body)

    @staticmethod
    def create_user(user_name, password, domain_id, **kwargs):
        '''Create a v3 user.
        :param user_name str: Name of the user
        :param password str: password for user.
        :param domain_id unicode: ID of the domain.
        :param project_name str: Name of the project.

        :optional  params:
            default_project_name
            project_id
            group_name, etc ...
        :return User ID in unicode, on success.
        '''
        body = {"name": user_name, "password": password, "domain": domain_id}
        return KeystoneDriver.__create_resource__("user", body)

    @staticmethod
    def create_project_helper(project_info, **kwargs):
        """It creates a project, group, user. Adds the user to the group
        and then adds the group to the project with the specified role(s).

        :params dictionary project_info
            {project_name str: Name of the project
            user_name str: User name in the project
            password str: Password of the user.
            roles list: role list
            }
        :optional params:
            group_name str: Name of the group
            domain_name str: Name of the domain.
        :return dictionary containing details of the project.
        """
        try:
            LOG.debug("Creating Project ...")
            domain_name = kwargs.get("domain_name", config.cloud_admin_domain)
            domain_id = KeystoneDriver.get_identity_resource(
                "domain", resource_name=domain_name, only_id=True)
            if not isinstance(domain_id, unicode):
                # Create domain, if not created before.
                LOG.debug("Creating domain: %s", domain_name)
                domain_id = KeystoneDriver.create_domain(domain_name)
                if not isinstance(domain_id, unicode):
                    return
            # Create project.
            project_id = KeystoneDriver.create_project(
                project_info['project_name'], domain_id)
            if not isinstance(project_id, unicode):
                return
            project_info['project_id'] = project_id
            project_info['domain_name'] = domain_name
            project_info['domain_id'] = domain_id
            # Create user
            user_info = KeystoneDriver.create_user_helper(
                  user_name=project_info['user_name'],
                  password=project_info['password'],
                  domain_name=domain_name,
                  roles=project_info.get('roles'),
                  default_project_name=project_info['project_name'],
                  group_name=kwargs.get("group_name", "default-group"))
            if not isinstance(user_info, dict):
                LOG.error("problem while creating user and "
                          "corresponding resources.")
                return

            project_info.update(user_info)
            LOG.debug("Project info:%s", project_info)
            return project_info

        except Exception as err:
            LOG.exception(err)

    @staticmethod
    def create_user_helper(user_name, password,
                           domain_name=None,
                           roles=None, **kwargs):
        '''It creates the user, adds the role to the project/domain.
        If group name is passed then it adds the user to the group and adds the
        group to the project/domain with a specific role.

        :param user_name str: Name of the user.
        :param password str: Password for user.
        :param: domain_name str: Name of the domain.
        :param roles list: List of roles.

        :optional params
            :param default_project_name str: Name of the project
            :param group_name str: Name of the group.
            :param add_role_with_project boolean: a flag tells whether the user
                will be added to the project with a specific roles.
                Default: True, if False then it will be added to the domain.


        :return dictionary containing the user details.
        '''
        try:
            LOG.debug("Creating user ...")
            user_info = {}
            user_info['user_name'] = user_name
            user_info['password'] = password
            group_id = None
            project_id = None
            project_name = kwargs.get('default_project_name')
            if project_name:
                project_id = KeystoneDriver.get_identity_resource(
                    "project", resource_name=project_name, only_id=True)
                if project_id is None:
                    return
            if domain_name is None:
                domain_name = config.cloud_admin_domain
            domain_id = KeystoneDriver.get_identity_resource(
                "domain", resource_name=domain_name, only_id=True)
            if domain_id is None:
                return
            user_info['domain_id'] = domain_id
            # create group, if any
            if kwargs.get('group_name'):
                group_id = KeystoneDriver.get_identity_resource(
                    "group", resource_name=kwargs['group_name'], only_id=True)
                if not isinstance(group_id, unicode):
                    # Create a new group.
                    group_id = KeystoneDriver.create_group(
                        kwargs['group_name'], domain_id)
                    if group_id is None:
                        return
                user_info['group_name'] = kwargs['group_name']
                user_info['group_id'] = group_id
            # Create user
            uid = KeystoneDriver.create_user(
                user_name, password, domain_id, **kwargs)
            if not isinstance(uid, unicode):
                return
            # Add user to group and add group to the project/domain with a role
            if group_id:
                if not KeystoneDriver.add_user_to_group(uid, group_id):
                    return
            LOG.debug("User details:%s", user_info)
            if roles is None:
                return user_info
            args = {}
            if kwargs.get('add_role_with_project', True):
                args['project_id'] = project_id
            else:
                args['domain_id'] = domain_id

            # Assign role.
            for role_name in roles:
                if group_id:
                    status = KeystoneDriver.add_role(
                        role_name, group_id, **args)
                else:
                    status = KeystoneDriver.add_role(
                         role_name, user_id=uid, **args)
                if not status:
                    return

            return user_info
        except Exception as err:
            LOG.exception(err)


class ClientHelper(object):
    """Common class which has common functions for all the clients."""
    def __init__(self):
        # The child has to initialize these.
        self.nova = None
        self.neutron = None

    # LIST API HELPER
    def _list_resource_(self, client_name, resource, **kwargs):
        '''A generic function to list the nova, neutron resources.
        :param client_name str: Name of the client. Ex: nova/neutron
        :param resource str: Name of the resource.
                Ex: server/image/flavor/network/subnet etc.
        :return on success: a list of dicts containing all resource details.
        '''
        try:
            cmd = "self.nova.%ss.list" % resource
            if client_name == "neutron":
                # Neutron by default prepares the list of dict.
                # Ex: networks = {'networks': [{}, {}]}
                cmd = "self.neutron.list_%ss" % resource
                return eval(cmd)(**kwargs).values()[0]
            resource_list = []
            results = eval(cmd)(**kwargs)
            for res in results:
                resource_list.append(res.to_dict())
            return resource_list
        except Exception as err:
            LOG.error("Unable to list %s", resource)
            LOG.exception(err)

    # DELETE API HELPER
    def _delete_resource_(self, client_name, resource, resource_id, **kwargs):
        '''It's a generic function that deletes the resources corresponding
        to nova, neutron based on id.
        :param client_name str: Name of the client. Ex: nova/neutron
        :param resource str: Name of the resource.
                Ex: server/image/flavor/network/subnet etc.
        :param resource_id unicode: ID of the resource.
                        Ex: id of network, subnet, server, port etc.
        :optional params:
            resource_name str: Name of the resource to delete.

        :return True on success.
        '''
        try:
            cmd = "self.nova.%ss.delete" % resource
            if client_name == "neutron":
                cmd = "self.neutron.delete_%s" % resource
            out = eval(cmd)(resource_id)
            if out:
                response = out[0]
                # response.status_code, response.headers, response.text
                if response.status_code not in range(200, 300):
                    LOG.error("Resource:%s with ID: %s couldn't be deleted.",
                              resource, resource_id)
                    return False
            LOG.info("Deleted %s with ID: %s.", resource, resource_id)
            return True
        except Exception as err:
            LOG.error("Unable to delete %s with id=%s", resource, resource_id)
            LOG.exception(err)
            return False

    # SHOW API HELPER
    @staticmethod
    @decorator
    def _get_resource_(func, self, resource, resource_name=None,
                       resource_id=None, only_id=False, **kwargs):
        '''A generic function to get the nova., neutron resource
        based on name or id.
        :param resource str: Name of the resource.
            Ex: server/image/flavor  network/router/subnet/port
        :param resource_name str: Name of the resource whose info is required.
        :param resource_id unicode: ID of the resource.
        :param only_id bool: True to get full detail, False to get only
                             ID of the resource.
        '''
        try:
            if resource_id:
                kwargs["id"] = resource_id
            elif resource_name:
                kwargs['name'] = resource_name
            elif not kwargs:    # To support advanced search.
                LOG.error("To get '%s' either provide name or ID", resource)
                return
            # Execute client command and get result.
            res = func(self, resource, resource_name, resource_id,
                       only_id=False, **kwargs)
            if not isinstance(res, dict):
                return
            LOG.debug("Detail of %s with %s:%s is %s", resource,
                      kwargs.keys()[0], kwargs.values()[0], res)
            if only_id:
                return res['id']
            return res
        except Exception as err:
            LOG.error("Unable to get %s with %s: %s.",
                      resource, kwargs.keys()[0], kwargs.values()[0])
            LOG.exception(err)


class NovaDriver(object):
    """Wrapper abova novaclient module to call nova rest api's"""
    def __init__(self):
        # The child is expected to initialize this nova
        self._nova = None
        self.helper = ClientHelper()

    @property
    def nova(self):
        return self._nova

    @nova.setter
    def nova(self, nova_client_obj):
        self._nova = nova_client_obj
        self.helper.nova = self._nova

    # Common nova API for LIST
    def list_nova_resource(self, resource, **kwargs):
        '''A generic function to list the nova resource.
        :param resource str: Name of the resource. Ex: server/image/flavor
        :return on success: a list of dicts containing all resource details.
        '''
        return self.helper._list_resource_("nova", resource, **kwargs)

    # Common nova API for SHOW
    @ClientHelper._get_resource_
    def get_nova_resource(self, resource, resource_name=None,
                          resource_id=None, only_id=False, **kwargs):
        '''A generic function to get the nova resource based on name/id.
        :param resource str: Name of the resource. Ex: server/image/flavor
        :param resource_name str: Name of the resource whose info is required.
        :param resource_id unicode: ID of the resource.
        :param only_id bool: True to get full detail, False to get only
                             ID of the resource.
        :optional params:
            id, tenant_id
        :return on success: dict, if only_id is False else unicode
        '''
        # NOTE: this kwargs is filled by decorator.
        res = eval("self.nova.%ss.findall" % resource)(**kwargs)
        if not res:
            LOG.info("No %s found with %s: %s", resource,
                     kwargs.keys()[0], kwargs.values()[0])
            return
        if len(res) > 1:
            LOG.warning("Multiple %ss match with %s:%s. Use ID to be more "
                        "specific.", resource, kwargs.keys()[0],
                        kwargs.values()[0])
        res = res[0].to_dict()
        return res

    # Common nova API for DELETE
    def delete_nova_resource(self, resource, resource_id=None, **kwargs):
        '''It's a generic function that deletes the resources corresponding
        to nova based on id or name.
        :param resource str: Name of the nova resource
                    Ex: resource: server, image, flavor
        :param resource_id unicode: ID of the resource to be deleted..
                    Ex: resource: server, resource_id: "vm id"
        :optional param:
            resource_name: Name of the resource to be deleted.
            ex: resource_name: test-vm
        :return True on success.
        '''
        if resource_id is None:
            # Get the resource id from resource name.
            if kwargs.get('resource_name') is None:
                LOG.error("Provide either resource id or name to delete.")
                return False
            resource_id = self.get_nova_resource(
                resource, resource_name=kwargs['resource_name'],
                only_id=True)
            if resource_id is None:
                return False
        return self.helper._delete_resource_("nova", resource,
                                             resource_id, **kwargs)

    def create_server(self, server_name, image_id, flavor, network_ids):
        """ Creates Nova instance.

        :param str server_name: nova instance name.
        :param str image_id: glance image_id to launch nova instance
        :param str flavor: flavor to launch instance
                (e.g. '1', '2', '3', ...)
        :param str network_ids: list of network ids.
                (e.g. [net-id-1, net-id-2, ...])
        """
        try:
            nics = []
            for net_id in network_ids:
                nics.append({'net-id': net_id})
            instance_info = self.nova.servers.create(server_name, image_id,
                                                     flavor, nics=nics)
            return instance_info.id
        except Exception as err:
            LOG.exception(err)


class NeutronDriver(object):
    """Wrapper above neutronclient module to call neutron rest api's"""
    def __init__(self):
        # The child is expected to initialize this neutron
        self._neutron = None
        self.helper = ClientHelper()

    @property
    def neutron(self):
        return self._neutron

    @neutron.setter
    def neutron(self, neutron_client_obj):
        self._neutron = neutron_client_obj
        self.helper.neutron = self._neutron

    # Common neutron API for LIST
    def list_neutron_resource(self, resource, **kwargs):
        '''A generic function to list the neutron resource.
        :param resource str: Name of the resource.
                Ex: router, floatingip, network, subnet, port,
                pool, vip, member, monitor/health_monitor,
                firewall, firewall_policy, firewall_rule, etc
        :return on success: a list of dicts containing all resource details.
        '''
        if resource.lower() == "monitor":
            resource = "health_monitor"
        if resource.lower() == "firewall_policy":
            resource = "firewall_policie"  # 's' is appended in helper.
        return self.helper._list_resource_("neutron", resource, **kwargs)

    # Common neutron API for SHOW
    @ClientHelper._get_resource_
    def get_neutron_resource(self, resource, resource_name=None,
                             resource_id=None, only_id=False, **kwargs):
        '''A generic function to get the neutron resource.
        :param resource str: Name of the resource.
            Ex: router, floatingip, network, subnet, port,
            pool, vip, member, monitor/health_monitor, firewall,
            firewall_policy, firewall_rule, etc
        :param resource_name str: Name of the resource whose info is required.
        :param resource_id unicode: ID of the resource.
        :param only_id bool: True to get full detail, False to get only
                             ID of the resource.
        :return on success: dict, if only_id is False else unicode
        '''
        # NOTE: this kwargs is filled by decorator.
        res = self.list_neutron_resource(resource, **kwargs)
        if not res:
            LOG.info("No %s found with %s:%s", resource,
                     kwargs.keys()[0], kwargs.values()[0])
            return
        elif len(res) > 1:
            LOG.warning("Multiple %ss match with %s:%s. Use ID to be more "
                        "sprcific.", resource, kwargs.keys()[0],
                        kwargs.values()[0])
        return res[0]

    # Common neutron API for DELETE
    def delete_neutron_resource(self, resource, resource_id=None, **kwargs):
        '''It's a generic function that deletes the resources corresponding
        to neutron based on id or name.
        :param resource str: Name of the neutron resource
                    Ex: resource: router, network, subnet, port
        :param resource_id unicode: ID of the resource to be deleted..
                    Ex: resource: network, resource_id: "network id"
        :optional param:
            resource_name: Name of the resource to be deleted.
            ex: resource_name: test-network
        :return True on success.
        '''
        if resource_id is None:
            # Get the resource id from resource name.
            if kwargs.get('resource_name') is None:
                LOG.error("Provide either resource id or name to delete.")
                return False
            resource_id = self.get_neutron_resource(
                resource, resource_name=kwargs['resource_name'],
                only_id=True)
            if resource_id is None:
                return False
        return self.helper._delete_resource_("neutron", resource,
                                             resource_id, **kwargs)

    def __create_resource__(self, body, **kwargs):
        """A generic function that creates neutron resources
        :param: body dict: Input dictionary to create a resource.

        :return unicode on success.
        """
        try:
            resource_name = body.keys()[0]
            cmd = "self.neutron.create_%s" % resource_name
            result = eval(cmd)(body=body, **kwargs)
            LOG.info("Output of create_%s: %s", resource_name, result)
            if not isinstance(result, dict):
                LOG.error("Unable to create %s", resource_name)
                return
            if not result[resource_name].get('id'):
                LOG.error("Problem while creating %s", resource_name)
                return
            _id = result[resource_name]['id']
            LOG.info("%s is created with ID: %s", resource_name, _id)
            return _id
        except Exception as err:
            LOG.error("Unable to create :%s", resource_name)
            LOG.exception(err)

    def create_network(self, name, **kwargs):
        """Create neutron network
        :param str name: Name to assign to neutron network.
        """
        body = {'network': {'name': name, 'admin_state_up': True}}
        return self.__create_resource__(body=body, **kwargs)

    def create_subnet(self, network_id, subnet_cidr, name="", **kwargs):
        """Creates nutron subnet.

        :param str name: subnet name
        :param str subnet_cidr: subnet cidr (e.g. 13.3.3.0/24)
        :param str network_id: uuid of network, in which subnet
                        will be created.
        """
        body = {'subnet': {'name': name, 'network_id': network_id,
                           'cidr': subnet_cidr, 'ip_version': 4}}
        return self.__create_resource__(body=body, **kwargs)

    def create_router(self, name, **kwargs):
        """Creates neutron router

        :param str name: router name
        """
        body = {'router': {'name': name}}
        return self.__create_resource__(body=body, **kwargs)

    def create_floatingip(self, ext_net_id=None, **kwargs):
        """Create floating ip address
        :param str ext_net_id: external network uuid.
        :optional params
            ext_net_name: Name of the external network.
        """
        if ext_net_id is None:
            ext_net_id = self.get_neutron_resource(
                "network", resource_name=kwargs['ext_net_name'], only_id=True)
            if ext_net_id is None:
                return

        body = {'floatingip': {'floating_network_id': ext_net_id}}
        return self.__create_resource__(body=body, **kwargs)

    def create_firewall_rule(self, protocol, action, name="", **kwargs):
        """Creates firewall rule.

        :param str name: firewall rule name
        :param str protocol: protocol (e.g. tcp/udp/icmp)
        :param str action: action (e.g. deny/allow)
        :param str source_ip_address: (optional)
        :param str source_port: (optional)
        :param str destination_port: (optional)
        :param str destination_ip_address: (optional)
        """
        body = {'firewall_rule': {'action': action, 'protocol': protocol,
                                  'name': name}}
        fwr = body['firewall_rule']
        if kwargs.get('source_ip_address'):
            fwr['source_ip_address'] = kwargs['source_ip_address']
        if kwargs.get('source_port'):
            fwr['source_port'] = kwargs['source_port']
        if kwargs.get('destination_ip_address'):
            fwr['destination_ip_address'] = kwargs['destination_ip_address']
        if kwargs.get('destination_port'):
            fwr['destination_port'] = kwargs['destination_port']
        return self.__create_resource__(body=body, **kwargs)

    def create_firewall_policy(self, name, fw_rule_ids, **kwargs):
        """Creates firewall policy
        :param str name: firewall policy name
        :param str fw_rule_ids: firewall rule id list
        """
        body = {'firewall_policy': {'name': name, 'firewall_rules': []}}
        body['firewall_policy']['firewall_rules'].extend(fw_rule_ids)
        return self.__create_resource__(body=body, **kwargs)

    def create_firewall(self, router_ids, policy_id, name="", **kwargs):
        """Creates firewall.
        :param str name: firewall name
        :param str router_ids: list of router ids
        :param str policy_id: firewall policy id
        """
        body = {'firewall': {'name': name, 'router_ids': router_ids,
                             'firewall_policy_id': policy_id}}
        return self.__create_resource__(body=body, **kwargs)

    def create_lb_pool(self, name, subnet_id, lb_method="ROUND_ROBIN",
                       protocol="TCP", **kwargs):
        """Creates loadbalacer pool.

        :param str name: pool name
        :param str lb_method: loadbalancing method
            (e.g ROUND_ROBIN, LEAST_CONNECTIONS, SOURCE_IP)
        :param str subnet_id: subnet_id
        :param str protocol: (TCP/HTTP/HTTPS)
        """
        body = {'pool': {'name': name, 'lb_method': lb_method,
                         'subnet_id': subnet_id, 'protocol': protocol}}
        return self.__create_resource__(body=body, **kwargs)

    def create_lb_vip(self, name, subnet_id, pool_id, protocol="TCP",
                      protocol_port="80", **kwargs):
        """Creates loadbalacer virtual ip address

        :param str name: lb vip name
        :param str protocol: (e.g. HTTP/HTTPS/TCP)
        :param int protocol_port: protocol port  (e.g. 80)
        :param str subnet_id:
        :param str pool_id: lb pool id
        """
        body = {'vip': {'name': name, 'protocol': protocol,
                        'protocol_port': protocol_port,
                        'subnet_id': subnet_id,
                        'pool_id': pool_id}}
        return self.__create_resource__(body=body, **kwargs)

    def create_lb_monitor(self, monitor_type="PING", delay=10, timeout=5,
                          max_retries=1, **kwargs):
        '''Createa healthmonitor for members of a lb-pool.

        :param monitor_type str: Type of Monitor (PING/TCP/HTTP/HTTPS)
        :param delay int: Amount of delay to send next request.
        :param timeout int: Amount of time to wait for response.
                            NOTE: timeout < delay
        :param max_retries int: No. of retries for checking health.
        '''
        body = {"health_monitor": {"type": monitor_type, "timeout": timeout,
                                   "delay": delay, "max_retries": max_retries}}
        _hm = body['health_monitor']
        if monitor_type.lower() in ["http", "https"]:
            _hm['expected_codes'] = kwargs.get('expected_codes', "200")
            _hm['http_method'] = kwargs.get('http_method', "GET")
            _hm['url_path'] = kwargs.get('url_path', "/")
        return self.__create_resource__(body=body, **kwargs)

    def associate_or_disassociate_lb_monitor(self, pool_id, health_monitor_id,
                                             operation="associate"):
        '''Associates/Disassociate health monitor to/from lb pool

        :param pool_id unicode: ID of the pool.
        :param health_monitor_id unicode: ID of the monitor
        :param operation str: Operation name (associate/disassociate)
        '''
        try:
            hmon = {'health_monitor': {'id': health_monitor_id}}
            if operation.lower() != "associate":
                operation = "disassociate"
                hmon = health_monitor_id
            cmd = "self.neutron.%s_health_monitor" % operation.lower()
            eval(cmd)(pool_id, hmon)
            LOG.info("Monitor:%s is %sed with pool:%s",
                     health_monitor_id, operation, pool_id)
            return True
        except Exception as err:
            LOG.exception(err)
            return False

    def create_lb_member(self, pool_id, server_ip, protocol_port="80",
                         weight=1, **kwargs):
        """Adds web servers to the loadbalacer pool.

        :param str pool_id: loadbalacer pool id
        :param int protocol_port: (e.g. 80)
        :param int weight: weight to web server. (e.g. 1, 2, 3, ..)
        :param str server_ip: web server ip address (e.g. 13.3.3.14)
        """
        body = {'member': {'pool_id': pool_id, 'protocol_port': protocol_port,
                           'weight': weight, 'address': server_ip}}
        return self.__create_resource__(body=body, **kwargs)

    def add_router_interface(self, router_id, subnet_id):
        """Attach subnet to router

        :param str router_id: router id
        :param str subnet_id: subnet_id
        """
        try:
            body = {'subnet_id': subnet_id}
            self.neutron.add_interface_router(router_id, body=body)
            LOG.info("Subnet: %s is attached with rouiter:%s",
                     subnet_id, router_id)
            return True
        except Exception as err:
            LOG.exception(err)
            return False

    def set_router_gateway(self, router_id, ext_net_id=None, **kwargs):
        """Sets router gateway to external network

        :param str router_id:
        :param str ext_net_id: external network id
        :optional params:
            ext_net_name: Name of external network.
        """
        try:
            if ext_net_id is None:
                ext_net_id = self.get_neutron_resource(
                    "network", resource_name=kwargs['ext_net_name'],
                    only_id=True)
                if ext_net_id is None:
                    return
            body = {'network_id': ext_net_id}
            self.neutron.add_gateway_router(router_id, body=body)
            LOG.info("Router:%s is set to ext-gw:%s", router_id, ext_net_id)
            return True
        except Exception as err:
            LOG.exception(err)
            return False

    def delete_router_interface(self, router_id, subnet_id):
        try:
            self.neutron.remove_interface_router(
                router_id, body={'subnet_id': subnet_id})
            LOG.info("Subnet: %s is detached from rouiter:%s",
                     subnet_id, router_id)
            return True
        except Exception as err:
            LOG.exception(err)
            return False

    def clear_router_gateway(self, router_id):
        try:
            self.neutron.remove_gateway_router(router_id)
            return True
            LOG.info("Router:%s is detached from ext-gw", router_id)
        except Exception as err:
            LOG.exception(err)
            return False

    def update_floatingip(self, floatingip_id, **kwargs):
        """Updates floating ip resource

        :param str name: (optional)
        :param str description: (optional)
        :param str port_id: (optional)
        """
        try:
            if kwargs.get('port_id') is None:
                return
            body = {'floatingip': {'port_id': kwargs.get('port_id')}}
            floatingip_info = self.neutron.update_floatingip(
                floatingip_id, body=body)
            LOG.info("Floating ip updated: %s", floatingip_info)
            return floatingip_info
        except Exception as err:
            LOG.exception(err)


class CommonClient(KeystoneDriver, NeutronDriver, NovaDriver):
    """A common client to access other client (keystone, nova, neutron etc)
    resources.
    """
    nova_api_version = '2'

    def __init__(self, project_type="admin", project_info=None, **kwargs):
        '''
        :param project_type str: project type (admin/non-admin)
        :param project_info dict: Detail info of the project,
                like project_name, user_name, and password
                Ignore this if it is admin project.
        :optional params:
            domain_name: Name of the project and user domain,
                        if the set up is domain based.

        NOTE:
            1. Each driver resources can be accessed using the "self"
                ex: self.create_project(..), self.create_network("dummy"),
            2. The keystone, neutron and nova resources can be accessed using
                self.keystone_admin, self.neutron and self.nova respectively.
        '''
        KeystoneDriver.__init__(self)
        NeutronDriver.__init__(self)
        NovaDriver.__init__(self)

        KeystoneDriver.set_cloud_admin_info()
        self.session = None
        # self.nova = None
        # self.neutron = None
        # self.keystone_admin = None

        self.project_type = project_type
        self.project_info = project_info
        # Set the context to a specific user.
        self.set_context(project_type=project_type,
                         project_info=project_info, **kwargs)

    def get_context(self):
        return self.project_type, self.project_info

    def set_context(self, project_type="admin", project_info=None, **kwargs):
        '''It sets the context to the project passed.
        NOTE: For non-admin project pass the project_info.

        :param project_type str: Project type. (admin/non-admin)
        :param project_info dict: Detail info of the project.
                like project_name, user_name, and password
                Ignore this if it is admin project
        :optional params:
            domain_name: Name of the project and user domain,
                        if the set up is domain based.
        '''
        try:
            old_context = self.get_context()
            session = kwargs.get('session')
            if session is None:
                session = KeystoneDriver.get_keystone_auth_session(
                    project_type=project_type,
                    project_info=project_info, **kwargs)
                if session is None:
                    LOG.error("Unable to get the session object.")
                    return
            self.session = session
            # Note: internally the properties of super class is called.
            self.nova = nova_client.Client(self.nova_api_version,
                                           session=session)
            self.neutron = neutron_client(session=session)

            LOG.debug("Context is set to :%s project, id:%s", project_type,
                      self.session.get_project_id())

            return old_context

        except Exception as err:
            LOG.exception(err)

    @contextmanager
    def project_context(self, project_type="admin",
                        project_info=None, **kwargs):
        """A context manager to work on a new context and when the work is done
        unsets the context to that of the old one.
        :param project_type str: Type of project (admin/non-admin)
        :param project_info dict: Detail info of the project.
                like project_name, user_name, and password
                Ignore this if it is admin project
        :optional params:
            domain_name: Name of the project and user domain,
                        if the set up is domain based.
        USAGE:
            with project_context(project_type, project_info) as new_context:
                print "hi"
                # do what ever u want to perform
                self.create_network("dd")
        """
        try:
            old_session = self.session
            # Set the new context.
            old_context = self.set_context(
                project_type=project_type, project_info=project_info, **kwargs)
            yield
        finally:
            # Unset the context.
            self.set_context(*old_context, session=old_session)
